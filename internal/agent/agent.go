// Package agent is the SSH channel acting as the minion of the servers it
// reaches (docs: contracts/agentless-channels/). Core's calls (bind-call)
// are answered by the minion's Caller, the server's login kept a while for
// the next call; core's opens (bind-persistent) get a connection socket to
// core on one side, the server's SSH connection on the other, and the
// minion's Runner between them. Both kinds are agentless, so core gives
// the channel the keys of each call's and open's id (protocol.LinkKeys): it
// opens core's messages and seals the minion's with them.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/logoscore/logos-golang-channel-core/v3/pkg/connclient"
	"github.com/logoscore/logos-golang-channel-core/v3/pkg/linkclient"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/ops"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshhost"
)

// Stats are the channel's counters.
type Stats struct {
	Calls, CallsFailed, Opens, OpensFailed, Open, LoginsKept int64
	Draining, LinkUp                                         bool
}

// Agent answers calls and opens connections.
type Agent struct {
	coreURL, instance string
	max               int
	pool              *sshconn.Pool

	draining    atomic.Bool
	linkUp      atomic.Bool
	callTimeout atomic.Int64 // a time.Duration
	calls       atomic.Int64
	callsFailed atomic.Int64
	opens       atomic.Int64
	opensFailed atomic.Int64

	mu       sync.Mutex
	sessions map[*session]struct{}
}

// DefaultCallTimeout bounds a call until SetCallTimeout says otherwise:
// what core waits for one.
const DefaultCallTimeout = 2 * time.Minute

// New is an agent for instance, opening connection sockets under core's
// base URL, at most max persistent connections at once.
func New(coreURL, instance string, max int) *Agent {
	a := &Agent{coreURL: coreURL, instance: instance, max: max, pool: sshconn.NewPool(), sessions: map[*session]struct{}{}}
	a.SetCallTimeout(DefaultCallTimeout)
	return a
}

// SetCallTimeout bounds the calls from now on: each ends at the shorter of
// d and core's deadline, the call's tasks fitted within it.
func (a *Agent) SetCallTimeout(d time.Duration) { a.callTimeout.Store(int64(d)) }

// CallTimeout is the bound in force.
func (a *Agent) CallTimeout() time.Duration { return time.Duration(a.callTimeout.Load()) }

// SetDraining refuses (true) or takes again new calls and opens; open
// connections stay.
func (a *Agent) SetDraining(v bool) { a.draining.Store(v) }

// Draining reports whether calls and opens are refused.
func (a *Agent) Draining() bool { return a.draining.Load() }

// SetLinkUp records the control link's state (linkclient's OnState).
func (a *Agent) SetLinkUp(up bool) { a.linkUp.Store(up) }

// Stats are the counters now.
func (a *Agent) Stats() Stats {
	a.mu.Lock()
	open := int64(len(a.sessions))
	a.mu.Unlock()
	return Stats{Calls: a.calls.Load(), CallsFailed: a.callsFailed.Load(), Opens: a.opens.Load(), OpensFailed: a.opensFailed.Load(),
		Open: open, LoginsKept: int64(a.pool.Idle()), Draining: a.draining.Load(), LinkUp: a.linkUp.Load()}
}

// CloseAll closes every persistent connection, and every login a call
// kept: their sockets to core close with them. It returns how many
// connections.
func (a *Agent) CloseAll(why string) int {
	a.mu.Lock()
	all := make([]*session, 0, len(a.sessions))
	for s := range a.sessions {
		all = append(all, s)
	}
	a.mu.Unlock()
	for _, s := range all {
		s.close(why)
	}
	a.pool.CloseIdle()
	return len(all)
}

// Close closes every connection and stops the pool: the channel is
// stopping.
func (a *Agent) Close(why string) {
	a.CloseAll(why)
	a.pool.Close()
}

// logf is the minion's log, at debug: what it does with each task.
func logf(addr string) func(format string, args ...any) {
	return func(format string, args ...any) {
		slog.Debug(fmt.Sprintf(format, args...), "server", addr)
	}
}

// Call answers one of core's calls: the control link's handler.
func (a *Agent) Call(ctx context.Context, call linkclient.Call) linkclient.Answer {
	a.calls.Add(1)
	start := time.Now()
	ans := a.call(ctx, call)
	outcome, level := "answered", slog.LevelDebug
	switch {
	case ans.Failure != nil:
		a.callsFailed.Add(1)
		outcome, level = protocol.LinkFailName(ans.Failure.Kind), slog.LevelInfo
	case ans.ID == nil:
		a.callsFailed.Add(1)
		outcome, level = "not_the_minion", slog.LevelInfo
	}
	args := []any{"request", call.Request, "host", call.Values["host"], "outcome", outcome, "duration_ms", time.Since(start).Milliseconds()}
	if ans.Failure != nil {
		args = append(args, "err", ans.Failure.Msg)
	}
	slog.Log(ctx, level, "call", args...)
	return ans
}

func (a *Agent) call(ctx context.Context, call linkclient.Call) linkclient.Answer {
	// The shorter of core's deadline (channel-core's ctx ends at it) and
	// the channel's own: the login and the tasks keep within it.
	ctx, cancel := context.WithTimeout(ctx, a.CallTimeout())
	defer cancel()
	if a.Draining() {
		return linkclient.Fail(protocol.LinkFailOther, "the channel is draining")
	}
	t, err := connection.ReadTarget(call.Values, call.Credentials)
	if err != nil {
		return linkclient.Fail(protocol.LinkFailOther, "%s", err)
	}
	if call.Keys == nil {
		return linkclient.Fail(protocol.LinkFailOther, "the call carries no keys: core gives a channel that acts as the minion the keys of its id")
	}
	plain, err := protocol.OpenFrame(call.Keys.Material, call.ID, protocol.FrameCoreToMinion, call.Data)
	if err != nil {
		return linkclient.Fail(protocol.LinkFailOther, "core's message does not open with the call's keys")
	}
	msg, err := minion.ReadCore(plain)
	if err != nil {
		return linkclient.Fail(protocol.LinkFailOther, "%s", err)
	}
	c, logins, err := a.pool.Get(ctx, t)
	if err != nil {
		ans := sshconn.CallFailure(ctx, err, "")
		ans.Logins = logins
		return ans
	}
	// The call lives as long as its context: core's deadline, or the link.
	// Ending it closes the connection, so whatever waits on the server gives
	// up: a server gone quiet never holds the call, nor the link with it
	// (the link opens again only once its calls returned).
	watch := context.AfterFunc(ctx, func() { _ = c.Close() })
	host := sshhost.New(c)
	adopt(host, call.Acting, t.Addr)
	caller := &minion.Caller{Host: host, Ops: ops.Commands, MaxTasks: ops.MaxTasks, Hello: host.Hello, Logf: logf(t.Addr),
		Acting: minion.ActingTask(call.Acting)}
	items := caller.Answer(ctx, msg)
	reply, err := minion.Reply(msg.ID, items)
	intact := watch() // false: the call's context ended, and closed the connection
	if !intact {
		slog.Info("call outlived its context: its connection closed", "request", call.Request, "host", call.Values["host"],
			"why", context.Cause(ctx))
	}
	if err != nil {
		a.pool.Put(t, c, false)
		ans := linkclient.Fail(protocol.LinkFailOther, "the answer does not encode: %s", err)
		ans.Logins = logins
		return ans
	}
	a.pool.Put(t, c, intact)
	sealed, err := protocol.SealFrame(call.Keys.Material, call.ID, protocol.FrameMinionToCore, reply)
	if err != nil {
		ans := linkclient.Fail(protocol.LinkFailOther, "the answer does not seal: %s", err)
		ans.Logins = logins
		return ans
	}
	id := call.ID
	return linkclient.Answer{ID: &id, Data: sealed, Peer: c.Peer, Logins: logins}
}

// maxFrame bounds a connection socket's frame: an id and the largest
// message, with room to spare.
const maxFrame = protocol.MaxMinionMessageSize + 64<<10

// Open opens a persistent connection core asked for: the control link's
// Opener. It logs in to the server, opens the connection's socket to core
// naming the open, and runs the minion between them on its own.
func (a *Agent) Open(ctx context.Context, o linkclient.Open) linkclient.Answer {
	ans := a.open(ctx, o)
	if ans.Failure != nil {
		a.opensFailed.Add(1)
		slog.Info("open failed", "request", o.Request, "host", o.Values["host"], "kind", protocol.LinkFailName(ans.Failure.Kind), "err", ans.Failure.Msg)
	} else {
		a.opens.Add(1)
	}
	return ans
}

func (a *Agent) open(ctx context.Context, o linkclient.Open) linkclient.Answer {
	if a.Draining() {
		return linkclient.Fail(protocol.LinkFailOther, "the channel is draining")
	}
	a.mu.Lock()
	full := len(a.sessions) >= a.max
	a.mu.Unlock()
	if full {
		return linkclient.Fail(protocol.LinkFailOther, "the channel has %d connections open, its most", a.max)
	}
	t, err := connection.ReadTarget(o.Values, o.Credentials)
	if err != nil {
		return linkclient.Fail(protocol.LinkFailOther, "%s", err)
	}
	if o.Under == [16]byte{} || o.Keys == nil {
		// The minion keeps no ids and no keys: it speaks under the id core
		// gives, sealed with that id's keys.
		return linkclient.Fail(protocol.LinkFailOther, "core's open says no id to speak under, or not its keys: a core older than this channel")
	}
	c, logins, err := sshconn.Dial(ctx, t)
	if err != nil {
		ans := sshconn.Failure(ctx, err)
		ans.Logins = logins
		return ans
	}
	core, err := connclient.Dial(ctx, connclient.Options{BaseURL: a.coreURL, Instance: a.instance,
		Kind: protocol.KindBindPersistent, OpenRequest: o.Request, Peer: c.Peer, MaxFrame: maxFrame})
	if err != nil {
		_ = c.Close()
		// The login worked all the same: core is told which.
		ans := linkclient.Fail(protocol.LinkFailOther, "core did not take the connection's socket: %s", err)
		ans.Logins = logins
		return ans
	}
	s := newSession(t, c, core, o.Request, append([]byte(nil), o.Under[:]...), o.Keys.Material)
	s.acting = minion.ActingTask(o.Acting)
	adopt(sshhost.New(c), o.Acting, t.Addr)
	a.mu.Lock()
	a.sessions[s] = struct{}{}
	a.mu.Unlock()
	go func() {
		s.run()
		a.mu.Lock()
		delete(a.sessions, s)
		a.mu.Unlock()
	}()
	slog.Info("connection open", "request", o.Request, "server", t.Addr, "user", c.User, "host_key", c.Fingerprint())
	return linkclient.Answer{Logins: logins}
}

// adopt takes up the become core says is in effect for the session (the
// task that made its identity: a call's or an open's acting), as the minion
// would have kept it: the connection elevates again when a shell command
// comes. None: shell commands run as the login.
func adopt(h *sshhost.Host, a *protocol.LinkActing, server string) {
	if a == nil || ops.Commands[a.Cmd] != minion.CmdBecome {
		h.Adopt(nil)
		return
	}
	b, err := minion.BecomeArgs(a.Task, a.Args)
	if err != nil {
		// Core checked the task's args when it was queued: one this
		// channel does not read leaves the session as its login.
		slog.Warn("the session's become does not read: shell commands run as the login", "server", server, "err", err)
		h.Adopt(nil)
		return
	}
	h.Adopt(&b)
}
