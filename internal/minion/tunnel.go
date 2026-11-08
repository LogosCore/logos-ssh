package minion

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Tunnels (docs: contracts/agentless-channels, Tunnels; the items:
// contracts/minion-messages/tunnels): the SSH minion's, over the session's
// SSH connection, as `ssh -L`, `-D`, `-R` and `-t` are. The tunnel command
// runs until core cancels it, and while it runs core opens streams in it,
// whatever it puts in front of them (SOCKS, HTTP, a forward, a terminal, a
// VPN: core's alone): a TCP connection the server makes (the SSH
// connection's direct-tcpip, its name resolved by the server, so internal
// names work), TLS on top when the open says (the minion's own), a unix
// socket on the server (direct-streamlocal), a process in a terminal (a
// session with a pty), or a listener for one connection (a remote forward:
// SOCKS5 BIND). Both sides carry a stream's bytes in their messages, by
// offset, within a window each way, as BOB's minion does (minions share
// the protocol, never their insides: this is the SSH minion's own copy).
// SSH carries no UDP: an open that says udp is answered unsupported, as
// one of a kind it does not open (a named pipe).
//
// A reverse tunnel goes the other way: the server listens where the
// task's args say (a remote forward, within its GatewayPorts), and the
// minion opens a stream for each connection that comes there, which core
// connects to a destination the minion never learns.
//
// Tunnels go on the session's SSH connection (Tunneler), and with it: a
// call (bind-call) carries none.

const (
	// tunnelWindow is the room the minion gives core on a stream: what it
	// holds of it for a host slower than core. The default room, so its
	// replies leave it out.
	tunnelWindow = protocol.DefaultTunnelRoom
	// tunnelResend: what went and was not acked in that long goes again
	// from the ack, and a window shut that long with bytes waiting is
	// probed.
	tunnelResend = 5 * time.Second
	// tunnelHeld is the most the minion reads of a host ahead of core's
	// ack, whatever room core gives: as much as core's window grows to.
	tunnelHeld = 4 << 20
	// maxWindow is the most a stream's window, the room the minion gives
	// core, grows to; maxTunnelExtra what a tunnel's windows grew past
	// tunnelWindow together (rtt.go).
	maxWindow      = 4 << 20
	maxTunnelExtra = 32 << 20
	// tunnelRead is one read of a host, or write to it, at most.
	tunnelRead = 32 << 10
	// tunnelMinPiece is the least a tunnel_data carries when the stream has
	// more: a message nearly full leaves it to the next.
	tunnelMinPiece = 1 << 10
	// tunnelItemSize is what a tunnel item takes besides its bytes,
	// generously.
	tunnelItemSize = 64
	// tunnelMaxItems is the most tunnel items one message carries.
	tunnelMaxItems = 192
	// reverseSlack is how much longer than the task's timeout (core's
	// connect) a connection to a reverse forward waits for core's answer.
	reverseSlack = 30 * time.Second
)

// tunnels are a session's tunnel tasks and their streams.
type tunnels struct {
	mu     sync.Mutex
	byTask map[string]*tunnel
	// closes answer items for a task the minion runs no tunnel of.
	closes []protocol.TunnelCloseItem
	// turn is where the next message starts sending data: every stream has
	// its turn.
	turn  int
	nudge func()
	// resend is tunnelResend, slack reverseSlack, each shorter in tests.
	resend time.Duration
	// rtt is the session's round trip, as core's acks measure it (rtt.go).
	rtt        rttState
	slack      time.Duration
	acceptWait time.Duration
	// host is what the streams go over: the session's SSH connection; nil,
	// none (a call), and tunnel tasks fail.
	host Tunneler
	logf func(format string, args ...any)
}

// Tunneler is what tunnels go over: the session's SSH connection
// (sshhost.Host), the test's own host in tests.
type Tunneler interface {
	// Dial connects from the server: network "tcp" to host:port (a name
	// the server resolves), or "unix" to a socket's path; ctx bounds the
	// connect only. A refusal is an *OpenError.
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	// Listen listens on the server at a tcp address (a remote forward:
	// within its GatewayPorts, else on its loopback).
	Listen(network, address string) (net.Listener, error)
	// Process runs program (none: the login's shell) with args on the
	// server, in a terminal of rows by cols when they say one: terminal
	// says whether it got one (else it runs on pipes). ctx bounds its
	// start only: it runs until it exits or the Proc closes.
	Process(ctx context.Context, program string, args []string, rows, cols int) (p *Proc, terminal bool, err error)
}

// OpenError is why the server did not open a stream, as a tunnel_reply's
// result says it (protocol.TunnelRefused, ...).
type OpenError struct {
	Result int
	Msg    string
}

func (e *OpenError) Error() string { return e.Msg }

func newTunnels(nudge func(), host Tunneler, logf func(string, ...any)) *tunnels {
	return &tunnels{byTask: map[string]*tunnel{}, nudge: nudge, resend: tunnelResend, slack: reverseSlack,
		acceptWait: protocol.TunnelAcceptWait, host: host, logf: logf}
}

// tunnel is a tunnel task's: its limits, its streams, what it owes core.
type tunnel struct {
	task       []byte
	ctx        context.Context
	maxStreams int
	timeout    time.Duration
	streams    map[uint64]*tstream
	replies    []protocol.TunnelReplyItem
	closes     []protocol.TunnelCloseItem

	// A reverse port forward's: its streams are the minion's, the last
	// numbered last; its listener, the address it listens at, and whether
	// core is still to be told it (a tunnel_listen).
	reverse   bool
	last      uint64
	ln        net.Listener
	bound     string
	sayListen bool
	// extra is what its streams' windows grew past tunnelWindow, together.
	extra int
}

// tstream is one stream: the minion's connection to its destination.
type tstream struct {
	t  *tunnel
	id uint64
	// conn is nil while it connects; reply is the answer core had (said
	// again when core asks again).
	conn  net.Conn
	reply *protocol.TunnelReplyItem
	gone  bool
	done  chan struct{}

	// A stream the minion opens (a reverse forward's): the connection that
	// came, held unread until core answers (then it is conn); its tunnel
	// item while core has not, last sent at openSent.
	accepted net.Conn
	opening  *protocol.TunnelItem
	openSent time.Time

	// A process's (kind process): conn as a process. An accept's (kind
	// accept): its listener, until who came (then conn is theirs).
	proc *Proc
	ln   net.Listener

	// Its tunnel_ctl items (tunnel_ctl.go): toward core, ctlOut from
	// ctlBase (the next core's ack has not covered), sent up to ctlSent,
	// last at ctlSentAt; from core, ctlIn, the next the minion takes.
	ctlOut    []protocol.TunnelCtlItem
	ctlBase   uint64
	ctlSent   uint64
	ctlSentAt time.Time
	ctlIn     uint64

	// From core, toward the host: taken up to next (its eof counted), not
	// yet written: in; ahead, what came past next.
	in         []byte
	next       uint64
	ahead      []protocol.TunnelDataItem
	aheadBytes int
	eofIn      bool
	// shut: the host has core's eof (its write side closed).
	shut     bool
	ackDue   bool
	ackedEnd uint64
	// window is the room the minion gives core (win: tunnelWindow until it
	// grew).
	window   int
	inSignal chan struct{}
	// finishing: core said done; the stream goes once the host has it all.
	finishing bool

	// Toward core: the host's bytes from base (core's next) not yet acked,
	// sent up to sent (the eof one past them), last at sentAt; nothing past
	// limit, the furthest core's acks reached.
	out       []byte
	base      uint64
	sent      uint64
	sentAt    time.Time
	limit     uint64
	eofOut    bool
	upDone    bool
	outSignal chan struct{}
	// rttEnd and rttAt: a round trip being measured, the offset whose ack
	// ends it and when its bytes went (zero: none).
	rttEnd uint64
	rttAt  time.Time
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// tunnelCmd: a command of a tunnel action (the build's tunnel and
// reverse_tunnel), whose task is a tunnel.
func tunnelCmd(c Command) bool { return c == CmdTunnel || c == CmdReverseTunnel }

// tunnelArgs are a tunnel task's limits, by its command's params: how many
// streams at once, and how long a connect may take (a reverse tunnel's is
// core's, which a connection waits on).
func tunnelArgs(c Command, args protocol.Args) (int, time.Duration) {
	numMax, numTimeout := uint64(ArgTunnelMaxStreams), uint64(ArgTunnelTimeout)
	if c == CmdReverseTunnel {
		numMax, numTimeout = ArgReverseMaxStreams, ArgReverseTimeout
	}
	maxStreams, ok := protocol.ArgInt(args, numMax)
	if !ok || maxStreams <= 0 {
		maxStreams = 256
	}
	timeout, ok := protocol.ArgDuration(args, numTimeout)
	if !ok || timeout <= 0 {
		timeout = 10 * time.Second
	}
	return int(min(maxStreams, 1<<16)), timeout
}

// open makes the task's tunnel, as the task is taken: core opens streams in
// it once it has the task's ack.
func (ts *tunnels) open(ctx context.Context, task []byte, cmd Command, args protocol.Args) {
	maxStreams, timeout := tunnelArgs(cmd, args)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.byTask[string(task)] = &tunnel{task: task, ctx: ctx, maxStreams: maxStreams, timeout: timeout, streams: map[uint64]*tstream{},
		reverse: cmd == CmdReverseTunnel}
}

// close ends the task's tunnel and its streams: how many it had.
func (ts *tunnels) close(task []byte) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := ts.byTask[string(task)]
	if t == nil {
		return 0
	}
	delete(ts.byTask, string(task))
	if t.ln != nil {
		closeLater(t.ln)
	}
	n := len(t.streams)
	for _, st := range t.streams {
		ts.drop(st)
	}
	return n
}

// closeAll ends every tunnel: the session is over.
func (ts *tunnels) closeAll() {
	ts.mu.Lock()
	var tasks [][]byte
	for _, t := range ts.byTask {
		tasks = append(tasks, t.task)
	}
	ts.mu.Unlock()
	for _, task := range tasks {
		ts.close(task)
	}
}

// runTunnel runs a tunnel task (its tunnel made as it was taken), whatever
// core puts in front of it: streams come and go in it until core cancels
// it, and close with it. It ends ok. A runner with no SSH connection to
// tunnel over (a call's) fails it.
func (r *Runner) runTunnel(ctx context.Context, t *Task) {
	if r.tun.host == nil {
		r.tun.close(t.id)
		r.End(t, false, nil, "tunnels go over a connection that stays open (bind-persistent), not a call")
		return
	}
	<-ctx.Done()
	n := r.tun.close(t.id)
	r.logf("task %x: the tunnel closes, with %d stream(s)", t.id[:4], n)
	r.End(t, true, nil, "")
}

// reverse runs a reverse port forward (its tunnel made as it was taken):
// the server listens where its args say (bind, 0.0.0.0 unless they say;
// listen), the minion tells core where, and opens a stream for each
// connection that comes, until core cancels it, when it ends ok, its
// listener and streams closed. A listener the server does not open, or
// that fails, ends it failed, saying why.
func (r *Runner) reverse(ctx context.Context, t *Task, args protocol.Args) {
	if r.tun.host == nil {
		r.tun.close(t.id)
		r.End(t, false, nil, "tunnels go over a connection that stays open (bind-persistent), not a call")
		return
	}
	if udp, _ := protocol.ArgBool(args, ArgReverseUDP); udp {
		r.tun.close(t.id)
		r.End(t, false, nil, "SSH forwards TCP alone: no UDP listener")
		return
	}
	bind, ok := protocol.ArgString(args, ArgReverseBind)
	if !ok || bind == "" {
		bind = "0.0.0.0"
	}
	listen, _ := protocol.ArgInt(args, ArgReverseListen)
	err := protocol.TunnelListen(bind, listen)
	address := net.JoinHostPort(bind, strconv.FormatInt(listen, 10))
	if err == nil {
		var ln net.Listener
		if ln, err = r.tun.listen(t.id, address); err == nil {
			stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
			r.logf("task %x: the server listens at %s", t.id[:4], ln.Addr())
			err = r.tun.accept(t.id, ln)
			stop()
			_ = ln.Close()
		}
	}
	n := r.tun.close(t.id)
	if ctx.Err() != nil {
		r.logf("task %x: the reverse forward closes, with %d stream(s)", t.id[:4], n)
		r.End(t, true, nil, "")
		return
	}
	r.logf("task %x: the reverse forward ends: %v", t.id[:4], err)
	r.End(t, false, nil, err.Error())
}

// listen opens a reverse forward's listener at address, and has core told
// where it listens. An error says why it did not open.
func (ts *tunnels) listen(task []byte, address string) (net.Listener, error) {
	ln, err := ts.host.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("the server did not listen at %s (its AllowTcpForwarding, or the port taken): %w", address, err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := ts.byTask[string(task)]
	if t == nil {
		closeLater(ln)
		return nil, errors.New("the tunnel closed as it opened")
	}
	t.ln, t.bound, t.sayListen = ln, clip(ln.Addr().String(), protocol.MaxTunnelBound), true
	ts.nudge()
	return ln, nil
}

// accept takes the listener's connections, each a stream the minion opens,
// until the listener closes (the task's end) or fails: why it stopped (a
// remote forward's listener fails only as the connection goes).
func (ts *tunnels) accept(task []byte, ln net.Listener) error {
	ts.mu.Lock()
	t := ts.byTask[string(task)]
	ts.mu.Unlock()
	if t == nil {
		return errors.New("the tunnel is closed")
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("the server's listener closed (the SSH connection went)")
			}
			return err
		}
		ts.opened(t, c)
	}
}

// opened opens a stream for a connection that came to the listener: its
// tunnel item names who connected. One past max_streams, or that comes as
// the task ends, is reset; one core does not answer within the task's
// timeout and reverseSlack more, too, and core is told.
func (ts *tunnels) opened(t *tunnel, c net.Conn) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	host, port := peer(c)
	if ts.byTask[string(t.task)] != t || len(t.streams) >= t.maxStreams || host == "" {
		closeLater(c)
		return
	}
	t.last++
	st := &tstream{t: t, id: t.last, accepted: c, done: make(chan struct{}), inSignal: make(chan struct{}, 1),
		outSignal: make(chan struct{}, 1), ackedEnd: tunnelWindow,
		opening: &protocol.TunnelItem{T: protocol.ItemTunnel, Task: t.task, Stream: t.last, Host: host, Port: port}}
	t.streams[st.id] = st
	time.AfterFunc(t.timeout+ts.slack, func() { ts.gaveUp(st) })
	ts.nudge()
}

// peer is the address that connected, as a tunnel item names it: "" when
// it does not fit one.
func peer(c net.Conn) (string, uint64) {
	host, port, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil || host == "" || len(host) > protocol.MaxTunnelHost {
		return "", 0
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", 0
	}
	return host, p
}

// gaveUp ends a stream the minion opened that core did not answer in time:
// its connection reset, and core told, should it open it late.
func (ts *tunnels) gaveUp(st *tstream) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if st.gone || st.opening == nil {
		return
	}
	ts.reset(st)
}

// openDue: the stream's tunnel item goes now: never sent, or sent resend
// ago with no answer.
func (st *tstream) openDue(now time.Time, resend time.Duration) bool {
	return st.opening != nil && (st.openSent.IsZero() || now.Sub(st.openSent) >= resend)
}

// takeReply: core connected a stream the minion opened, or could not.
// Open, its bytes go both ways from now, within the room core gives; not,
// its connection is reset. A reply again is nothing; one that says open
// for a stream gone gets a close, so core drops its side too.
func (ts *tunnels) takeReply(r protocol.TunnelReplyItem) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	st, _ := ts.find(r.Task, r.Stream)
	if st == nil {
		if r.Result == protocol.TunnelOpen {
			ts.closeUnknown(r.Task, r.Stream)
		}
		return
	}
	if st.opening == nil {
		return
	}
	if r.Result != protocol.TunnelOpen {
		ts.drop(st)
		return
	}
	st.conn, st.accepted, st.opening = st.accepted, nil, nil
	st.limit = protocol.TunnelRoom(r.Room)
	go ts.readHost(st)
	go ts.writeHost(st)
	ts.nudge()
}

// closeLater closes c off the lock: over SSH a close is a message to the
// server (a channel's close; a listener's cancel-tcpip-forward, which waits
// for its answer; a process's kill, a session of its own), and can wait on
// a busy or slow connection. The engine and every other stream go on.
func closeLater(c io.Closer) {
	go func() { _ = c.Close() }()
}

// take reads one of core's tunnel items; an error says why it does not
// read.
func (ts *tunnels) take(raw cbor.RawMessage) error {
	switch protocol.ItemType(raw) {
	case protocol.ItemTunnel:
		it, err := protocol.ReadTunnel(raw)
		if err != nil && !it.Answerable() {
			return err
		}
		ts.openStream(it, err)
	case protocol.ItemTunnelReply:
		var r protocol.TunnelReplyItem
		if err := readTunnelItem(raw, &r); err != nil {
			return err
		}
		ts.takeReply(r)
	case protocol.ItemTunnelData:
		var d protocol.TunnelDataItem
		if err := readTunnelItem(raw, &d); err != nil {
			return err
		}
		ts.takeData(d)
	case protocol.ItemTunnelAck:
		var a protocol.TunnelAckItem
		if err := readTunnelItem(raw, &a); err != nil {
			return err
		}
		ts.takeAck(a)
	case protocol.ItemTunnelClose:
		var c protocol.TunnelCloseItem
		if err := readTunnelItem(raw, &c); err != nil {
			return err
		}
		ts.takeClose(c)
	case protocol.ItemTunnelDatagram:
		var d protocol.TunnelDatagramItem
		if err := readTunnelItem(raw, &d); err != nil {
			return err
		}
		// SSH carries no UDP: the minion has no stream of datagrams.
		ts.mu.Lock()
		ts.closeUnknown(d.Task, d.Stream)
		ts.mu.Unlock()
	case protocol.ItemTunnelCtl:
		var c protocol.TunnelCtlItem
		if err := readTunnelItem(raw, &c); err != nil {
			return err
		}
		ts.takeCtl(c)
	}
	return nil
}

func readTunnelItem(raw cbor.RawMessage, v interface{ Validate() error }) error {
	if err := protocol.UnmarshalCBOR(raw, v); err != nil {
		return err
	}
	return v.Validate()
}

// find is the task's stream; nil, with the reason core is told, when the
// minion has none.
func (ts *tunnels) find(task []byte, id uint64) (*tstream, int) {
	t := ts.byTask[string(task)]
	if t == nil {
		return nil, protocol.TunnelCloseTaskEnded
	}
	if st := t.streams[id]; st != nil {
		return st, 0
	}
	return nil, protocol.TunnelCloseUnknown
}

// closeUnknown answers an item about a stream the minion does not have.
func (ts *tunnels) closeUnknown(task []byte, id uint64) {
	_, reason := ts.find(task, id)
	if reason == 0 {
		reason = protocol.TunnelCloseUnknown
	}
	c := protocol.TunnelCloseItem{T: protocol.ItemTunnelClose, Task: task, Stream: id, Reason: reason}
	if t := ts.byTask[string(task)]; t != nil {
		t.closes = append(t.closes, c)
	} else {
		ts.closes = append(ts.closes, c)
	}
	ts.nudge()
}

// openStream connects a stream core opens; asked again, it answers again.
// One the minion does not take as it is (why: a key it does not know, or
// an item that does not read) is answered unsupported, and opens nothing.
func (ts *tunnels) openStream(it protocol.TunnelItem, why error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := ts.byTask[string(it.Task)]
	if t == nil {
		ts.closeUnknown(it.Task, it.Stream)
		return
	}
	if t.reverse {
		// A reverse forward's streams are the minion's: core opens none.
		t.closes = append(t.closes, protocol.TunnelCloseItem{T: protocol.ItemTunnelClose, Task: t.task, Stream: it.Stream,
			Reason: protocol.TunnelCloseTaskEnded})
		ts.nudge()
		return
	}
	if st := t.streams[it.Stream]; st != nil {
		if st.reply != nil {
			t.replies = append(t.replies, *st.reply)
			ts.nudge()
		}
		return
	}
	refuse := func(result int, msg string) {
		t.replies = append(t.replies, protocol.TunnelReplyItem{T: protocol.ItemTunnelReply, Task: t.task, Stream: it.Stream, Result: result,
			Msg: clip(msg, protocol.MaxTunnelMsg)})
		ts.nudge()
	}
	if why != nil {
		refuse(protocol.TunnelUnsupported, why.Error())
		return
	}
	if len(t.streams) >= t.maxStreams {
		refuse(protocol.TunnelNotAllowed, strconv.Itoa(t.maxStreams)+" streams open already")
		return
	}
	if ts.host == nil {
		refuse(protocol.TunnelUnsupported, "tunnels go over a connection that stays open (bind-persistent), not a call")
		return
	}
	switch {
	case it.UDP:
		refuse(protocol.TunnelUnsupported, "SSH carries no UDP")
		return
	case it.Kind == protocol.TunnelKindICMP:
		refuse(protocol.TunnelUnsupported, "SSH carries no ICMP")
		return
	case it.Kind == protocol.TunnelKindPipe:
		refuse(protocol.TunnelUnsupported, "SSH forwards no named pipe")
		return
	case it.Source != "":
		refuse(protocol.TunnelUnsupported, "SSH's forward picks no source address: the server's sshd connects from where it chooses")
		return
	}
	st := &tstream{t: t, id: it.Stream, done: make(chan struct{}), inSignal: make(chan struct{}, 1), outSignal: make(chan struct{}, 1),
		limit: protocol.TunnelRoom(it.Room), ackedEnd: tunnelWindow}
	t.streams[it.Stream] = st
	switch it.Kind {
	case protocol.TunnelKindProcess:
		go ts.startProc(st, it)
	case protocol.TunnelKindAccept:
		go ts.startAccept(st, it)
	default:
		go ts.connect(st, it)
	}
}

// openConn makes a stream's connection as its open says, within timeout,
// from the server: a TCP connection to its host and port (direct-tcpip; TLS
// on top when it says: the destination's name its host, no certificate
// checked, since the operator reaches what is there), or a unix socket
// (direct-streamlocal, OpenSSH's).
func (ts *tunnels) openConn(ctx context.Context, it protocol.TunnelItem, timeout time.Duration) (net.Conn, error) {
	// One deadline for all of it: the connect, and a TLS handshake after.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if it.Kind == protocol.TunnelKindUnix {
		return ts.host.Dial(ctx, "unix", it.Path)
	}
	conn, err := ts.host.Dial(ctx, "tcp", net.JoinHostPort(it.Host, strconv.FormatUint(it.Port, 10)))
	if err != nil || !it.TLS {
		return conn, err
	}
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // the operator reaches what is there
	if net.ParseIP(it.Host) == nil {
		cfg.ServerName = it.Host
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls: %w", err)
	}
	return tc, nil
}

// connect makes the stream's connection, within the task's timeout, and
// answers core: open, with the socket's address, or why not.
func (ts *tunnels) connect(st *tstream, it protocol.TunnelItem) {
	conn, err := ts.openConn(st.t.ctx, it, st.t.timeout)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if st.gone {
		if conn != nil {
			closeLater(conn)
		}
		return
	}
	r := protocol.TunnelReplyItem{T: protocol.ItemTunnelReply, Task: st.t.task, Stream: st.id}
	if err != nil {
		r.Result, r.Msg = dialResult(err), clip(err.Error(), protocol.MaxTunnelMsg)
		st.t.replies = append(st.t.replies, r)
		ts.drop(st)
		ts.nudge()
		return
	}
	r.Bound = clip(boundOf(conn.LocalAddr()), protocol.MaxTunnelBound)
	st.conn, st.reply = conn, &r
	st.t.replies = append(st.t.replies, r)
	go ts.readHost(st)
	go ts.writeHost(st)
	ts.nudge()
}

// boundOf is a stream's bound address, as its reply says it: none when
// the connection does not know it. The server opens a forward's
// connection, and SSH does not say where from (x/crypto gives 0.0.0.0:0).
func boundOf(a net.Addr) string {
	switch v := a.(type) {
	case nil:
		return ""
	case *net.TCPAddr:
		if v.Port == 0 && (v.IP == nil || v.IP.IsUnspecified()) {
			return ""
		}
	case *net.UnixAddr:
		return ""
	}
	return a.String()
}

// dialResult is the reply's result for a connect that failed: the
// server's, as the Tunneler read its refusal (an OpenError), else a
// timeout, else failed.
func dialResult(err error) int {
	var oe *OpenError
	var ne net.Error
	switch {
	case errors.As(err, &oe):
		return oe.Result
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return protocol.TunnelTimedOut
	}
	return protocol.TunnelFailed
}

// clip is s within n bytes, valid UTF-8.
func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "?")
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// readHost carries what the host sends toward core, while core's room
// lasts.
func (ts *tunnels) readHost(st *tstream) {
	buf := make([]byte, tunnelRead)
	for {
		ts.mu.Lock()
		for !st.gone && st.outFree() == 0 {
			ts.mu.Unlock()
			select {
			case <-st.outSignal:
			case <-st.done:
			}
			ts.mu.Lock()
		}
		if st.gone {
			ts.mu.Unlock()
			return
		}
		n := min(len(buf), st.outFree())
		conn := st.conn
		ts.mu.Unlock()
		k, err := conn.Read(buf[:n])
		ts.mu.Lock()
		if st.gone {
			ts.mu.Unlock()
			return
		}
		st.out = append(st.out, buf[:k]...)
		switch {
		case errors.Is(err, io.EOF):
			st.eofOut = true
		case err != nil:
			ts.reset(st)
		}
		ts.mu.Unlock()
		ts.nudge()
		if err != nil {
			return
		}
	}
}

// outFree is how much more of the host the minion may read now.
func (st *tstream) outFree() int {
	if st.eofOut {
		return 0
	}
	return max(int(min(st.limit-min(st.limit, st.base), tunnelHeld))-len(st.out), 0)
}

// writeHost writes core's bytes to the host, giving the room back as it
// goes, and ends the host's end with core's eof.
func (ts *tunnels) writeHost(st *tstream) {
	for {
		ts.mu.Lock()
		for !st.gone && len(st.in) == 0 && (!st.eofIn || st.shut) && !st.finishing {
			ts.mu.Unlock()
			select {
			case <-st.inSignal:
			case <-st.done:
			}
			ts.mu.Lock()
		}
		if st.gone {
			ts.mu.Unlock()
			return
		}
		if len(st.in) == 0 {
			if st.eofIn && !st.shut {
				// Its write side ends off the lock (a channel's EOF, a TLS
				// close_notify: messages over the SSH connection), before
				// the stream may go.
				st.shut = true
				conn := st.conn
				ts.mu.Unlock()
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
				ts.mu.Lock()
				if st.gone {
					ts.mu.Unlock()
					return
				}
			}
			if st.finishing {
				ts.drop(st)
			} else {
				ts.doneIfOver(st)
			}
			ts.mu.Unlock()
			return
		}
		piece := st.in[:min(len(st.in), 2*tunnelRead)]
		conn := st.conn
		ts.mu.Unlock()
		_, err := conn.Write(piece)
		ts.mu.Lock()
		if st.gone {
			ts.mu.Unlock()
			return
		}
		if err != nil {
			ts.reset(st)
			ts.mu.Unlock()
			return
		}
		st.in = st.in[len(piece):]
		if len(st.in) == 0 {
			st.in = nil
		}
		wake := st.roomGrew()
		if len(st.in) == 0 && st.grow() {
			wake = true
		}
		ts.mu.Unlock()
		if wake {
			ts.nudge()
		}
	}
}

// roomGrew marks an ack due once the host took enough to say so: a quarter
// of the window.
func (st *tstream) roomGrew() bool {
	if st.ackDue || st.eofIn {
		return false
	}
	if w := st.win(); st.next+uint64(w-len(st.in)) >= st.ackedEnd+uint64(w/4) {
		st.ackDue = true
		return true
	}
	return false
}

// reset ends the stream as an abort: core is told, the connection reset.
func (ts *tunnels) reset(st *tstream) {
	if st.gone {
		return
	}
	st.t.closes = append(st.t.closes, protocol.TunnelCloseItem{T: protocol.ItemTunnelClose, Task: st.t.task, Stream: st.id, Reason: protocol.TunnelCloseReset})
	ts.drop(st)
	ts.nudge()
}

// doneIfOver ends the stream once both directions ended and each side has
// the other's eof, telling core.
func (ts *tunnels) doneIfOver(st *tstream) {
	if st.gone || !st.upDone || !st.shut || len(st.ctlOut) > 0 {
		// Done once its ctls are acked too: a process's exit.
		return
	}
	st.t.closes = append(st.t.closes, protocol.TunnelCloseItem{T: protocol.ItemTunnelClose, Task: st.t.task, Stream: st.id, Reason: protocol.TunnelCloseDone})
	ts.drop(st)
	ts.nudge()
}

// drop forgets the stream and closes its connection, off the lock. An
// abort and an end are the same here: SSH closes a channel either way.
func (ts *tunnels) drop(st *tstream) {
	if st.gone {
		return
	}
	st.gone = true
	close(st.done)
	delete(st.t.streams, st.id)
	st.shrink()
	if st.ln != nil {
		// An accept no one came to.
		closeLater(st.ln)
		st.ln = nil
	}
	if st.accepted != nil {
		// Never answered, or not opened: closed, as a refused connection
		// is (SSH has no reset: the server closes its end).
		closeLater(st.accepted)
		st.accepted, st.opening = nil, nil
	}
	if st.conn != nil {
		closeLater(st.conn)
	}
}

// takeData takes core's bytes at the minion's next, within the room it
// gave. One ahead of next is kept within the room until the bytes before
// it come; what the minion has already is acked again and dropped.
func (ts *tunnels) takeData(d protocol.TunnelDataItem) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	st, _ := ts.find(d.Task, d.Stream)
	if st == nil {
		ts.closeUnknown(d.Task, d.Stream)
		return
	}
	st.ackDue = true
	defer ts.nudge()
	switch {
	case st.eofIn || d.End() <= st.next:
		return
	case d.Off > st.next:
		// Its bytes within the room (its eof needs none).
		if w := st.win(); d.Off+uint64(len(d.Data)) <= st.next+uint64(w-len(st.in)) && st.aheadBytes+len(d.Data) <= w {
			d.Data = bytes.Clone(d.Data)
			st.ahead = append(st.ahead, d)
			st.aheadBytes += len(d.Data)
		}
		return
	}
	st.take(d)
	for moved := true; moved && !st.eofIn; {
		moved = false
		kept := st.ahead[:0]
		for _, a := range st.ahead {
			switch {
			case a.End() <= st.next:
				st.aheadBytes -= len(a.Data)
			case a.Off <= st.next:
				st.aheadBytes -= len(a.Data)
				st.take(a)
				moved = true
			default:
				kept = append(kept, a)
			}
		}
		st.ahead = kept
	}
	signal(st.inSignal)
}

// take takes d's bytes from next on (d starts at or before it and ends
// past it), within the room the minion gave.
func (st *tstream) take(d protocol.TunnelDataItem) {
	data := d.Data[min(st.next-d.Off, uint64(len(d.Data))):]
	eof := d.EOF
	if free := st.win() - len(st.in); len(data) > free {
		data, eof = data[:free], false
	}
	st.in = append(st.in, data...)
	st.next += uint64(len(data))
	if eof {
		st.eofIn = true
		st.next++
		st.ahead, st.aheadBytes = nil, 0
	}
}

// takeAck drops what core has of the host's bytes and takes the room it
// gives (unchanged when it says none); one below the last is nothing, one
// past what the minion sent is not an ack of its.
func (ts *tunnels) takeAck(a protocol.TunnelAckItem) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	st, _ := ts.find(a.Task, a.Stream)
	if st == nil {
		ts.closeUnknown(a.Task, a.Stream)
		return
	}
	if st.ctlAcked(a.Ctl) && st.upDone {
		// Its last ctl acked: it may be over.
		ts.doneIfOver(st)
		return
	}
	end := st.base + uint64(len(st.out))
	if st.conn == nil || st.upDone || a.Next < st.base || a.Next > end+1 || (a.Next == end+1 && !st.eofOut) {
		return
	}
	room := st.limit - min(st.limit, st.base)
	if a.Room != nil {
		room = *a.Room
	}
	ts.measured(st, a.Next)
	if a.Next > st.base {
		st.sentAt = time.Now()
	}
	if a.Next == end+1 {
		st.out, st.base, st.upDone = nil, end, true
	} else {
		st.out = st.out[a.Next-st.base:]
		st.base = a.Next
	}
	st.sent = max(st.sent, a.Next)
	st.limit = max(st.limit, a.Next+room)
	signal(st.outSignal)
	if st.upDone {
		ts.doneIfOver(st)
	}
}

// takeClose: core ended the stream. Done, it goes once the host has every
// byte; any other reason (one the minion does not know reads as a reset)
// closes the connection at once.
func (ts *tunnels) takeClose(c protocol.TunnelCloseItem) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	st, _ := ts.find(c.Task, c.Stream)
	if st == nil {
		return
	}
	if c.Reason == protocol.TunnelCloseDone && st.conn != nil && len(st.in) > 0 {
		st.finishing = true
		signal(st.inSignal)
		return
	}
	ts.drop(st)
}

// items are what the tunnels send core in a message of room bytes and most
// items: closes, replies, acks, then data, a stream's item in turn while
// room lasts; and the bytes they take.
func (ts *tunnels) items(room, most int) ([]any, int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var out []any
	used := 0
	put := func(it any, size int) bool {
		if len(out) >= most || used+size > room {
			return false
		}
		out = append(out, it)
		used += size
		return true
	}
	for len(ts.closes) > 0 && put(ts.closes[0], tunnelItemSize) {
		ts.closes = ts.closes[1:]
	}
	var open []*tstream
	now := time.Now()
	for _, t := range ts.sorted() {
		for len(t.closes) > 0 && put(t.closes[0], tunnelItemSize) {
			t.closes = t.closes[1:]
		}
		if t.sayListen && put(protocol.TunnelListenItem{T: protocol.ItemTunnelListen, Task: t.task, Bound: t.bound}, tunnelItemSize) {
			t.sayListen = false
		}
		for _, st := range t.sortedStreams() {
			if st.openDue(now, ts.resendAfter()) && put(*st.opening, len(st.opening.Host)+tunnelItemSize) {
				st.openSent = now
			}
		}
		for len(t.replies) > 0 && put(t.replies[0], tunnelItemSize) {
			t.replies = t.replies[1:]
		}
		// Ctls after the replies (a stream's open first), before any data:
		// a process's exit before its eof.
		for _, st := range t.sortedStreams() {
			st.putCtls(put, now, ts.resendAfter())
		}
		for _, st := range t.sortedStreams() {
			if st.conn != nil {
				open = append(open, st)
			}
		}
	}
	for _, st := range open {
		if st.ackDue && put(st.ackItem(), tunnelItemSize) {
			st.ackDue = false
			st.ackedEnd = st.next + uint64(st.win()-len(st.in))
		}
	}
	if n := len(open); n > 0 {
		start := ts.turn % n
		ts.turn++
	rounds:
		for moved := true; moved; {
			moved = false
			for i := range n {
				st := open[(start+i)%n]
				d := st.dataItem(now, room-used-tunnelItemSize, ts.resendAfter())
				if d == nil {
					continue
				}
				if !put(*d, len(d.Data)+tunnelItemSize) {
					break rounds
				}
				st.measure(d.End(), d.Off < st.sent, now)
				st.sent, st.sentAt = d.End(), now
				moved = true
			}
		}
	}
	return out, used
}

// sorted is the tunnels by task; sortedStreams a tunnel's streams by
// number.
func (ts *tunnels) sorted() []*tunnel {
	out := make([]*tunnel, 0, len(ts.byTask))
	for _, t := range ts.byTask {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b *tunnel) int { return bytes.Compare(a.task, b.task) })
	return out
}

func (t *tunnel) sortedStreams() []*tstream {
	out := make([]*tstream, 0, len(t.streams))
	for _, st := range t.streams {
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b *tstream) int {
		switch {
		case a.id < b.id:
			return -1
		case a.id > b.id:
			return 1
		}
		return 0
	})
	return out
}

func (st *tstream) ackItem() protocol.TunnelAckItem {
	room := uint64(max(st.win()-len(st.in), 0))
	return protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: st.t.task, Stream: st.id, Next: st.next, Room: &room, Ctl: st.ctlIn}
}

// dataItem is the stream's next tunnel_data in room bytes: what was not
// sent (from the ack again once a send went unacked resend long), up to
// core's room, then the eof once every byte went (the eof needs no room);
// a probe, one byte past a window shut that long with bytes waiting; nil
// for nothing, or too little room.
func (st *tstream) dataItem(now time.Time, room int, resend time.Duration) *protocol.TunnelDataItem {
	if st.upDone || room <= 0 {
		return nil
	}
	end := st.base + uint64(len(st.out))
	sent := st.sent
	quiet := now.Sub(st.sentAt) >= resend
	if sent > st.base && quiet {
		sent = st.base
	}
	n := 0
	if limit := min(end, st.limit); sent < limit {
		n = int(limit - sent)
	}
	eof := st.eofOut && sent <= end && sent+uint64(n) == end
	if n == 0 && !eof {
		if sent >= end || !quiet {
			return nil
		}
		n = 1
	}
	if most := min(room, protocol.MaxTunnelData); n > most {
		if most < tunnelMinPiece {
			return nil
		}
		n, eof = most, false
	}
	from := int(sent - st.base)
	d := protocol.TunnelDataItem{T: protocol.ItemTunnelData, Task: st.t.task, Stream: st.id, Off: sent, EOF: eof}
	if n > 0 {
		d.Data = st.out[from : from+n]
	}
	return &d
}

// pending: the tunnels have something to send now.
func (ts *tunnels) pending() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.closes) > 0 {
		return true
	}
	now := time.Now()
	for _, t := range ts.byTask {
		if len(t.closes) > 0 || len(t.replies) > 0 || t.sayListen {
			return true
		}
		for _, st := range t.streams {
			if st.openDue(now, ts.resendAfter()) || st.ctlDue(now, ts.resendAfter()) {
				return true
			}
			if st.conn != nil && (st.ackDue || st.dataItem(now, protocol.MaxTunnelData, ts.resendAfter()) != nil) {
				return true
			}
		}
	}
	return false
}

// due is how soon a stream sends again unasked (from its ack, or a probe of
// a shut window): the session checks in then, even over a persistent
// connection. False for none.
func (ts *tunnels) due() (time.Duration, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var soonest time.Time
	for _, t := range ts.byTask {
		for _, st := range t.streams {
			if len(st.ctlOut) > 0 && st.ctlSent > st.ctlBase {
				// Its ctls again, while core has not acked them.
				if at := st.ctlSentAt.Add(ts.resendAfter()); soonest.IsZero() || at.Before(soonest) {
					soonest = at
				}
			}
			if st.opening != nil && !st.openSent.IsZero() {
				// Its tunnel item again, while core has not answered.
				if at := st.openSent.Add(ts.resendAfter()); soonest.IsZero() || at.Before(soonest) {
					soonest = at
				}
				continue
			}
			if st.conn == nil || st.upDone {
				continue
			}
			end := st.base + uint64(len(st.out))
			waiting := st.sent > st.base || (st.sent < end && st.sent >= st.limit)
			if at := st.sentAt.Add(ts.resendAfter()); waiting && (soonest.IsZero() || at.Before(soonest)) {
				soonest = at
			}
		}
	}
	if soonest.IsZero() {
		return 0, false
	}
	return max(time.Until(soonest), time.Millisecond), true
}
