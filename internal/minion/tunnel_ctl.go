package minion

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A stream's tunnel_ctl items (docs: contracts/minion-messages/tunnels.md,
// Controls): what it says besides its bytes, in order and none lost. The
// minion numbers its own from 0 and sends each again from core's ack (its
// Ctl) until it covers it: a process's exit, who came to an accept. It
// takes core's at its next, acking with its own acks: a terminal's size, a
// signal. And the two kinds of open that use them: a process (proc.go) and
// an accept, SOCKS5's BIND.

// queueCtl puts a ctl of the minion's on the stream, numbered. Under ts.mu.
func (ts *tunnels) queueCtl(st *tstream, c protocol.TunnelCtlItem) {
	if st.gone {
		return
	}
	c.T, c.Task, c.Stream, c.Seq = protocol.ItemTunnelCtl, st.t.task, st.id, st.ctlBase+uint64(len(st.ctlOut))
	st.ctlOut = append(st.ctlOut, c)
	ts.nudge()
}

// ctlDue: one of the stream's ctls is to go: one not sent, or sent and not
// acked for resend.
func (st *tstream) ctlDue(now time.Time, resend time.Duration) bool {
	if len(st.ctlOut) == 0 {
		return false
	}
	return st.ctlSent < st.ctlBase+uint64(len(st.ctlOut)) || now.Sub(st.ctlSentAt) >= resend
}

// putCtls puts what of the stream's ctls is due, from the ack again once
// they went unacked resend long.
func (st *tstream) putCtls(put func(any, int) bool, now time.Time, resend time.Duration) {
	if !st.ctlDue(now, resend) {
		return
	}
	from := st.ctlSent
	if from > st.ctlBase && now.Sub(st.ctlSentAt) >= resend {
		from = st.ctlBase
	}
	went := false
	for seq := from; seq < st.ctlBase+uint64(len(st.ctlOut)); seq++ {
		c := st.ctlOut[seq-st.ctlBase]
		if !put(c, tunnelItemSize+len(c.Host)) {
			break
		}
		st.ctlSent, went = max(st.ctlSent, seq+1), true
	}
	if went {
		st.ctlSentAt = now
	}
}

// ctlAcked drops the ctls core's ack covers (its Ctl: the next it takes);
// true when that left none.
func (st *tstream) ctlAcked(next uint64) bool {
	if next <= st.ctlBase || next > st.ctlBase+uint64(len(st.ctlOut)) {
		return false
	}
	st.ctlOut = st.ctlOut[next-st.ctlBase:]
	st.ctlBase = next
	st.ctlSent = max(st.ctlSent, next)
	if len(st.ctlOut) == 0 {
		st.ctlOut = nil
		return true
	}
	return false
}

// takeCtl takes core's ctl at the minion's next and acks it (one before is
// acked again; one past waits for core to send again): a process's new
// terminal size, a signal for it.
func (ts *tunnels) takeCtl(c protocol.TunnelCtlItem) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	st, _ := ts.find(c.Task, c.Stream)
	if st == nil {
		ts.closeUnknown(c.Task, c.Stream)
		return
	}
	if c.Seq > st.ctlIn {
		return
	}
	st.ackDue = true
	defer ts.nudge()
	if c.Seq < st.ctlIn {
		return
	}
	st.ctlIn++
	p := st.proc
	if p == nil {
		return
	}
	if c.Rows > 0 && c.Cols > 0 {
		_ = p.Resize(int(c.Rows), int(c.Cols))
	}
	if c.Signal > 0 {
		// Off the lock: the server signals through a session of its own.
		go func() { _ = p.Signal(c.Signal) }()
	}
}

// startProc runs a stream's process on the server (its session open within
// the task's timeout) and answers core: open (in a terminal or on pipes, as
// the reply says), or why not; a program the server does not have shows as
// its exit, 127, as the shell says it. Its exit goes to core as a
// ctl once its output ended, before the stream's eof.
func (ts *tunnels) startProc(st *tstream, it protocol.TunnelItem) {
	ctx, cancel := context.WithTimeout(st.t.ctx, st.t.timeout)
	p, terminal, err := ts.host.Process(ctx, it.Path, it.Args, int(it.Rows), int(it.Cols))
	cancel()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if st.gone {
		if p != nil {
			closeLater(p)
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
	p.OnExit(func(code int64) {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		ts.queueCtl(st, protocol.TunnelCtlItem{Exit: &code})
	})
	r.Terminal = terminal
	st.conn, st.proc, st.reply = p, p, &r
	st.t.replies = append(st.t.replies, r)
	go ts.readHost(st)
	go ts.writeHost(st)
	ts.nudge()
}

// startAccept has the server listen where the open says (a remote
// forward: every address of the server as its GatewayPorts lets, any free
// port, as core asks) for one connection, and answers core with where
// it listens; who came goes in a ctl, then the stream is that connection's.
// No one within acceptWait, and the stream is reset.
func (ts *tunnels) startAccept(st *tstream, it protocol.TunnelItem) {
	ln, err := ts.host.Listen("tcp", net.JoinHostPort(it.Host, strconv.FormatUint(it.Port, 10)))
	ts.mu.Lock()
	if st.gone {
		ts.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		return
	}
	r := protocol.TunnelReplyItem{T: protocol.ItemTunnelReply, Task: st.t.task, Stream: st.id}
	if err != nil {
		// The server says no more than no (its AllowTcpForwarding, or the
		// port taken).
		r.Result, r.Msg = dialResult(err), clip(err.Error(), protocol.MaxTunnelMsg)
		st.t.replies = append(st.t.replies, r)
		ts.drop(st)
		ts.nudge()
		ts.mu.Unlock()
		return
	}
	r.Bound = clip(ln.Addr().String(), protocol.MaxTunnelBound)
	st.ln, st.reply = ln, &r
	st.t.replies = append(st.t.replies, r)
	ts.nudge()
	wait := ts.acceptWait
	ts.mu.Unlock()
	// A remote forward's listener has no deadline: closed after the wait.
	stop := time.AfterFunc(wait, func() { _ = ln.Close() })
	c, err := ln.Accept()
	stop.Stop()
	_ = ln.Close()
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if st.gone {
		if c != nil {
			closeLater(c)
		}
		return
	}
	st.ln = nil
	if err != nil {
		// No one came in time.
		ts.reset(st)
		return
	}
	host, port := peer(c)
	st.conn = c
	ts.queueCtl(st, protocol.TunnelCtlItem{Host: host, Port: port})
	go ts.readHost(st)
	go ts.writeHost(st)
}
