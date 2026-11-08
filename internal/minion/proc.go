package minion

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A process a stream runs on the server (an open of kind process, docs:
// contracts/minion-messages/tunnels.md, Terminal): the program core names
// (none: the login's shell) with its args, in a terminal of the open's size
// (a session with a pty) or, with no size or no terminal to give, on
// pipes. Its bytes are the stream's; its exit goes to core as a tunnel_ctl
// before the stream's eof; the stream's end hangs it up.

// Proc is a running process as a stream's connection: the server's ways
// to read it, write to it, resize it, signal it and end it. A Tunneler
// fills it in (NewProc), then the stream reads it.
type Proc struct {
	out io.Reader
	in  io.WriteCloser
	// exited closes once the process ended, code its exit (128 and the
	// signal's number when one ended it).
	exited chan struct{}
	code   int64
	closed atomic.Bool
	// onExit has the exit said, once the output ended.
	onExit func(code int64)
	// The server's ways: a new size, a signal (protocol.TunnelSignal...),
	// an end to the whole of it, and the end of its input (nil: none, as a
	// terminal's input does not end).
	resizeFn   func(rows, cols int) error
	signalFn   func(sig int) error
	killFn     func()
	closeWrite func() error
	once       sync.Once
}

// ProcWays are how the server resizes, signals and ends a process, and
// ends its input (CloseInput nil: none, a terminal's).
type ProcWays struct {
	Resize     func(rows, cols int) error
	Signal     func(sig int) error
	Kill       func()
	CloseInput func() error
}

// NewProc is a process's connection over its output and input; wait is
// its exit code, once it ended (watched in the background).
func NewProc(out io.Reader, in io.WriteCloser, ways ProcWays, wait func() int64) *Proc {
	p := &Proc{out: out, in: in, exited: make(chan struct{}), resizeFn: ways.Resize, signalFn: ways.Signal, killFn: ways.Kill,
		closeWrite: ways.CloseInput}
	go func() {
		p.code = wait()
		close(p.exited)
	}()
	return p
}

// Read is the process's output: once it ended, its exit is said (onExit),
// then an eof.
func (p *Proc) Read(b []byte) (int, error) {
	n, err := p.out.Read(b)
	if n > 0 || err == nil {
		return n, nil
	}
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	<-p.exited
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	if p.onExit != nil {
		p.onExit(p.code)
	}
	return 0, io.EOF
}

// OnExit has fn told the exit, once the output ended (before Read says
// its eof); set before the first Read.
func (p *Proc) OnExit(fn func(code int64)) { p.onExit = fn }

func (p *Proc) Write(b []byte) (int, error) { return p.in.Write(b) }

// CloseWrite ends the process's input: its pipe's; a terminal's does not
// end (its process ends it, or the stream's close).
func (p *Proc) CloseWrite() error {
	if p.closeWrite == nil {
		return nil
	}
	return p.closeWrite()
}

// Close hangs the process up: all of it ends. Its output is let go first
// (no one reads it any more): what writes it, waiting on its reader, gives
// up, so the kill and the session's end do not wait on it.
func (p *Proc) Close() error {
	p.once.Do(func() {
		p.closed.Store(true)
		if c, ok := p.out.(io.Closer); ok {
			_ = c.Close()
		}
		select {
		case <-p.exited:
		default:
			if p.killFn != nil {
				p.killFn()
			}
		}
		_ = p.in.Close()
	})
	return nil
}

// Resize gives the process's terminal a new size (none: nothing).
func (p *Proc) Resize(rows, cols int) error {
	if p.resizeFn == nil {
		return nil
	}
	return p.resizeFn(rows, cols)
}

// Signal signals the process (protocol.TunnelSignal...).
func (p *Proc) Signal(sig int) error {
	if p.signalFn == nil {
		return nil
	}
	return p.signalFn(sig)
}

func (p *Proc) LocalAddr() net.Addr              { return procAddr{} }
func (p *Proc) RemoteAddr() net.Addr             { return procAddr{} }
func (p *Proc) SetDeadline(time.Time) error      { return nil }
func (p *Proc) SetReadDeadline(time.Time) error  { return nil }
func (p *Proc) SetWriteDeadline(time.Time) error { return nil }

type procAddr struct{}

func (procAddr) Network() string { return "process" }
func (procAddr) String() string  { return "process" }
