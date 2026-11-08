package minion

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// fakeTunneler is a server for the engine's tests: a stream it connects is
// one end of a pipe (the test holds the other), and closing it, or ending
// its write side, waits for release, as an SSH channel's close waits on a
// connection that is slow to take it.
type fakeTunneler struct {
	release chan struct{}
	mu      sync.Mutex
	far     []net.Conn
}

func (f *fakeTunneler) Dial(context.Context, string, string) (net.Conn, error) {
	near, far := net.Pipe()
	f.mu.Lock()
	f.far = append(f.far, far)
	f.mu.Unlock()
	return &slowConn{Conn: near, release: f.release}, nil
}

func (f *fakeTunneler) Listen(string, string) (net.Listener, error) {
	return nil, errors.New("no listening here")
}

func (f *fakeTunneler) Process(context.Context, string, []string, int, int) (*Proc, bool, error) {
	return nil, false, errors.New("no processes here")
}

type slowConn struct {
	net.Conn
	release chan struct{}
}

func (c *slowConn) Close() error {
	if c.release != nil {
		<-c.release
	}
	return c.Conn.Close()
}

func (c *slowConn) CloseWrite() error {
	if c.release != nil {
		<-c.release
	}
	return nil
}

func tunnelTask(id byte) protocol.TaskItem {
	return protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{id}, 16), Cmd: uint64(CmdTunnel)}
}

// openedStream starts a tunnel task and opens its stream 1, waiting for
// the minion's answer.
func openedStream(t *testing.T, r *Runner, task []byte) {
	t.Helper()
	r.Take(coreSays(t, tunnelTask(task[0])), nil)
	r.Take(coreSays(t, protocol.TunnelItem{T: protocol.ItemTunnel, Task: task, Stream: 1, Host: "10.0.0.5", Port: 22}), nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, it := range r.Outgoing() {
			if rep, ok := it.(protocol.TunnelReplyItem); ok && rep.Stream == 1 {
				if rep.Result != protocol.TunnelOpen {
					t.Fatalf("the stream: %+v", rep)
				}
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the stream did not open")
}

// within fails the test when fn does not return in a second: what a slow
// close must not hold up.
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s waited on a close the server was slow to take", what)
	}
}

// The session's connection went: its runner closes, and a tunnel task
// ends with it (no goroutine left waiting on a task no one cancels).
func TestTunnelEndsWithRunner(t *testing.T) {
	r := newRunnerWith(Config{Tunnels: &fakeTunneler{}}, CmdTunnel)
	r.Take(coreSays(t, tunnelTask(1)), nil)
	r.Close()
	if task := waitEnd(t, r, 2*time.Second); !task.ok {
		t.Fatalf("the tunnel task: %+v", task)
	}
}

// Closing a stream's connection goes over the SSH connection, and can be
// slow: the other streams, and the runner's messages, do not wait for it.
func TestTunnelCloseHoldsNothingUp(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	r := newRunnerWith(Config{Tunnels: &fakeTunneler{release: release}}, CmdTunnel)
	task := bytes.Repeat([]byte{2}, 16)
	openedStream(t, r, task)
	within(t, "core's close of a stream", func() {
		r.Take(coreSays(t, protocol.TunnelCloseItem{T: protocol.ItemTunnelClose, Task: task, Stream: 1, Reason: protocol.TunnelCloseReset}), nil)
	})
	within(t, "the next message", func() { r.Outgoing() })
	within(t, "the runner's close", r.Close)
}

// Core's eof ends the connection's write side, over the SSH connection
// too (a channel's EOF, a TLS close_notify): nothing else waits for it.
func TestTunnelEOFHoldsNothingUp(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	r := newRunnerWith(Config{Tunnels: &fakeTunneler{release: release}}, CmdTunnel)
	task := bytes.Repeat([]byte{3}, 16)
	openedStream(t, r, task)
	r.Take(coreSays(t, protocol.TunnelDataItem{T: protocol.ItemTunnelData, Task: task, Stream: 1, Off: 0, EOF: true}), nil)
	time.Sleep(50 * time.Millisecond) // the write side ending, slowly
	within(t, "the next message", func() { r.Outgoing() })
	within(t, "core's next item", func() {
		r.Take(coreSays(t, protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: task, Stream: 1, Next: 0}), nil)
	})
}
