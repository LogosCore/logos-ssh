package agent

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/ops"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// tunnelCore is core's end of a session, for tests: it answers each of the
// minion's messages, with items it has for it, and keeps what came.
type tunnelCore struct {
	t    *testing.T
	core *fakeCore
	sid  []byte
	got  []protocol.MinionMessage
}

// open starts a session over the test server and has its hello answered.
func openSession(t *testing.T, srv *sshtest.Server) (*tunnelCore, *sshconn.Conn) {
	t.Helper()
	tg, err := connection.ReadTarget(srv.Values(), srv.Credentials())
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := sshconn.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	core := newFakeCore()
	buildID := bytes.Repeat([]byte{0xb}, 16)
	s := newSession(tg, c, core, 1, buildID, testKeys)
	ended := make(chan struct{})
	go func() {
		s.run()
		close(ended)
	}()
	t.Cleanup(func() {
		_ = core.Close()
		<-ended
	})
	m := minionMessage(t, core.next(t).Data)
	cs := &tunnelCore{t: t, core: core, sid: bytes.Repeat([]byte{0x5}, 16)}
	_, data := coreMessage(t, m.ID, protocol.HelloResponseItem{T: protocol.ItemHelloResponse, SID: cs.sid})
	core.toMinion <- protocol.ConnFrame{ID: buildID, Data: data}
	return cs, c
}

// push sends core's items unasked.
func (cs *tunnelCore) push(items ...any) {
	_, data := coreMessage(cs.t, nil, items...)
	cs.core.toMinion <- protocol.ConnFrame{ID: cs.sid, Data: data}
}

// until answers the minion's messages (with what reply gives for each,
// nil: nothing) until one of their items satisfies done.
func (cs *tunnelCore) until(what string, done func(raw []byte) bool, reply func(protocol.MinionMessage) []any) {
	cs.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		m := minionMessage(cs.t, cs.core.next(cs.t).Data)
		checkItems(cs.t, m)
		cs.got = append(cs.got, m)
		var items []any
		if reply != nil {
			items = reply(m)
		}
		_, data := coreMessage(cs.t, m.ID, items...)
		cs.core.toMinion <- protocol.ConnFrame{ID: cs.sid, Data: data}
		for _, raw := range m.Items {
			if done(raw) {
				return
			}
		}
	}
	cs.t.Fatalf("no %s", what)
}

func is[T any](t *testing.T, raw []byte, typ int, check func(T) bool) bool {
	if protocol.ItemType(raw) != typ {
		return false
	}
	var v T
	if protocol.UnmarshalCBOR(raw, &v) != nil {
		t.Fatal("an item that does not read")
	}
	return check(v)
}

// acked: the minion acked task.
func acked(t *testing.T, task []byte) func([]byte) bool {
	return func(raw []byte) bool {
		return is(t, raw, protocol.ItemAck, func(a protocol.AckItem) bool {
			for _, id := range a.Tasks {
				if bytes.Equal(id, task) {
					return true
				}
			}
			return false
		})
	}
}

// A tunnel task over the session's SSH connection: a stream core opens to
// a TCP destination carries bytes both ways through the server; a terminal
// runs in the server's pty, says its exit; a UDP open is unsupported; the
// task ends ok when cancelled, and runs beside the task allowance.
func TestSessionTunnel(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	cs, _ := openSession(t, srv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	port := uint64(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a port

	task := bytes.Repeat([]byte{0x7}, 16)
	cs.push(protocol.TaskItem{T: protocol.ItemTask, Task: task, Cmd: ops.Tunnel, Args: protocol.Args{}})
	cs.until("ack of the tunnel task", acked(t, task), nil)

	// A TCP stream: open, then its bytes back.
	cs.push(protocol.TunnelItem{T: protocol.ItemTunnel, Task: task, Stream: 1, Host: "127.0.0.1", Port: port},
		protocol.TunnelItem{T: protocol.ItemTunnel, Task: task, Stream: 2, UDP: true})
	var udp *protocol.TunnelReplyItem
	cs.until("the stream's open", func(raw []byte) bool {
		return is(t, raw, protocol.ItemTunnelReply, func(r protocol.TunnelReplyItem) bool {
			if r.Stream == 2 {
				udp = &r
				return false
			}
			if r.Result != protocol.TunnelOpen {
				t.Fatalf("the stream: result %d %q", r.Result, r.Msg)
			}
			return true
		})
	}, nil)
	cs.push(protocol.TunnelDataItem{T: protocol.ItemTunnelData, Task: task, Stream: 1, Off: 0, Data: []byte("through ssh")})
	var back []byte
	cs.until("the bytes back", func(raw []byte) bool {
		return is(t, raw, protocol.ItemTunnelData, func(d protocol.TunnelDataItem) bool {
			if d.Stream == 1 {
				back = append(back, d.Data...)
			}
			return string(back) == "through ssh"
		})
	}, func(m protocol.MinionMessage) []any {
		// Core acks what it has.
		var acks []any
		for _, raw := range m.Items {
			if protocol.ItemType(raw) == protocol.ItemTunnelData {
				var d protocol.TunnelDataItem
				_ = protocol.UnmarshalCBOR(raw, &d)
				acks = append(acks, protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: task, Stream: d.Stream, Next: d.End()})
			}
		}
		return acks
	})
	if udp == nil {
		cs.until("the UDP open's answer", func(raw []byte) bool {
			return is(t, raw, protocol.ItemTunnelReply, func(r protocol.TunnelReplyItem) bool {
				if r.Stream == 2 {
					udp = &r
				}
				return udp != nil
			})
		}, nil)
	}
	if udp.Result != protocol.TunnelUnsupported || !strings.Contains(udp.Msg, "UDP") {
		t.Fatalf("a UDP open: %+v", udp)
	}

	// A terminal: open in a pty, its exit before its eof.
	if runtime.GOOS == "linux" {
		cs.push(protocol.TunnelItem{T: protocol.ItemTunnel, Task: task, Stream: 3, Kind: protocol.TunnelKindProcess, Path: "/bin/sh",
			Args: []string{"-c", "echo hi from the pty; exit 7"}, Rows: 24, Cols: 80})
		var terminal bool
		var exit *int64
		var out []byte
		cs.until("the terminal's exit", func(raw []byte) bool {
			switch protocol.ItemType(raw) {
			case protocol.ItemTunnelReply:
				is(t, raw, protocol.ItemTunnelReply, func(r protocol.TunnelReplyItem) bool {
					if r.Stream == 3 {
						terminal = r.Result == protocol.TunnelOpen && r.Terminal
					}
					return false
				})
			case protocol.ItemTunnelData:
				is(t, raw, protocol.ItemTunnelData, func(d protocol.TunnelDataItem) bool {
					if d.Stream == 3 {
						out = append(out, d.Data...)
					}
					return false
				})
			case protocol.ItemTunnelCtl:
				return is(t, raw, protocol.ItemTunnelCtl, func(c protocol.TunnelCtlItem) bool {
					exit = c.Exit
					return c.Stream == 3 && c.Exit != nil
				})
			}
			return false
		}, func(m protocol.MinionMessage) []any {
			var acks []any
			for _, raw := range m.Items {
				switch protocol.ItemType(raw) {
				case protocol.ItemTunnelData:
					var d protocol.TunnelDataItem
					_ = protocol.UnmarshalCBOR(raw, &d)
					acks = append(acks, protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: task, Stream: d.Stream, Next: d.End()})
				case protocol.ItemTunnelCtl:
					var c protocol.TunnelCtlItem
					_ = protocol.UnmarshalCBOR(raw, &c)
					acks = append(acks, protocol.TunnelAckItem{T: protocol.ItemTunnelAck, Task: task, Stream: c.Stream, Ctl: c.Seq + 1})
				}
			}
			return acks
		})
		if !terminal || *exit != 7 || !bytes.Contains(out, []byte("hi from the pty")) || bytes.Contains(out, []byte("LOGOS")) {
			t.Fatalf("terminal %v, exit %v, output %q", terminal, *exit, out)
		}
	}

	// Beside it, the task allowance is whole: a shell runs.
	cs.push(shellTask(9, "echo beside"))
	cs.until("the shell's end", func(raw []byte) bool {
		return is(t, raw, protocol.ItemResult, func(r protocol.ResultItem) bool { return r.Done && r.OK != nil && *r.OK })
	}, nil)

	// Cancelled: it ends ok, its streams closed.
	cs.push(protocol.CancelItem{T: protocol.ItemCancel, Task: task})
	cs.until("the tunnel task's end", func(raw []byte) bool {
		return is(t, raw, protocol.ItemResult, func(r protocol.ResultItem) bool {
			if bytes.Equal(r.Task, task) && r.Done && (r.OK == nil || !*r.OK) {
				t.Fatalf("the tunnel task: %+v", r)
			}
			return bytes.Equal(r.Task, task) && r.Done
		})
	}, nil)
}

// A reverse tunnel: the server listens, says where (tunnel_listen), and a
// connection to it is a stream the minion opens to core.
func TestSessionReverseTunnel(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	cs, _ := openSession(t, srv)
	task := bytes.Repeat([]byte{0x8}, 16)
	cs.push(protocol.TaskItem{T: protocol.ItemTask, Task: task, Cmd: ops.ReverseTunnel,
		Args: protocol.Args{minion.ArgReverseBind: "127.0.0.1", minion.ArgReverseListen: int64(0)}})
	var bound string
	cs.until("where the server listens", func(raw []byte) bool {
		return is(t, raw, protocol.ItemTunnelListen, func(l protocol.TunnelListenItem) bool {
			bound = l.Bound
			return true
		})
	}, nil)
	_, port, _ := net.SplitHostPort(bound)
	if port == "" || port == "0" {
		t.Fatalf("listens at %q", bound)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("to core"))
	var stream uint64
	cs.until("the minion's stream", func(raw []byte) bool {
		return is(t, raw, protocol.ItemTunnel, func(it protocol.TunnelItem) bool {
			stream = it.Stream
			return true
		})
	}, nil)
	cs.push(protocol.TunnelReplyItem{T: protocol.ItemTunnelReply, Task: task, Stream: stream, Result: protocol.TunnelOpen})
	var got []byte
	cs.until("the connection's bytes", func(raw []byte) bool {
		return is(t, raw, protocol.ItemTunnelData, func(d protocol.TunnelDataItem) bool {
			got = append(got, d.Data...)
			return string(got) == "to core"
		})
	}, nil)
}
