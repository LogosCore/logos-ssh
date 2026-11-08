package sshhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// tunnelHost is a Host over a test server, with the server to set.
func tunnelHost(t *testing.T) (*Host, *sshtest.Server) {
	t.Helper()
	srv := sshtest.New(t, t.TempDir())
	tg, err := connection.ReadTarget(srv.Values(), srv.Credentials())
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := sshconn.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return New(c), srv
}

// echo listens on the test's machine, writing back what comes.
func echo(t *testing.T, ln net.Listener) {
	t.Helper()
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
}

func roundTrip(t *testing.T, c net.Conn, say string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(say)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(say))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != say {
		t.Fatalf("read %q (%v), want %q", got, err, say)
	}
}

func openResult(t *testing.T, err error) int {
	t.Helper()
	var oe *minion.OpenError
	if !errors.As(err, &oe) {
		t.Fatalf("not an OpenError: %v", err)
	}
	return oe.Result
}

// The server connects where a stream goes: TCP and a unix socket; what it
// refuses comes back as the result its words say.
func TestDial(t *testing.T) {
	h, srv := tunnelHost(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, ln)
	c, err := h.Dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "over ssh")
	_ = c.Close()

	sock := filepath.Join(t.TempDir(), "s")
	uln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	echo(t, uln)
	c, err = h.Dial(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "over a socket")
	_ = c.Close()

	// A port no one listens on: refused.
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := free.Addr().String()
	_ = free.Close()
	if _, err := h.Dial(context.Background(), "tcp", addr); openResult(t, err) != protocol.TunnelRefused {
		t.Fatalf("a closed port: %v", err)
	}
	// A socket that is not there: not found.
	if _, err := h.Dial(context.Background(), "unix", sock+"-gone"); openResult(t, err) != protocol.TunnelNotFound {
		t.Fatalf("no socket: %v", err)
	}
	// A server without unix sockets (an unknown channel type): unsupported.
	srv.NoUnix.Store(true)
	if _, err := h.Dial(context.Background(), "unix", sock); openResult(t, err) != protocol.TunnelUnsupported {
		t.Fatalf("no unix sockets: %v", err)
	}
	// No forwarding at all: denied, with the server's words.
	srv.NoForward.Store(true)
	_, err = h.Dial(context.Background(), "tcp", ln.Addr().String())
	if openResult(t, err) != protocol.TunnelDenied || !strings.Contains(err.Error(), "AllowTcpForwarding") {
		t.Fatalf("forwarding off: %v", err)
	}
}

func TestByWords(t *testing.T) {
	for msg, want := range map[string]int{
		"Connection refused":                               protocol.TunnelRefused,
		"No route to host":                                 protocol.TunnelHostUnreachable,
		"Name or service not known":                        protocol.TunnelHostUnreachable,
		"Name does not resolve":                            protocol.TunnelHostUnreachable,
		"Temporary failure in name resolution":             protocol.TunnelHostUnreachable,
		"Network is unreachable":                           protocol.TunnelNetUnreachable,
		"Connection timed out":                             protocol.TunnelTimedOut,
		"dial unix /x: connect: no such file or directory": protocol.TunnelNotFound,
		"Permission denied":                                protocol.TunnelDenied,
		"something else":                                   protocol.TunnelFailed,
	} {
		if got := byWords(msg); got != want {
			t.Errorf("%q: %d, want %d", msg, got, want)
		}
	}
}

// A remote forward: the server listens, its connections come to the
// listener; one the server refuses is denied.
func TestListen(t *testing.T) {
	h, srv := tunnelHost(t)
	ln, err := h.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if port == "0" {
		t.Fatalf("listens at %s: no port said", ln.Addr())
	}
	echo(t, ln)
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c, "from the server's side")
	_ = c.Close()
	_ = ln.Close()

	srv.NoForward.Store(true)
	if _, err := h.Listen("tcp", "127.0.0.1:0"); openResult(t, err) != protocol.TunnelDenied {
		t.Fatalf("forwarding off: %v", err)
	}
}

// readAll reads a process's output until its eof, with its exit.
func readAll(t *testing.T, p *minion.Proc) (string, int64) {
	t.Helper()
	code := int64(-100)
	p.OnExit(func(c int64) { code = c })
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(&out, p)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the process did not end")
	}
	return out.String(), code
}

// A process in a terminal (Linux's test server gives one): its output
// without the session's process id, its exit, a resize the server sees;
// on pipes when the server gives no terminal, its input ending.
func TestProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the test server's terminals are Linux's")
	}
	h, srv := tunnelHost(t)
	p, terminal, err := h.Process(context.Background(), "/bin/sh", []string{"-c", "echo in a terminal; [ -t 0 ] && echo tty; exit 3"}, 24, 80)
	if err != nil || !terminal {
		t.Fatalf("terminal %v: %v", terminal, err)
	}
	out, code := readAll(t, p)
	if !strings.Contains(out, "in a terminal") || !strings.Contains(out, "tty") || strings.Contains(out, "LOGOS") || code != 3 {
		t.Fatalf("output %q, exit %d", out, code)
	}

	// Resized, and interrupted as a key pressed: Ctrl-C.
	p, _, err = h.Process(context.Background(), "/bin/sh", []string{"-c", "sleep 30"}, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Resize(40, 120); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for srv.Size.Load() != [2]int{40, 120} && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := srv.Size.Load(); got != [2]int{40, 120} {
		t.Fatalf("the server's size %v", got)
	}
	time.Sleep(200 * time.Millisecond) // sleep under way
	if err := p.Signal(protocol.TunnelSignalInterrupt); err != nil {
		t.Fatal(err)
	}
	if _, code := readAll(t, p); code != 130 {
		t.Fatalf("interrupted: exit %d", code)
	}

	// Terminated, through the session's process id.
	p, _, err = h.Process(context.Background(), "/bin/sh", []string{"-c", "sleep 30"}, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	_ = p.Signal(protocol.TunnelSignalTerminate)
	if _, code := readAll(t, p); code != 128+15 && code != 143 {
		t.Fatalf("terminated: exit %d", code)
	}

	// No terminal: on pipes, its input ends.
	srv.NoPTY.Store(true)
	p, terminal, err = h.Process(context.Background(), "/bin/cat", nil, 24, 80)
	if err != nil || terminal {
		t.Fatalf("terminal %v: %v", terminal, err)
	}
	if _, err := p.Write([]byte("piped\n")); err != nil {
		t.Fatal(err)
	}
	_ = p.CloseWrite()
	if out, code := readAll(t, p); out != "piped\n" || code != 0 {
		t.Fatalf("output %q, exit %d", out, code)
	}

	// Closed: it is hung up, and gone.
	p, _, err = h.Process(context.Background(), "/bin/sh", []string{"-c", "sleep 30"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	_ = p.Close()
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) || time.Since(start) > 5*time.Second {
		t.Fatalf("after close: %v", err)
	}
}

func TestProcessLine(t *testing.T) {
	if got := processLine(false, "M:", "", nil); got != `echo M:$$; exec "${SHELL:-/bin/sh}" -l` {
		t.Fatal(got)
	}
	if got := processLine(false, "M:", "/bin/echo", []string{"it's", "a b"}); got != `echo M:$$; exec '/bin/echo' 'it'\''s' 'a b'` {
		t.Fatal(got)
	}
	if got := processLine(true, "M:", `C:\Program Files\x.exe`, []string{`a"b`, `c\`, "", "plain"}); got != `"C:\Program Files\x.exe" "a\"b" c\ "" plain` {
		t.Fatal(got)
	}
	if got := processLine(true, "M:", "", nil); got != "" {
		t.Fatal(got)
	}
}

// A process whose output no one reads any more (its stream gone) still
// closes: it is killed on the server, and nothing is left writing its
// output (x/crypto's copy of it, s.Wait).
func TestProcessCloseWithOutputPending(t *testing.T) {
	h, srv := tunnelHost(t)
	for _, size := range [][2]int{{0, 0}, {24, 80}} {
		if size[0] > 0 && runtime.GOOS != "linux" {
			continue
		}
		srv.NoPTY.Store(size[0] == 0)
		probe := fmt.Sprintf("logos-probe-%d-%d", time.Now().UnixNano(), size[0])
		p, _, err := h.Process(context.Background(), "/bin/sh", []string{"-c", "while :; do echo " + probe + "; done"}, size[0], size[1])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(p, make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond) // its output backs up: no one reads it
		closed := make(chan struct{})
		go func() {
			_ = p.Close()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("size %v: Close hung on the output no one reads", size)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			out, _ := exec.Command("pgrep", "-f", probe).Output()
			stack := make([]byte, 1<<20)
			stack = stack[:runtime.Stack(stack, true)]
			stuck := bytes.Contains(stack, []byte("(*Session).stdout")) && bytes.Contains(stack, []byte("io.(*pipe).write"))
			if len(bytes.TrimSpace(out)) == 0 && !stuck {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("size %v: after Close, the process runs (%q) or its output copy is stuck (%v)", size, out, stuck)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}
