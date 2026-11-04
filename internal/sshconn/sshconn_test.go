//go:build unix

package sshconn_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

func target(t *testing.T, v map[string]any) connection.Target {
	t.Helper()
	tg, err := connection.ReadTarget(v)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// A login by password, or by key: the connection says the server's
// version and host key, and answers keepalives.
func TestDial(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	c, err := sshconn.Dial(context.Background(), target(t, srv.Values()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint() != srv.Fingerprint() || !strings.HasPrefix(c.Version, "SSH-2.0-") || c.Peer != "127.0.0.1" || !c.Alive(time.Second) {
		t.Fatalf("fingerprint %s, version %q, peer %q", c.Fingerprint(), c.Version, c.Peer)
	}
	if _, err := c.SFTP(); err != nil {
		t.Fatalf("sftp: %v", err)
	}
	_ = c.Close()
	if c.Alive(time.Second) {
		t.Fatal("alive after its close")
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	srv.AuthorizeKey(sshPub)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	v := srv.Values()
	delete(v, "password")
	v["private_key"] = string(pem.EncodeToMemory(block))
	v["host_key"] = srv.Fingerprint()
	if c, err = sshconn.Dial(context.Background(), target(t, v)); err != nil {
		t.Fatalf("by key, its host key pinned: %v", err)
	}
	_ = c.Close()

	locked, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pass"))
	v["private_key"] = string(pem.EncodeToMemory(locked))
	if _, err := sshconn.Dial(context.Background(), target(t, v)); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("an encrypted key without its passphrase: %v", err)
	}
	v["passphrase"] = "pass"
	if c, err = sshconn.Dial(context.Background(), target(t, v)); err != nil {
		t.Fatalf("an encrypted key with its passphrase: %v", err)
	}
	_ = c.Close()
}

// What came of a dial that did not log in, as the channel answers it.
func TestRefusals(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	failure := func(v map[string]any) (int, string) {
		t.Helper()
		ctx := context.Background()
		_, err := sshconn.Dial(ctx, target(t, v))
		if err == nil {
			t.Fatalf("%v: logged in", v)
		}
		a := sshconn.Failure(ctx, err)
		return a.Failure.Kind, a.Failure.Msg
	}
	v := srv.Values()
	v["password"] = "wrong"
	if kind, msg := failure(v); kind != protocol.LinkFailLogin || !strings.Contains(msg, "refused the login") {
		t.Errorf("a wrong password: %d %s", kind, msg)
	}
	v = srv.Values()
	v["host_key"] = "SHA256:" + strings.Repeat("A", 43)
	if kind, msg := failure(v); kind != protocol.LinkFailHostKey || !strings.Contains(msg, srv.Fingerprint()) {
		t.Errorf("another host key: %d %s", kind, msg)
	}
	v = srv.Values()
	delete(v, "password")
	if kind, msg := failure(v); kind != protocol.LinkFailLogin || !strings.Contains(msg, "no password and no key") {
		t.Errorf("no way to log in: %d %s", kind, msg)
	}
	v = srv.Values()
	v["port"] = uint64(1)
	if kind, _ := failure(v); kind != protocol.LinkFailUnreachable {
		t.Errorf("nothing there: %d", kind)
	}

	// Not an SSH server: a call says what answered.
	v = srv.Values()
	v["port"] = sshtest.Speaks(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	_, err := sshconn.Dial(context.Background(), target(t, v))
	a := sshconn.CallFailure(context.Background(), err, "")
	if a.Failure != nil || !strings.HasPrefix(string(a.Excerpt), "HTTP/1.1 400") {
		t.Errorf("not an SSH server: %+v (%v)", a, err)
	}

	// A server that never answers: the connect timeout.
	v = srv.Values()
	v["port"] = sshtest.Silent(t)
	v["connect_timeout"] = "500ms"
	start := time.Now()
	if kind, _ := failure(v); kind != protocol.LinkFailTimeout || time.Since(start) > 3*time.Second {
		t.Errorf("silent: %d after %s", kind, time.Since(start))
	}
}

// A call's login is kept for the next call to the same server, for its
// reuse; none kept without one, and none past it.
func TestPool(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	p := sshconn.NewPool()
	defer p.Close()
	v := srv.Values()
	v["call_reuse"] = "1s"
	tg := target(t, v)
	c1, err := p.Get(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	p.Put(tg, c1, true)
	c2, err := p.Get(context.Background(), tg)
	if err != nil || c2 != c1 {
		t.Fatalf("not kept: %v", err)
	}
	p.Put(tg, c2, true)
	time.Sleep(2500 * time.Millisecond)
	if p.Idle() != 0 || c1.Alive(time.Second) {
		t.Fatal("kept past its reuse")
	}
	v["call_reuse"] = "0s"
	tg = target(t, v)
	c3, err := p.Get(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	p.Put(tg, c3, true)
	if p.Idle() != 0 || c3.Alive(time.Second) {
		t.Fatal("kept without a reuse")
	}
}

// An open the server never answers gives up within OpenWait, and closes
// the connection: it is not to be trusted after.
func TestOpenGivesUp(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	c, err := sshconn.Dial(context.Background(), target(t, srv.Values()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	was := sshconn.OpenWait
	sshconn.OpenWait = 300 * time.Millisecond
	defer func() { sshconn.OpenWait = was }()
	srv.Stall.Store(true)
	start := time.Now()
	if _, err := c.Session(); err == nil || !strings.Contains(err.Error(), "did not open a session") {
		t.Fatalf("session: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("gave up after %s", took)
	}
	select {
	case <-c.Closed():
	default:
		t.Fatal("the connection stayed open")
	}
}

// Closing the connection ends an open waiting on it at once.
func TestCloseEndsOpen(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	c, err := sshconn.Dial(context.Background(), target(t, srv.Values()))
	if err != nil {
		t.Fatal(err)
	}
	srv.Stall.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := c.SFTP()
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-done:
		if !errors.Is(err, sshconn.ErrClosed) {
			t.Fatalf("sftp: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the open outlived the connection")
	}
}
