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

func target(t *testing.T, v map[string]any, given map[string]protocol.Credential) connection.Target {
	t.Helper()
	tg, err := connection.ReadTarget(v, given)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// keyCredential is a KEY credential of the server's user for priv, the key
// locked with passphrase when there is one.
func keyCredential(t *testing.T, srv *sshtest.Server, id string, priv ed25519.PrivateKey, passphrase string) protocol.Credential {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase != "" {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Credential{ID: id, Name: "test key", Type: protocol.CredentialTypeKey, Username: srv.User,
		Key: string(pem.EncodeToMemory(block))}
}

// A login by password, or by key: the connection says the server's
// version and host key, and answers keepalives; the logins say which
// credential was taken.
func TestDial(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	c, logins, err := sshconn.Dial(context.Background(), target(t, srv.Values(), srv.Credentials()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Fingerprint() != srv.Fingerprint() || !strings.HasPrefix(c.Version, "SSH-2.0-") || c.Peer != "127.0.0.1" || !c.Alive(time.Second) ||
		c.User != srv.User {
		t.Fatalf("fingerprint %s, version %q, peer %q, user %q", c.Fingerprint(), c.Version, c.Peer, c.User)
	}
	if len(logins) != 1 || logins[0] != (protocol.LinkLogin{Credential: sshtest.PasswordID, Accepted: true}) {
		t.Fatalf("logins %+v", logins)
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
	v := srv.Values()
	v["credentials"] = []any{"k1"}
	v["host_key"] = srv.Fingerprint()
	if c, _, err = sshconn.Dial(context.Background(), target(t, v, map[string]protocol.Credential{"k1": keyCredential(t, srv, "k1", priv, "")})); err != nil {
		t.Fatalf("by key, its host key pinned: %v", err)
	}
	_ = c.Close()

	locked := keyCredential(t, srv, "k1", priv, "pass")
	if _, _, err := sshconn.Dial(context.Background(), target(t, v, map[string]protocol.Credential{"k1": locked})); err == nil ||
		!strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("an encrypted key without its passphrase: %v", err)
	}
	locked.Passphrase = "pass"
	if c, _, err = sshconn.Dial(context.Background(), target(t, v, map[string]protocol.Credential{"k1": locked})); err != nil {
		t.Fatalf("an encrypted key with its passphrase: %v", err)
	}
	_ = c.Close()

	// A key without a username logs in as the target's user.
	plain := keyCredential(t, srv, "k1", priv, "")
	plain.Username = ""
	v["user"] = srv.User
	if c, _, err = sshconn.Dial(context.Background(), target(t, v, map[string]protocol.Credential{"k1": plain})); err != nil || c.User != srv.User {
		t.Fatalf("the target's user: %v", err)
	}
	_ = c.Close()
}

// The credentials are tried in order, a connection each, until one is
// taken: the logins say each refusal and the one taken; with all refused,
// the failure names each.
func TestDialTriesEachCredential(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	_, unknown, _ := ed25519.GenerateKey(rand.Reader) // not authorized
	given := map[string]protocol.Credential{
		"wrong": srv.PasswordCredential("wrong", "nope"),
		"k9":    keyCredential(t, srv, "k9", unknown, ""),
		"good":  srv.PasswordCredential("good", srv.Password),
	}
	v := srv.Values()
	v["credentials"] = []any{"wrong", "k9", "good"}
	c, logins, err := sshconn.Dial(context.Background(), target(t, v, given))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	want := []protocol.LinkLogin{{Credential: "wrong"}, {Credential: "k9"}, {Credential: "good", Accepted: true}}
	if len(logins) != len(want) || logins[0] != want[0] || logins[1] != want[1] || logins[2] != want[2] {
		t.Fatalf("logins %+v", logins)
	}

	v["credentials"] = []any{"wrong", "k9"}
	_, logins, err = sshconn.Dial(context.Background(), target(t, v, given))
	a := sshconn.Failure(context.Background(), err)
	if a.Failure == nil || a.Failure.Kind != protocol.LinkFailLogin || len(logins) != 2 || logins[0].Accepted || logins[1].Accepted ||
		!strings.Contains(a.Failure.Msg, `(password "test password")`) || !strings.Contains(a.Failure.Msg, `(key "test key")`) {
		t.Fatalf("every login refused: %+v %+v", a, logins)
	}

	// Anything but a refusal ends the dial: the next would meet it too.
	v["credentials"] = []any{"wrong", "good"}
	v["host_key"] = "SHA256:" + strings.Repeat("A", 43)
	if _, logins, err := sshconn.Dial(context.Background(), target(t, v, given)); len(logins) != 0 ||
		sshconn.Failure(context.Background(), err).Failure.Kind != protocol.LinkFailHostKey {
		t.Fatalf("another host key: %+v %v", logins, err)
	}
}

// What came of a dial that did not log in, as the channel answers it.
func TestRefusals(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	failure := func(v map[string]any, given map[string]protocol.Credential) (int, string) {
		t.Helper()
		ctx := context.Background()
		_, _, err := sshconn.Dial(ctx, target(t, v, given))
		if err == nil {
			t.Fatalf("%v: logged in", v)
		}
		a := sshconn.Failure(ctx, err)
		return a.Failure.Kind, a.Failure.Msg
	}
	wrong := map[string]protocol.Credential{sshtest.PasswordID: srv.PasswordCredential(sshtest.PasswordID, "wrong")}
	if kind, msg := failure(srv.Values(), wrong); kind != protocol.LinkFailLogin || !strings.Contains(msg, "refused the login") {
		t.Errorf("a wrong password: %d %s", kind, msg)
	}
	v := srv.Values()
	v["host_key"] = "SHA256:" + strings.Repeat("A", 43)
	if kind, msg := failure(v, srv.Credentials()); kind != protocol.LinkFailHostKey || !strings.Contains(msg, srv.Fingerprint()) {
		t.Errorf("another host key: %d %s", kind, msg)
	}
	v = srv.Values()
	v["port"] = uint64(1)
	if kind, _ := failure(v, srv.Credentials()); kind != protocol.LinkFailUnreachable {
		t.Errorf("nothing there: %d", kind)
	}

	// Not an SSH server: a call says what answered.
	v = srv.Values()
	v["port"] = sshtest.Speaks(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	_, _, err := sshconn.Dial(context.Background(), target(t, v, srv.Credentials()))
	a := sshconn.CallFailure(context.Background(), err, "")
	if a.Failure != nil || !strings.HasPrefix(string(a.Excerpt), "HTTP/1.1 400") {
		t.Errorf("not an SSH server: %+v (%v)", a, err)
	}

	// A server that never answers: the connect timeout.
	v = srv.Values()
	v["port"] = sshtest.Silent(t)
	v["connect_timeout"] = "500ms"
	start := time.Now()
	if kind, _ := failure(v, srv.Credentials()); kind != protocol.LinkFailTimeout || time.Since(start) > 3*time.Second {
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
	tg := target(t, v, srv.Credentials())
	c1, logins, err := p.Get(context.Background(), tg)
	if err != nil || len(logins) != 1 || !logins[0].Accepted {
		t.Fatalf("%v, logins %+v", err, logins)
	}
	p.Put(tg, c1, true)
	// Kept: no login, so none to tell of.
	c2, logins, err := p.Get(context.Background(), tg)
	if err != nil || c2 != c1 || logins != nil {
		t.Fatalf("not kept: %v, logins %+v", err, logins)
	}
	p.Put(tg, c2, true)
	time.Sleep(2500 * time.Millisecond)
	if p.Idle() != 0 || c1.Alive(time.Second) {
		t.Fatal("kept past its reuse")
	}
	v["call_reuse"] = "0s"
	tg = target(t, v, srv.Credentials())
	c3, _, err := p.Get(context.Background(), tg)
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
	c, _, err := sshconn.Dial(context.Background(), target(t, srv.Values(), srv.Credentials()))
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
	c, _, err := sshconn.Dial(context.Background(), target(t, srv.Values(), srv.Credentials()))
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

// A kept login is for the credentials it was made with: a target whose
// credential changed (its password edited) logs in again, and is refused
// when the new one is wrong, rather than riding the old login.
func TestPoolKeysByCredentials(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	p := sshconn.NewPool()
	defer p.Close()
	v := srv.Values()
	v["call_reuse"] = "1m"
	tg := target(t, v, srv.Credentials())
	c, _, err := p.Get(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	p.Put(tg, c, true)
	edited := target(t, v, map[string]protocol.Credential{sshtest.PasswordID: srv.PasswordCredential(sshtest.PasswordID, "changed")})
	if _, logins, err := p.Get(context.Background(), edited); err == nil || len(logins) != 1 || logins[0].Accepted {
		t.Fatalf("an edited credential rode the kept login: %v %+v", err, logins)
	}
}
