// Package sshconn reaches a server over SSH for the channel's minion
// (docs: contracts/agentless-channels/): it dials the server, directly or
// through a proxy, logs in with the target's credentials (a key, a
// password) in turn, checks the host key it presents, and tells what came of
// it apart: nothing reached, something that is not an SSH server, a host
// key other than the one given, every login refused.
package sshconn

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/logoscore/logos-golang-channel-core/v3/pkg/linkclient"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// Conn is a server's SSH connection, logged in.
type Conn struct {
	SSH *ssh.Client
	// HostKey is the key the server presented; Version the version string
	// it sent (SSH-2.0-OpenSSH_9.6p1 …).
	HostKey ssh.PublicKey
	Version string
	// Peer is the IP address the channel connected to: the session's
	// external address. Empty through a proxy that resolved a name.
	Peer string
	// User is who the connection logged in as; Password the password it
	// logged in with, when the login was a password's (a PLAINTEXT
	// credential's): what a become's sudo asks for unless the task gives
	// another. Never logged.
	User     string
	Password string

	// opening serializes opening the SFTP client; mu guards ftp, never held
	// across a wait, so Close never waits on the server.
	opening sync.Mutex
	mu      sync.Mutex
	ftp     *sftp.Client
	once    sync.Once
	// closed is closed with the connection: what waits on the server gives
	// up with it.
	closed chan struct{}
	// state is what lives as long as the connection does (State): the
	// shells a become keeps open on it, say.
	stateMu sync.Mutex
	state   map[any]any
}

// State is the connection's value for key, made by create the first time
// it is asked for: what outlives each call on a connection kept for the
// next (a become's elevated shells), and goes with it.
func (c *Conn) State(key any, create func() any) any {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if v, ok := c.state[key]; ok {
		return v
	}
	if c.state == nil {
		c.state = map[any]any{}
	}
	v := create()
	c.state[key] = v
	return v
}

// OpenWait bounds opening a channel (a session, the SFTP client): a server
// answers an open at once, and a connection that went away under one can
// leave it unanswered for good (x/crypto/ssh: an open queued during a key
// exchange the connection did not live through).
var OpenWait = 15 * time.Second

// ErrClosed is an open given up on because the connection closed.
var ErrClosed = errors.New("the connection closed")

// open waits for a channel the server opens, within OpenWait and no longer
// than the connection lives. One it gives up on closes the connection: it
// is not to be trusted after. x/crypto offers no way to end an open, so one
// that never returns stays behind, waiting on a connection that is gone.
func open[T any](c *Conn, what string, f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := f()
		done <- result{v, err}
	}()
	timer := time.NewTimer(OpenWait)
	defer timer.Stop()
	var zero T
	select {
	case r := <-done:
		return r.v, r.err
	case <-c.closed:
		return zero, fmt.Errorf("%s: %w", what, ErrClosed)
	case <-timer.C:
		_ = c.Close()
		return zero, fmt.Errorf("the server did not open %s within %s", what, OpenWait)
	}
}

// Session opens a session (an exec channel), within OpenWait.
func (c *Conn) Session() (*ssh.Session, error) {
	return open(c, "a session", c.SSH.NewSession)
}

// SFTP is the connection's SFTP client, opened the first time it is asked
// for, within OpenWait.
func (c *Conn) SFTP() (*sftp.Client, error) {
	c.opening.Lock()
	defer c.opening.Unlock()
	c.mu.Lock()
	f := c.ftp
	c.mu.Unlock()
	if f != nil {
		return f, nil
	}
	f, err := open(c, "its SFTP", func() (*sftp.Client, error) { return sftp.NewClient(c.SSH) })
	if err != nil {
		return nil, fmt.Errorf("the server's SFTP: %w", err)
	}
	c.mu.Lock()
	c.ftp = f
	c.mu.Unlock()
	return f, nil
}

// Fingerprint is the presented host key's SHA-256 fingerprint, as
// ssh-keygen -l prints it.
func (c *Conn) Fingerprint() string { return ssh.FingerprintSHA256(c.HostKey) }

// Alive reports whether the server answers a keepalive within wait.
func (c *Conn) Alive(wait time.Duration) bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := c.SSH.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		// A server that does not know the request still answers it: false
		// for the request, but alive.
		return err == nil
	case <-time.After(wait):
		return false
	}
}

// Close closes the connection, its SFTP client with it; what waits on the
// server (an open, an SFTP request, a command's output) gives up.
func (c *Conn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.closed)
		err = c.SSH.Close()
		c.mu.Lock()
		f := c.ftp
		c.mu.Unlock()
		if f != nil {
			_ = f.Close() // the connection's close says what matters
		}
	})
	return err
}

// Closed is closed once the connection is.
func (c *Conn) Closed() <-chan struct{} { return c.closed }

// Wait returns once the connection closed, from either side.
func (c *Conn) Wait() error { return c.SSH.Wait() }

// HostKeyError: the server presented a host key other than the one the
// target gives.
type HostKeyError struct{ Presented, Want string }

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("the server's host key is %s, not the one the target gives (%s)", e.Presented, e.Want)
}

// LoginError: the server refused the login, or the target gives none that
// can be tried.
type LoginError struct{ Why string }

func (e *LoginError) Error() string { return e.Why }

// NotSSHError: what answered is not an SSH server; First is the start of
// what it sent.
type NotSSHError struct {
	First []byte
	Err   error
}

func (e *NotSSHError) Error() string {
	return fmt.Sprintf("not an SSH server (it sent %q): %v", protocol.Excerpt(e.First), e.Err)
}

// Dial reaches the target's server and logs in with its logins in turn, a
// connection each, until one is taken; each try within the target's
// connect timeout. Logins say how those tried fared: the refused ones, then
// the one taken. A refusal (or a credential that does not read) moves on to
// the next; anything else ends the dial, as the next would meet it too: the
// server not reached, another host key, not an SSH server.
func Dial(ctx context.Context, t connection.Target) (*Conn, []protocol.LinkLogin, error) {
	if len(t.Logins) == 0 {
		return nil, nil, &LoginError{Why: "the target gives no credentials"}
	}
	var logins []protocol.LinkLogin
	var refusals []string
	for _, l := range t.Logins {
		c, err := dialAs(ctx, t, l)
		var login *LoginError
		switch {
		case err == nil:
			return c, append(logins, protocol.LinkLogin{Credential: l.Credential, Accepted: true}), nil
		case errors.As(err, &login) && ctx.Err() == nil:
			logins = append(logins, protocol.LinkLogin{Credential: l.Credential})
			refusals = append(refusals, l.Label()+": "+login.Why)
		default:
			return nil, logins, err
		}
	}
	return nil, logins, &LoginError{Why: strings.Join(refusals, "; ")}
}

// dialAs reaches the target's server and logs in as l, within the target's
// connect timeout.
func dialAs(ctx context.Context, t connection.Target, l connection.Login) (*Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.ConnectTimeout)
	defer cancel()
	auth, err := authMethods(l)
	if err != nil {
		return nil, err
	}
	raw, err := dial(ctx, t)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	rec := &recording{Conn: raw}
	var presented ssh.PublicKey
	var mismatch *HostKeyError
	cfg := &ssh.ClientConfig{
		User: l.User, Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			presented = key
			if t.HostKey != "" && ssh.FingerprintSHA256(key) != t.HostKey {
				mismatch = &HostKeyError{Presented: ssh.FingerprintSHA256(key), Want: t.HostKey}
				return mismatch
			}
			return nil
		},
	}
	// The handshake gives up with the context: closing the connection ends
	// it.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	conn, chans, reqs, err := ssh.NewClientConn(rec, t.Addr, cfg)
	stop()
	if err != nil {
		_ = raw.Close()
		switch first := rec.first(); {
		case mismatch != nil:
			return nil, mismatch
		case ctx.Err() != nil:
			return nil, fmt.Errorf("%w: %v", context.DeadlineExceeded, err)
		case len(first) > 0 && !strings.HasPrefix(string(first), "SSH-"):
			return nil, &NotSSHError{First: first, Err: err}
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, &LoginError{Why: "the server refused the login: " + strings.TrimPrefix(err.Error(), "ssh: handshake failed: ")}
		case len(first) == 0:
			return nil, fmt.Errorf("the server closed the connection before it said anything: %w", err)
		}
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &Conn{SSH: ssh.NewClient(conn, chans, reqs), HostKey: presented, Version: string(conn.ServerVersion()), Peer: peerOf(t, raw),
		User: l.User, Password: passwordOf(l), closed: make(chan struct{})}, nil
}

// passwordOf is the password a login logged in with: a password's, none for
// a key's.
func passwordOf(l connection.Login) string {
	if l.PrivateKey != "" {
		return ""
	}
	return l.Password
}

// authMethods are a login's ways of logging in: a key's, or a password (as
// itself, and answering a keyboard-interactive prompt, which many servers
// ask passwords by).
func authMethods(t connection.Login) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if t.PrivateKey != "" {
		key, err := ReadableKey(t.PrivateKey)
		if err != nil {
			return nil, &LoginError{Why: "the private key does not read: " + err.Error()}
		}
		var signer ssh.Signer
		if t.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(t.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(key))
		}
		var missing *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &missing):
			return nil, &LoginError{Why: "the private key is encrypted: the credential needs its passphrase"}
		case err != nil && err.Error() == "ssh: no key found":
			return nil, &LoginError{Why: "the private key does not read: no -----BEGIN … PRIVATE KEY----- block in it (give the whole key file)"}
		case err != nil:
			return nil, &LoginError{Why: "the private key does not read: " + err.Error()}
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		pw := t.Password
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = pw
			}
			return answers, nil
		}))
	}
	if len(auth) == 0 {
		return nil, &LoginError{Why: "the credential gives no password and no key"}
	}
	return auth, nil
}

// recording is a connection that keeps the first bytes it read: what
// answered, when it is not an SSH server.
type recording struct {
	net.Conn
	mu   sync.Mutex
	head []byte
}

func (r *recording) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		if left := protocol.MaxLinkExcerpt - len(r.head); left > 0 {
			r.head = append(r.head, p[:min(n, left)]...)
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recording) first() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.head...)
}

// Failure is the answer for a call or an open that met err: a failure of
// its kind (login and host_key ones an agentless channel's own).
func Failure(ctx context.Context, err error) linkclient.Answer {
	var hostKey *HostKeyError
	var login *LoginError
	var notSSH *NotSSHError
	var dnsErr *net.DNSError
	var netErr net.Error
	var opErr *net.OpError
	var refused *proxyRefused
	switch {
	case errors.As(err, &hostKey):
		return linkclient.Fail(protocol.LinkFailHostKey, "%s", err)
	case errors.As(err, &login):
		return linkclient.Fail(protocol.LinkFailLogin, "%s", err)
	case errors.As(err, &notSSH):
		return linkclient.Fail(protocol.LinkFailOther, "%s", err)
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || (errors.As(err, &netErr) && netErr.Timeout()):
		return linkclient.Fail(protocol.LinkFailTimeout, "%s", err)
	case errors.As(err, &refused):
		return linkclient.Fail(protocol.LinkFailOther, "%s", err)
	case errors.As(err, &dnsErr), errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETUNREACH), errors.As(err, &opErr) && opErr.Op == "dial":
		return linkclient.Fail(protocol.LinkFailUnreachable, "%s", err)
	}
	return linkclient.Fail(protocol.LinkFailOther, "%s", err)
}

// CallFailure is Failure for a call, which can say what answered when it
// is not an SSH server: core shows the target "not the minion", with it.
func CallFailure(ctx context.Context, err error, peer string) linkclient.Answer {
	var notSSH *NotSSHError
	if errors.As(err, &notSSH) {
		return linkclient.Answer{Excerpt: protocol.Excerpt(notSSH.First), Peer: peer}
	}
	return Failure(ctx, err)
}

// peerOf is the server's external address, as core shows it: the one c is
// connected to; through a proxy, the target's host when it is an IP
// address (a name, the proxy resolves), none otherwise.
func peerOf(t connection.Target, c net.Conn) string {
	if t.Proxy != nil {
		if a, err := netip.ParseAddr(t.Host); err == nil {
			return a.Unmap().String()
		}
		return ""
	}
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// dial connects to t's address, through its proxy when it has one.
func dial(ctx context.Context, t connection.Target) (net.Conn, error) {
	d := &net.Dialer{KeepAlive: 30 * time.Second}
	if t.Proxy == nil {
		return d.DialContext(ctx, "tcp", t.Addr)
	}
	switch t.Proxy.Scheme {
	case "socks5", "socks5h":
		p, err := proxy.FromURL(t.Proxy, d)
		if err != nil {
			return nil, err
		}
		cd, ok := p.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("the SOCKS dialer takes no context")
		}
		return cd.DialContext(ctx, "tcp", t.Addr)
	case "http":
		return dialConnect(ctx, d, t)
	}
	return nil, fmt.Errorf("proxy scheme %q", t.Proxy.Scheme)
}

// dialConnect asks an HTTP proxy for a tunnel to t's address (CONNECT).
func dialConnect(ctx context.Context, d *net.Dialer, t connection.Target) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp", t.Proxy.Host)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: t.Addr}, Host: t.Addr, Header: http.Header{}}
	if u := t.Proxy.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	if err := req.Write(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = resp.Body.Close() // a CONNECT's answer has no body worth reading
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		return nil, &proxyRefused{status: resp.Status}
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		// The server's first bytes came with the proxy's answer.
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

type proxyRefused struct{ status string }

func (e *proxyRefused) Error() string { return "the proxy refused the tunnel: " + e.status }

// bufferedConn reads first what a reader buffered past the proxy's answer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Dial connects to address from the server (network "tcp": direct-tcpip,
// host:port; "unix": OpenSSH's direct-streamlocal, a socket's path),
// within ctx: the server connects as slowly as its destination answers, so
// OpenWait does not bound it, nor does it close the connection. It gives up
// with the connection too. A refusal is an *ssh.OpenChannelError.
func (c *Conn) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-c.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	conn, err := c.SSH.DialContext(ctx, network, address)
	if err != nil && c.isClosed() {
		return nil, fmt.Errorf("a connection to %s: %w", address, ErrClosed)
	}
	return conn, err
}

// Listen has the server listen at a tcp address (a remote forward,
// tcpip-forward: on the server's loopback unless its GatewayPorts lets it
// listen where asked; port 0, one it picks), within OpenWait.
func (c *Conn) Listen(network, address string) (net.Listener, error) {
	return open(c, "a remote forward", func() (net.Listener, error) { return c.SSH.Listen(network, address) })
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}
