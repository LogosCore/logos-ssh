//go:build unix

// Package sshtest is an SSH server for tests, in the test's process on
// 127.0.0.1: it logs in its user by password or by an authorized key, runs
// commands in /bin/sh (each in a process group of its own, as sshd's
// sessions run), answers signals and keepalives, and serves SFTP from a
// folder. NewWindows makes one that answers as Windows's OpenSSH does.
package sshtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"io"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Server is a running SSH server.
type Server struct {
	// User and Password log in; so does a key AuthorizeKey adds.
	User, Password string
	// Dir is where SFTP starts and commands run.
	Dir     string
	HostKey ssh.Signer
	// Stall leaves the channels opened from now on unanswered, neither
	// accepted nor refused: a server gone quiet under an open.
	Stall atomic.Bool

	// Signals counts the signals commands got.
	Signals atomic.Int32

	ln         net.Listener
	mu         sync.Mutex
	authorized []ssh.PublicKey
	wg         sync.WaitGroup
	// exec runs commands in place of /bin/sh, each in a ctx of execCtx's;
	// sftpOf serves SFTP in place of the plain server (NewWindows).
	exec    Exec
	execCtx context.Context
	sftpOf  func(io.ReadWriteCloser) sftpServer
}

// New starts a server for t, its SFTP and commands in dir; it stops when
// the test ends.
func New(t testing.TB, dir string) *Server {
	t.Helper()
	return newServer(t, dir, "")
}

// newServer starts a server saying version ("": x/crypto's own).
func newServer(t testing.TB, dir, version string) *Server {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{User: "tester", Password: "secret", Dir: dir, HostKey: signer, ln: ln}
	cfg := &ssh.ServerConfig{
		ServerVersion: version,
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if m.User() == s.User && string(pw) == s.Password {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		},
		PublicKeyCallback: func(m ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, k := range s.authorized {
				if m.User() == s.User && string(k.Marshal()) == string(key.Marshal()) {
					return nil, nil
				}
			}
			return nil, errors.New("not an authorized key")
		},
	}
	cfg.AddHostKey(signer)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(nc, cfg)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// AuthorizeKey lets key log in as the user.
func (s *Server) AuthorizeKey(key ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorized = append(s.authorized, key)
}

// Host and Port are where the server listens.
func (s *Server) Host() string { return "127.0.0.1" }

func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// PasswordID is the id of the server's password's credential.
const PasswordID = "pw-1"

// Values are a target's values for the server, logging in by its password:
// the credential Credentials gives under PasswordID.
func (s *Server) Values() map[string]any {
	return map[string]any{"host": s.Host(), "port": uint64(s.Port()), "credentials": []any{PasswordID}} //nolint:gosec // a port
}

// Credentials are what core gives beside Values: the server's user and
// password, a PLAINTEXT credential.
func (s *Server) Credentials() map[string]protocol.Credential {
	return map[string]protocol.Credential{PasswordID: s.PasswordCredential(PasswordID, s.Password)}
}

// PasswordCredential is a PLAINTEXT credential of the server's user, with
// password.
func (s *Server) PasswordCredential(id, password string) protocol.Credential {
	return protocol.Credential{ID: id, Name: "test password", Type: protocol.CredentialTypePlaintext, Username: s.User, Password: password}
}

// Fingerprint is the server's host key's, as ssh-keygen -l prints it.
func (s *Server) Fingerprint() string { return ssh.FingerprintSHA256(s.HostKey.PublicKey()) }

func (s *Server) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer func() { _ = conn.Close() }() // the client went
	go func() {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(r.Type == "keepalive@openssh.com", nil)
			}
		}
	}()
	for nch := range chans {
		if s.Stall.Load() {
			continue // unanswered: the connection keeps the open pending
		}
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "sessions only")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs)
	}
}

// session serves a session's requests: one exec or the sftp subsystem,
// and signals for the command running.
func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	var mu sync.Mutex
	var cmd *exec.Cmd
	stop := func() {}
	for r := range reqs {
		switch r.Type {
		case "exec":
			var p struct{ Command string }
			if ssh.Unmarshal(r.Payload, &p) != nil {
				_ = r.Reply(false, nil)
				continue
			}
			if s.exec != nil {
				ctx, cancel := context.WithCancel(s.execCtx)
				mu.Lock()
				stop = cancel
				mu.Unlock()
				_ = r.Reply(true, nil)
				go func() {
					defer cancel()
					code := s.exec(ctx, p.Command, ch, ch.Stderr())
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)})) //nolint:gosec // an exit code
					_ = ch.Close()
				}()
				continue
			}
			c := exec.Command("/bin/sh", "-c", p.Command)
			c.Dir = s.Dir
			c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			c.Stdout, c.Stderr = ch, ch.Stderr()
			if err := c.Start(); err != nil {
				_ = r.Reply(false, nil)
				continue
			}
			mu.Lock()
			cmd = c
			mu.Unlock()
			_ = r.Reply(true, nil)
			go func() {
				err := c.Wait()
				var exitErr *exec.ExitError
				switch ws, ok := c.ProcessState.Sys().(syscall.WaitStatus); {
				case ok && ws.Signaled():
					name := ws.Signal().String()
					if n, ok := signalNames[ws.Signal()]; ok {
						name = n
					}
					_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
						Signal     string
						CoreDumped bool
						Error      string
						Lang       string
					}{Signal: name}))
				case err == nil || errors.As(err, &exitErr):
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(c.ProcessState.ExitCode())})) //nolint:gosec // an exit code
				}
				_ = ch.Close()
			}()
		case "subsystem":
			var p struct{ Name string }
			if ssh.Unmarshal(r.Payload, &p) != nil || p.Name != "sftp" {
				_ = r.Reply(false, nil)
				continue
			}
			_ = r.Reply(true, nil)
			go func() {
				var srv sftpServer
				if s.sftpOf != nil {
					srv = s.sftpOf(ch)
				} else if plain, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(s.Dir)); err == nil {
					srv = plain
				}
				if srv != nil {
					if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
						_ = srv.Close()
					}
				}
				_ = ch.Close()
			}()
		case "signal":
			s.Signals.Add(1)
			mu.Lock()
			c, cancel := cmd, stop
			mu.Unlock()
			cancel()
			if c != nil && c.Process != nil {
				_ = c.Process.Kill()
			}
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		default:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
}

// signalNames are the SSH names of the signals a test sends (RFC 4254,
// without "SIG").
var signalNames = map[syscall.Signal]string{syscall.SIGKILL: "KILL", syscall.SIGTERM: "TERM", syscall.SIGINT: "INT", syscall.SIGHUP: "HUP"}

// Silent is a TCP listener that takes connections and says nothing: a
// server that never answers. It returns its port.
func Silent(t testing.TB) uint64 {
	t.Helper()
	return listen(t, func(net.Conn) {})
}

// Speaks is a TCP listener that answers every connection with said and
// closes it: something that is not an SSH server. It returns its port.
func Speaks(t testing.TB, said string) uint64 {
	t.Helper()
	return listen(t, func(c net.Conn) {
		_, _ = c.Write([]byte(said))
		_ = c.Close()
	})
}

func listen(t testing.TB, each func(net.Conn)) uint64 {
	t.Helper()
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
			go each(c)
		}
	}()
	return uint64(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a port
}
