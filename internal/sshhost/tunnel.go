package sshhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"golang.org/x/crypto/ssh"

	"github.com/logoscore/logos-ssh/internal/minion"
)

// The Host as a minion.Tunneler: tunnels' streams over the session's SSH
// connection (docs: contracts/minion-messages/tunnels.md, the SSH channel).
// A forward is a direct-tcpip channel (direct-streamlocal for a unix
// socket), a remote forward a tcpip-forward, a process a session of its
// own: in a pty when the open gives a size and the server gives one, else
// on pipes. Every stream is the login's, whatever the session became: a
// become elevates shell tasks only.

var _ minion.Tunneler = (*Host)(nil)

// Dial connects from the server: a refusal as the result the server's words
// say (an *minion.OpenError).
func (h *Host) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := h.c.Dial(ctx, network, address)
	if err != nil {
		return nil, openError(err)
	}
	return conn, nil
}

// Listen has the server listen (a remote forward); one it refuses is
// denied (its AllowTcpForwarding, its GatewayPorts, or the port taken: the
// server says no more than no).
func (h *Host) Listen(network, address string) (net.Listener, error) {
	ln, err := h.c.Listen(network, address)
	if err != nil {
		if strings.Contains(err.Error(), "denied") {
			return nil, &minion.OpenError{Result: protocol.TunnelDenied, Msg: "the server refused to listen at " + address +
				" (its AllowTcpForwarding, or the port taken)"}
		}
		return nil, err
	}
	return ln, nil
}

// openError is the result a refused channel open says, by its reason and
// the server's words (OpenSSH says strerror's for a connect that failed,
// getaddrinfo's for a name it did not find).
func openError(err error) error {
	var oe *ssh.OpenChannelError
	if !errors.As(err, &oe) {
		return err
	}
	msg := "the server: " + oe.Error()
	result := protocol.TunnelFailed
	switch oe.Reason {
	case ssh.Prohibited:
		result = protocol.TunnelDenied
		msg = "the server does not forward there (its AllowTcpForwarding or PermitOpen): " + oe.Message
	case ssh.UnknownChannelType:
		result = protocol.TunnelUnsupported
		msg = "the server does not forward this kind (" + oe.Message + ")"
	case ssh.ConnectionFailed:
		result = byWords(oe.Message)
	}
	return &minion.OpenError{Result: result, Msg: msg}
}

// byWords is a failed connect's result by the server's words.
func byWords(msg string) int {
	m := strings.ToLower(msg)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(m, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("refused"):
		return protocol.TunnelRefused
	case has("network is unreachable", "network is down"):
		return protocol.TunnelNetUnreachable
	case has("no route to host", "host is down", "host is unreachable", "not known", "nodename nor servname",
		"name resolution", "does not resolve", "no address associated", "name has no usable address", "no such host"):
		return protocol.TunnelHostUnreachable
	case has("timed out"):
		return protocol.TunnelTimedOut
	case has("no such file or directory"):
		return protocol.TunnelNotFound
	case has("permission denied", "not permitted"):
		return protocol.TunnelDenied
	}
	return protocol.TunnelFailed
}

// Process runs program (none: the login's shell) with args in a session
// of its own: in a pty of rows by cols when they say one (else, or when the
// server gives none, on pipes, stderr with stdout). A Unix server's session
// says its process id first (kept back from the output), for the signals:
// interrupt, terminate and kill go to its whole session; a terminal's
// interrupt is a Ctrl-C written into it, as a key pressed. A Windows
// server's ends by SSH's KILL signal (Windows's OpenSSH ends the process
// tree on it), and has no interrupt but a terminal's Ctrl-C.
func (h *Host) Process(ctx context.Context, program string, args []string, rows, cols int) (*minion.Proc, bool, error) {
	win := h.windows()
	s, err := h.c.Session()
	if err != nil {
		return nil, false, err
	}
	fail := func(err error) (*minion.Proc, bool, error) {
		_ = s.Close()
		return nil, false, err
	}
	terminal := false
	if rows > 0 && cols > 0 {
		modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
		terminal = s.RequestPty("xterm-256color", rows, cols, modes) == nil
	}
	in, err := s.StdinPipe()
	if err != nil {
		return fail(err)
	}
	pr, pw := io.Pipe()
	w := &shellOut{w: pw, seen: win, mark: h.pidMark()}
	s.Stdout, s.Stderr = w, stderrOf{w}
	line := processLine(win, w.mark, program, args)
	started := make(chan error, 1)
	go func() {
		if line == "" {
			started <- s.Shell()
		} else {
			started <- s.Start(line)
		}
	}()
	select {
	case err = <-started:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		return fail(fmt.Errorf("the server did not start the process: %w", err))
	}
	var once sync.Once
	end := func(sig string) {
		if !win {
			h.signalSession(w.pid(), sig)
		}
		if sig == "KILL" {
			_ = s.Signal(ssh.SIGKILL)
			once.Do(func() { _ = s.Close() })
		}
	}
	// A new size goes from a goroutine of its own (window-change is a message
	// over the connection; the engine asks under its lock), the latest size
	// replacing one not sent yet.
	sizes, exited := make(chan [2]int, 1), make(chan struct{})
	if terminal {
		go func() {
			for {
				select {
				case sz := <-sizes:
					_ = s.WindowChange(sz[0], sz[1])
				case <-exited:
					return
				}
			}
		}()
	}
	ways := minion.ProcWays{
		Resize: func(rows, cols int) error {
			if !terminal {
				return nil
			}
			select {
			case <-sizes:
			default:
			}
			select {
			case sizes <- [2]int{rows, cols}:
			default:
			}
			return nil
		},
		Signal: func(sig int) error {
			switch sig {
			case protocol.TunnelSignalInterrupt:
				if terminal {
					_, err := in.Write([]byte{0x03})
					return err
				}
				if win {
					return errors.New("a Windows process on pipes takes no interrupt")
				}
				h.signalSession(w.pid(), "INT")
			case protocol.TunnelSignalTerminate:
				if win {
					end("KILL")
					return nil
				}
				h.signalSession(w.pid(), "TERM")
			case protocol.TunnelSignalKill:
				end("KILL")
			}
			return nil
		},
		Kill: func() { end("KILL") },
	}
	if !terminal {
		ways.CloseInput = in.Close
	}
	wait := func() int64 {
		err := s.Wait()
		_ = pw.Close()
		close(exited)
		once.Do(func() { _ = s.Close() })
		return exitCode(err)
	}
	return minion.NewProc(pr, in, ways, wait), terminal, nil
}

// processLine is the session's command: on a Unix server, its process id
// said, then program exec'd (none: the login's shell, as a login shell); on
// a Windows one the line as cmd.exe takes it ("": the default shell).
func processLine(win bool, mark, program string, args []string) string {
	if win {
		if program == "" {
			return ""
		}
		parts := []string{winQuote(program)}
		for _, a := range args {
			parts = append(parts, winQuote(a))
		}
		return strings.Join(parts, " ")
	}
	run := `exec "${SHELL:-/bin/sh}" -l`
	if program != "" {
		parts := []string{"exec", shellQuote(program)}
		for _, a := range args {
			parts = append(parts, shellQuote(a))
		}
		run = strings.Join(parts, " ")
	}
	return "echo " + mark + "$$; " + run
}

// winQuote quotes an argument as Windows programs read their command line
// (CommandLineToArgvW), as syscall.EscapeArg does.
func winQuote(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, c := range []byte(s) {
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
			slashes = 0
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			slashes = 0
		}
		if c != '\\' {
			b.WriteByte(c)
		}
	}
	b.WriteString(strings.Repeat(`\`, slashes*2))
	b.WriteByte('"')
	return b.String()
}

// signalSession signals the session pid leads (sshd made one for it, a
// terminal's or not) through a session of its own: every process in it, as
// a terminal's hangup would; else its process group, else pid alone.
func (h *Host) signalSession(pid int, sig string) {
	if pid <= 1 {
		return
	}
	s, err := h.c.Session()
	if err != nil {
		return
	}
	defer func() { _ = s.Close() }() // best effort
	done := make(chan struct{})
	go func() {
		_ = s.Run(fmt.Sprintf("/bin/sh -c 'pkill -%[1]s -s %[2]d 2>/dev/null || kill -s %[1]s -- -%[2]d 2>/dev/null || kill -s %[1]s %[2]d'",
			sig, pid))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// exitCode is a session's end as an exit code: its status, or 128 and the
// signal's number when one ended it; -1 when the server said neither (the
// connection went).
func exitCode(err error) int64 {
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee) && ee.Signal() != "":
		if n, ok := signalNumbers[ee.Signal()]; ok {
			return 128 + n
		}
		return 128
	case errors.As(err, &ee):
		return int64(ee.ExitStatus())
	}
	return -1
}

// signalNumbers are the signals SSH names (RFC 4254 6.10), by their
// numbers on Linux.
var signalNumbers = map[string]int64{"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "ABRT": 6, "FPE": 8, "KILL": 9, "USR1": 10, "SEGV": 11,
	"USR2": 12, "PIPE": 13, "ALRM": 14, "TERM": 15}
