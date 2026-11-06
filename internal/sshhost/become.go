package sshhost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/logoscore/logos-ssh/internal/minion"
	"golang.org/x/crypto/ssh"
)

// Becoming another user on a Unix server (docs: contracts/agentless-channels/,
// SSH: become). An SSH connection stays its login's: every channel sshd opens
// on it runs as the login. So a become keeps shells elevated on the
// connection: each one sudo or su started once (a root shell, say), which the
// minion writes shell commands into, one at a time each, as a person types
// into the shell sudo su gave them. One lives on a connection: shell
// commands take turns in it while the session is elevated, and a become
// made while one is in effect runs inside it (root's su asks nothing). It
// goes with the connection, or at unbecome.
//
// A command goes into its shell as one line: in a subshell in the
// background, in a process group of its own (setsid), stdin /dev/null,
// stderr into stdout, between markers random to the connection. The shell
// stays free while it runs, so a stop is another line to it: a kill as the
// user it became, which the login could not do.
//
// A become that goes on inside the shell leaves the shell it started from
// under the new one, waiting for su to return. Should the new shell end
// (killed, say) that one would read the next command, as its own user. So
// once su returns it reads one more line and exits unless that line is a
// code random to the become, which the minion writes only when su failed:
// after a fall the next line, or the end of the connection, ends it, and the
// minion drops the shell when it sees su return.

// maxShells is how many elevated shells a connection keeps: one, so a
// become from an elevated one goes on from it.
const maxShells = 1

// becomeWait bounds an elevation: the prompt, the password, the shell's
// first words.
const becomeWait = 15 * time.Second

// sudoPrompt is the prompt sudo is given (-p): its own default, so nothing on
// the server reads as the minion's; %p is the login. Before the shell starts,
// only sudo writes, so it is the minion's to find.
const (
	sudoPrompt     = "[sudo] password for %p: "
	sudoPromptSeen = "[sudo] password for "
	suPromptSeen   = "Password:"
)

// becomeErr is an elevation's failure: "become: <why>", ErrBecome.
type becomeErr struct{ why string }

func (e becomeErr) Error() string { return "become: " + e.why }
func (e becomeErr) Unwrap() error { return minion.ErrBecome }

func becomeFail(format string, a ...any) error { return becomeErr{fmt.Sprintf(format, a...)} }

// elevation is a connection's become: the one in effect and its shells.
type elevation struct {
	mu     sync.Mutex
	acting *minion.Become
	// gen tells this become's shells from an earlier one's, closed as they
	// are done with.
	gen   int
	idle  []*rootShell
	open  int // this gen's shells, idle and busy, and those being made
	freed chan struct{}
	// failure is why shells cannot be elevated again on the connection;
	// told once the operators were.
	failure string
	told    bool
	marker  string
}

type elevationKey struct{}

func (h *Host) elev() *elevation {
	return h.c.State(elevationKey{}, func() any {
		return &elevation{freed: make(chan struct{}, 1), marker: randomLetters(12)}
	}).(*elevation)
}

// Login is who the connection logged in as.
func (h *Host) Login() string { return h.c.User }

// Acting is the become in effect on the connection; nil for none.
func (h *Host) Acting() *minion.Become {
	e := h.elev()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.acting == nil {
		return nil
	}
	b := *e.acting
	return &b
}

// Adopt takes the become core says is in effect for the session (a call's
// or an open's acting task): kept when it is the one in effect, else taken
// (elevating when a shell command comes) or dropped (nil).
func (h *Host) Adopt(b *minion.Become) {
	e := h.elev()
	e.mu.Lock()
	defer e.mu.Unlock()
	if (b == nil && e.acting == nil) || (b != nil && e.acting != nil && e.acting.Same(*b)) {
		return
	}
	e.reset()
	if b != nil {
		c := *b
		e.acting = &c
	}
}

// reset drops the become in effect and its shells (e.mu held).
func (e *elevation) reset() {
	for _, s := range e.idle {
		s.close()
	}
	e.idle, e.open, e.acting, e.failure, e.told = nil, 0, nil, "", false
	e.gen++
}

// Become elevates a shell as b says, now: from then on shell commands run in
// shells elevated so. One that fails leaves the connection as it was.
func (h *Host) Become(ctx context.Context, b minion.Become) (minion.Became, error) {
	if h.windows() {
		return minion.Became{}, becomeFail("a Windows server has no sudo or su")
	}
	if h.Acting() != nil {
		return h.becomeFrom(ctx, b)
	}
	s, got, err := h.elevate(ctx, b)
	if err != nil {
		return minion.Became{}, err
	}
	e := h.elev()
	e.mu.Lock()
	e.reset()
	c := b
	e.acting = &c
	s.gen = e.gen
	e.idle, e.open = []*rootShell{s}, 1
	e.mu.Unlock()
	return got, nil
}

// becomeFrom becomes b from the shell elevated now (root, say): inside it,
// so su from root asks nothing. One that fails leaves the shell as it was.
// A connection that comes later elevates as b alone (core gives the last
// become): one only another made possible fails there, and says so.
func (h *Host) becomeFrom(ctx context.Context, b minion.Become) (minion.Became, error) {
	e := h.elev()
	s, err := e.acquire(ctx, h)
	if err != nil {
		return minion.Became{}, err
	}
	password := b.Password
	if b.Method != minion.BecomeSu && password == "" {
		password = h.c.Password
	}
	got, err := s.nest(ctx, e.marker, b, password)
	e.mu.Lock()
	if err == nil && s.gen == e.gen {
		c := b
		e.acting, e.failure, e.told = &c, "", false
	}
	e.mu.Unlock()
	e.release(s)
	return got, err
}

// Unbecome: shell commands run as the login again.
func (h *Host) Unbecome() {
	e := h.elev()
	e.mu.Lock()
	e.reset()
	e.mu.Unlock()
}

// BecomeFailure is why shell commands cannot run as the acting user on the
// connection, and whether it is the first time asked.
func (h *Host) BecomeFailure() (string, bool) {
	e := h.elev()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failure == "" {
		return "", false
	}
	first := !e.told
	e.told = true
	return e.failure, first
}

// shellAs runs a command in the connection's shell elevated as the become
// in effect; started once it holds it (or cannot).
func (h *Host) shellAs(ctx context.Context, command string, out io.Writer, started func()) (minion.Exit, error) {
	if h.windows() {
		started()
		return minion.Exit{}, becomeFail("a Windows server has no sudo or su")
	}
	e := h.elev()
	for try := 0; ; try++ {
		s, err := e.acquire(ctx, h)
		if try == 0 {
			started()
		}
		if err != nil {
			return minion.Exit{}, err
		}
		exit, err := s.run(ctx, e.marker, command, out)
		as := s.as
		e.release(s)
		if errors.Is(err, errFell) && try == 0 {
			// It fell before the command went in: another shell, elevated
			// again, takes it.
			continue
		}
		if !errors.Is(err, minion.ErrNotStarted) {
			exit.As = &as
		}
		return exit, err
	}
}

// acquire is an idle shell of the become in effect, or a new one elevated,
// waiting while maxShells are busy.
func (e *elevation) acquire(ctx context.Context, h *Host) (*rootShell, error) {
	for {
		e.mu.Lock()
		if e.acting == nil {
			e.mu.Unlock()
			return nil, becomeFail("the session no longer runs as another user")
		}
		for len(e.idle) > 0 {
			s := e.idle[len(e.idle)-1]
			e.idle = e.idle[:len(e.idle)-1]
			if !s.dead() {
				e.mu.Unlock()
				return s, nil
			}
			s.close()
			e.open--
		}
		if e.open < maxShells {
			e.open++
			b, gen := *e.acting, e.gen
			e.mu.Unlock()
			s, _, err := h.elevate(ctx, b)
			e.mu.Lock()
			defer e.mu.Unlock()
			if gen != e.gen {
				if s != nil {
					s.close()
				}
				return nil, becomeFail("the session's become changed")
			}
			if err != nil {
				e.open--
				var be becomeErr
				why := err.Error()
				if errors.As(err, &be) {
					why = be.why
				}
				if why != e.failure {
					e.failure, e.told = why, false
				}
				return nil, err
			}
			e.failure, e.told = "", false
			s.gen = gen
			return s, nil
		}
		e.mu.Unlock()
		select {
		case <-e.freed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// release gives a shell back: idle for the next command, or closed when it
// ended or the become changed.
func (e *elevation) release(s *rootShell) {
	e.mu.Lock()
	switch {
	case s.gen != e.gen:
		s.close()
	case s.dead():
		s.close()
		e.open--
	default:
		e.idle = append(e.idle, s)
	}
	e.mu.Unlock()
	select {
	case e.freed <- struct{}{}:
	default:
	}
}

// becomeLine is the command that elevates a shell as b: sudo's, sudo su's,
// or su's (in a terminal script(1) makes: su reads passwords only from one,
// and script's leaves no login record). Each says who it became (id) before
// it becomes a POSIX shell reading commands.
func becomeLine(b minion.Become, pty bool) string {
	start := "id -u; id -un; exec /bin/sh"
	var line string
	switch b.Method {
	case minion.BecomeSudoSu:
		line = "sudo -S -p " + shellQuote(sudoPrompt) + " su -s /bin/sh " + shellQuote(b.User) + " -c " + shellQuote(start)
	case minion.BecomeSu:
		line = "LC_ALL=C su " + shellQuote(b.User) + " -c " + shellQuote(start)
	default:
		line = "sudo -S -p " + shellQuote(sudoPrompt) + " -u " + shellQuote(b.User) + " -- /bin/sh -c " + shellQuote(start)
	}
	if pty {
		return "exec script -qc " + shellQuote(line) + " /dev/null"
	}
	return "exec " + line
}

// elevate starts a shell elevated as b: its password given when (and only
// when) the server asks for it, never twice.
func (h *Host) elevate(ctx context.Context, b minion.Become) (*rootShell, minion.Became, error) {
	password := b.Password
	if b.Method != minion.BecomeSu && password == "" {
		password = h.c.Password
	}
	if b.Method == minion.BecomeSu && password == "" && h.c.User != "root" {
		return nil, minion.Became{}, becomeFail("su asks for %s's password: give become one", b.User)
	}
	pty := b.Method == minion.BecomeSu
	s, got, err := h.elevateWith(ctx, b, password, pty)
	if err != nil && !pty && strings.Contains(err.Error(), "tty") {
		// sudoers' requiretty: the same through a terminal of script's.
		s, got, err = h.elevateWith(ctx, b, password, true)
	}
	return s, got, err
}

func (h *Host) elevateWith(ctx context.Context, b minion.Become, password string, pty bool) (*rootShell, minion.Became, error) {
	ctx, cancel := context.WithTimeout(ctx, becomeWait)
	defer cancel()
	s, err := startShell(h, becomeLine(b, pty), pty)
	if err != nil {
		return nil, minion.Became{}, becomeFail("%s", err)
	}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	written := 0
	for {
		outText, errText := s.out.text(), s.errs.text()
		prompts := strings.Count(errText, sudoPromptSeen) + strings.Count(outText, sudoPromptSeen)
		if pty {
			prompts += strings.Count(outText, suPromptSeen)
		}
		if prompts > written {
			switch {
			case written > 0:
				return nil, minion.Became{}, becomeFail("%s refused the password (%s)", b.MethodLabel(), passwordOf(b))
			case password == "":
				return nil, minion.Became{}, becomeFail("%s asks for a password, and there is none: the target logged in with a key; give become a password",
					b.MethodLabel())
			}
			if _, err := io.WriteString(s.in, password+"\n"); err != nil {
				return nil, minion.Became{}, becomeFail("%s", err)
			}
			written++
		}
		if uid, user, n, found := idLines(outText); found {
			s.out.drop(n)
			if err := s.setup(ctx, h.elev().marker); err != nil {
				return nil, minion.Became{}, becomeFail("the shell %s started does not answer: %s", b.MethodLabel(), err)
			}
			ok = true
			s.as = minion.Ran{Task: b.Task, User: user, UID: uid}
			return s, minion.Became{User: user, UID: uid, PasswordUsed: written > 0, Notes: notesOf(errText)}, nil
		}
		select {
		case <-s.out.note:
		case <-s.errs.note:
		case <-s.ended:
			return nil, minion.Became{}, becomeFail("%s", failureOf(b, s, pty))
		case <-ctx.Done():
			return nil, minion.Became{}, becomeFail("%s did not answer within %s", b.MethodLabel(), becomeWait)
		}
	}
}

// passwordOf says whose password a refused one was.
func passwordOf(b minion.Become) string {
	if b.Credential != "" {
		return "the become's credential"
	}
	return "the login's"
}

// idLines finds the elevated shell's first words: id -u's and id -un's
// lines, after any prompt; how many bytes they took.
func idLines(out string) (int64, string, int, bool) {
	start := 0
	for _, p := range []string{sudoPromptSeen, suPromptSeen} {
		if i := strings.LastIndex(out, p); i >= 0 {
			if j := strings.IndexByte(out[i:], '\n'); j >= 0 {
				start = max(start, i+j+1)
			} else {
				return 0, "", 0, false
			}
		}
	}
	rest := out[start:]
	var lines []string
	used := start
	for len(lines) < 2 {
		i := strings.IndexByte(rest, '\n')
		if i < 0 {
			return 0, "", 0, false
		}
		line := strings.TrimSpace(strings.TrimRight(rest[:i], "\r"))
		used += i + 1
		rest = rest[i+1:]
		if line != "" {
			lines = append(lines, line)
		}
	}
	uid, err := strconv.ParseInt(lines[0], 10, 64)
	if err != nil {
		return 0, "", 0, false
	}
	return uid, lines[1], used, true
}

// notesOf is what sudo said on the way that is not its prompt.
func notesOf(errText string) string {
	var keep []string
	for _, l := range strings.Split(errText, "\n") {
		if i := strings.Index(l, sudoPromptSeen); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" && l != "Sorry, try again." {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// failureOf says why a shell ended before it became anyone.
func failureOf(b minion.Become, s *rootShell, pty bool) string {
	code := s.exitCode()
	said := notesOf(s.errs.text() + "\n" + strings.ReplaceAll(s.out.text(), suPromptSeen, ""))
	switch {
	case code == 127 && pty && strings.Contains(said, "script"):
		return "su needs a terminal, and the server has no script(1)"
	case code == 127:
		return fmt.Sprintf("%s is not installed", strings.Fields(b.MethodLabel())[0])
	case said != "":
		return lastLines(said, 3)
	}
	return fmt.Sprintf("%s ended (exit %d) without starting a shell", b.MethodLabel(), code)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "; ")
}

// rootShell is a shell elevated on the connection, read from its stdout
// (and, without a terminal, its stderr: sudo's before it started).
type rootShell struct {
	s     *ssh.Session
	in    io.WriteCloser
	out   *pipe
	errs  *pipe
	ended chan struct{}
	code  int
	gen   int
	once  sync.Once
	// as is who the shell runs as: the become that made it, and the user.
	as minion.Ran
	// fell is what the shell under this one says once the one a become went
	// on into ended ("\n" marker "X"); nil until a become went on in it.
	fell []byte
}

func startShell(h *Host, line string, pty bool) (*rootShell, error) {
	sess, err := h.c.Session()
	if err != nil {
		return nil, err
	}
	in, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	if err := sess.Start(line); err != nil {
		_ = sess.Close()
		return nil, err
	}
	s := &rootShell{s: sess, in: in, out: newPipe(stdout), errs: newPipe(stderr), ended: make(chan struct{}), code: -1}
	go func() {
		err := sess.Wait()
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			s.code = exitErr.ExitStatus()
		} else if err == nil {
			s.code = 0
		}
		<-s.out.done
		close(s.ended)
	}()
	return s, nil
}

func (s *rootShell) exitCode() int { return s.code }

func (s *rootShell) dead() bool {
	select {
	case <-s.ended:
		return true
	default:
		return s.fallen()
	}
}

// fallen reports whether the shell a become went on into ended: what reads
// the connection's lines now is the shell under it, which takes none.
func (s *rootShell) fallen() bool {
	return s.fell != nil && bytes.Contains(s.out.bytes(), s.fell)
}

// errFell: the shell fell before a command went in. NotStarted wraps it, and
// another shell takes the command.
var errFell = errors.New("the elevated shell ended")

func (s *rootShell) close() {
	s.once.Do(func() {
		_ = s.in.Close()
		_ = s.s.Close()
	})
}

// setup readies the shell for commands: no echo, no line discipline (a
// terminal's), no history, its own errors dropped (commands send theirs
// into stdout), setsid's path. Its answer is the marker R.
func (s *rootShell) setup(ctx context.Context, m string) error {
	a, b := m[:len(m)/2], m[len(m)/2:]
	line := "stty raw -echo 2>/dev/null; exec 2>/dev/null; unset HISTFILE; S=$(command -v setsid 2>/dev/null); printf '%s%sR\\n' " +
		a + " " + b + "\n"
	if _, err := io.WriteString(s.in, line); err != nil {
		return err
	}
	want := m + "R"
	for {
		if i := strings.Index(s.out.text(), want); i >= 0 {
			rest := s.out.text()[i+len(want):]
			n := i + len(want)
			if strings.HasPrefix(rest, "\r\n") {
				n += 2
			} else if strings.HasPrefix(rest, "\n") {
				n++
			}
			s.out.drop(n)
			return nil
		}
		select {
		case <-s.out.note:
		case <-s.ended:
			return errors.New("it ended")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// run runs a command in the shell: its output to out until its end marker,
// its exit code. Stopped (ctx), the command's process group is killed from
// the shell, as the user it became.
func (s *rootShell) run(ctx context.Context, m, command string, out io.Writer) (minion.Exit, error) {
	if s.fallen() {
		s.close()
		return minion.Exit{}, minion.NotStarted(errFell)
	}
	s.out.drop(len(s.out.text())) // what a command left behind is not this one's
	a, b := m[:len(m)/2], m[len(m)/2:]
	line := "( $S /bin/sh -c " + shellQuote(command) + " </dev/null 2>&1 & c=$!; printf '%s%sP%s\\n' " + a + " " + b +
		` "$c"; wait $c; s=$?; printf '\n%s%sE%s\n' ` + a + " " + b + ` "$s" ) &` + "\n"
	if _, err := io.WriteString(s.in, line); err != nil {
		return minion.Exit{}, minion.NotStarted(err)
	}
	pidMark, endMark := m+"P", "\n"+m+"E"
	pid := 0
	killed := false
	var killAt <-chan time.Time
	for {
		buf := s.out.bytes()
		// The shell the command went into ended (fell): what came before is
		// the command's, the rest not. A fall's mark is as long as endMark,
		// so held back as it is.
		fell := -1
		if s.fell != nil {
			if fell = bytes.Index(buf, s.fell); fell >= 0 {
				buf = buf[:fell]
			}
		}
		if pid == 0 {
			if i := bytes.Index(buf, []byte(pidMark)); i >= 0 {
				if j := bytes.IndexByte(buf[i:], '\n'); j >= 0 {
					pid, _ = strconv.Atoi(strings.TrimSpace(string(buf[i+len(pidMark) : i+j])))
					s.out.drop(i + j + 1)
					continue
				}
			}
		} else {
			if i := bytes.Index(buf, []byte(endMark)); i >= 0 {
				if j := bytes.IndexByte(buf[i+1:], '\n'); j >= 0 {
					if _, err := out.Write(buf[:i]); err != nil {
						return minion.Exit{}, err
					}
					code, _ := strconv.ParseInt(strings.TrimSpace(string(buf[i+len(endMark):i+1+j])), 10, 64)
					s.out.drop(i + 1 + j + 1)
					if killed {
						return minion.Exit{}, ctx.Err()
					}
					return minion.Exit{Code: &code}, nil
				}
			} else if fell >= 0 {
				_, _ = out.Write(buf)
			} else if n := len(buf) - len(endMark); n > 0 {
				if _, err := out.Write(buf[:n]); err != nil {
					return minion.Exit{}, err
				}
				s.out.drop(n)
			}
		}
		if fell >= 0 {
			// The shell under it takes no line, and exits at the next: never
			// a command as its user.
			s.close()
			return minion.Exit{}, errors.New("the elevated shell ended")
		}
		select {
		case <-s.out.note:
		case <-s.ended:
			if killed {
				return minion.Exit{}, ctx.Err()
			}
			return minion.Exit{}, errors.New("the elevated shell ended")
		case <-killAt:
			// The kill did not end it: the shell goes too.
			s.close()
			return minion.Exit{}, ctx.Err()
		case <-func() <-chan struct{} {
			if killed {
				return nil
			}
			return ctx.Done()
		}():
			killed = true
			killAt = time.After(5 * time.Second)
			if pid > 1 {
				p := strconv.Itoa(pid)
				_, _ = io.WriteString(s.in, "kill -s KILL -- -"+p+" 2>/dev/null || { pkill -KILL -P "+p+" 2>/dev/null; kill -s KILL "+p+" 2>/dev/null; }\n")
			} else {
				s.close()
				return minion.Exit{}, ctx.Err()
			}
		}
	}
}

// pipe keeps what a stream sends until it is taken.
type pipe struct {
	mu   sync.Mutex
	buf  []byte
	note chan struct{}
	done chan struct{}
}

func newPipe(r io.Reader) *pipe {
	p := &pipe{note: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		b := make([]byte, 32<<10)
		for {
			n, err := r.Read(b)
			if n > 0 {
				p.mu.Lock()
				p.buf = append(p.buf, b[:n]...)
				p.mu.Unlock()
				select {
				case p.note <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return p
}

func (p *pipe) bytes() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.buf...)
}

func (p *pipe) text() string { return string(p.bytes()) }

func (p *pipe) drop(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = p.buf[min(n, len(p.buf)):]
}

// randomLetters are n random lowercase letters: a marker nothing else
// writes.
func randomLetters(n int) string {
	h := randomHex(n)
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + h[i]%26
	}
	return string(b)
}

// nest becomes b inside the shell: sudo or su started from it, its stderr
// into stdout (the shell drops its own), the password given when asked,
// once. Its end (a failure) says the marker X, and the shell waits for the
// become's code to go on; its id lines say it is in, and the shell under it
// then exits at the next line.
func (s *rootShell) nest(ctx context.Context, m string, b minion.Become, password string) (minion.Became, error) {
	ctx, cancel := context.WithTimeout(ctx, becomeWait)
	defer cancel()
	inner := strings.TrimPrefix(becomeLine(b, false), "exec ")
	a, z := m[:len(m)/2], m[len(m)/2:]
	code := randomLetters(16)
	s.out.drop(len(s.out.text()))
	line := inner + " 2>&1; printf '\\n%s%sX%s\\n' " + a + " " + z + ` "$?"; read -r k; [ "$k" = ` + code + " ] || exit 1\n"
	if _, err := io.WriteString(s.in, line); err != nil {
		return minion.Became{}, becomeFail("%s", err)
	}
	failMark := m + "X"
	written, refused := 0, false
	for {
		text := s.out.text()
		if i := strings.Index(text, failMark); i >= 0 {
			said := notesOf(strings.ReplaceAll(text[:i], suPromptSeen, ""))
			s.out.drop(len(text))
			// su returned: the shell goes on as it was.
			if _, err := io.WriteString(s.in, code+"\n"); err != nil {
				s.close()
				return minion.Became{}, becomeFail("%s", err)
			}
			switch {
			case refused:
				return minion.Became{}, becomeFail("%s refused the password (%s)", b.MethodLabel(), passwordOf(b))
			case written == 0 && password == "" && strings.Contains(text[:i], suPromptSeen):
				return minion.Became{}, becomeFail("%s asks for %s's password: give become one", b.MethodLabel(), b.User)
			case said != "":
				return minion.Became{}, becomeFail("%s", lastLines(said, 3))
			}
			return minion.Became{}, becomeFail("%s ended without starting a shell", b.MethodLabel())
		}
		prompts := strings.Count(text, sudoPromptSeen) + strings.Count(text, suPromptSeen)
		if prompts > written {
			// The password when asked, once; asked again (or with none to
			// give), an empty line, so sudo or su gives up.
			give := password
			if written > 0 || password == "" {
				give, refused = "", written > 0
			}
			if _, err := io.WriteString(s.in, give+"\n"); err != nil {
				return minion.Became{}, becomeFail("%s", err)
			}
			written++
		}
		if uid, user, n, found := idLines(text); found {
			s.out.drop(n)
			if err := s.setup(ctx, m); err != nil {
				s.close()
				return minion.Became{}, becomeFail("the shell %s started does not answer: %s", b.MethodLabel(), err)
			}
			s.as = minion.Ran{Task: b.Task, User: user, UID: uid}
			s.fell = []byte("\n" + m + "X")
			return minion.Became{User: user, UID: uid, PasswordUsed: written > 0 && password != "" && !refused, Notes: ""}, nil
		}
		select {
		case <-s.out.note:
		case <-s.ended:
			return minion.Became{}, becomeFail("the elevated shell ended")
		case <-ctx.Done():
			// Neither in nor out: the shell cannot be trusted with the next
			// command.
			s.close()
			return minion.Became{}, becomeFail("%s did not answer within %s", b.MethodLabel(), becomeWait)
		}
	}
}
