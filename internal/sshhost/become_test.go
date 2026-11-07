package sshhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

var _ minion.Becomer = (*Host)(nil)

// becomeHost is a host whose PATH has the fakes, logged in with password.
func becomeHost(t *testing.T, password string) (*Host, string) {
	t.Helper()
	sshtest.FakeBecome(t, "sudo-pw", "root-pw")
	dir := t.TempDir()
	h := hostIn(t, dir)
	h.c.Password = password
	return h, dir
}

func me(t *testing.T) string {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

func shell(t *testing.T, h *Host, command string) (string, *int64, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	exit, err := h.Shell(ctx, command, &out)
	return out.String(), exit.Code, err
}

// sudo with the login's password: asked once, given once; shell commands
// then run in the elevated shell, output and exit code as without.
func TestBecomeSudo(t *testing.T) {
	h, _ := becomeHost(t, "sudo-pw")
	got, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo})
	if err != nil {
		t.Fatal(err)
	}
	if got.User != me(t) || !got.PasswordUsed || got.UID != int64(os.Getuid()) {
		t.Fatalf("became %+v", got)
	}
	if h.Acting() == nil {
		t.Fatal("no become in effect")
	}
	out, code, err := shell(t, h, "echo out; echo err >&2; printf tail; exit 4")
	if err != nil || code == nil || *code != 4 || out != "out\nerr\ntail" {
		t.Fatalf("out %q code %v err %v", out, code, err)
	}
	if strings.Contains(out, h.elev().marker) {
		t.Fatal("a marker in the output")
	}
	// Overlapping commands: a shell each, up to maxShells.
	var wg sync.WaitGroup
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, code, err := shell(t, h, "sleep 0.3; echo "+strconv.Itoa(i))
			if err != nil || code == nil || *code != 0 || out != strconv.Itoa(i)+"\n" {
				t.Errorf("%d: out %q code %v err %v", i, out, code, err)
			}
		}()
	}
	wg.Wait()
	// A command reading stdin reads nothing: the shell's next lines stay
	// the shell's.
	if out, _, err := shell(t, h, "cat; echo done"); err != nil || out != "done\n" {
		t.Fatalf("stdin: %q %v", out, err)
	}
	h.Unbecome()
	if h.Acting() != nil {
		t.Fatal("still acting")
	}
	if out, _, err := shell(t, h, "echo plain"); err != nil || out != "plain\n" {
		t.Fatalf("after unbecome: %q %v", out, err)
	}
}

// NOPASSWD: nothing written, so the password never reaches the shell.
func TestBecomeNoPassword(t *testing.T) {
	h, _ := becomeHost(t, "sudo-pw")
	t.Setenv("FAKE_NOPASSWD", "1")
	got, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo})
	if err != nil || got.PasswordUsed {
		t.Fatalf("%+v %v", got, err)
	}
	if out, _, err := shell(t, h, "echo ok"); err != nil || out != "ok\n" {
		t.Fatalf("%q %v", out, err)
	}
}

// A refused password: once, never again; nothing changes. None to give
// when sudo asks: said so.
func TestBecomeRefused(t *testing.T) {
	h, _ := becomeHost(t, "wrong")
	_, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo})
	if !errors.Is(err, minion.ErrBecome) || !strings.Contains(err.Error(), "refused the password (the login's)") {
		t.Fatalf("%v", err)
	}
	if h.Acting() != nil {
		t.Fatal("acting after a refusal")
	}
	h.c.Password = ""
	_, err = h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudoSu})
	if err == nil || !strings.Contains(err.Error(), "asks for a password, and there is none") {
		t.Fatalf("%v", err)
	}
	// sudo su with the become's own password.
	got, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudoSu,
		Password: "sudo-pw", Credential: "c1"})
	if err != nil || !got.PasswordUsed {
		t.Fatalf("%+v %v", got, err)
	}
}

// su: the user's password at its prompt, in script's terminal.
func TestBecomeSu(t *testing.T) {
	h, _ := becomeHost(t, "")
	_, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSu})
	if err == nil || !strings.Contains(err.Error(), "su asks for root's password") {
		t.Fatalf("%v", err)
	}
	_, err = h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSu, Password: "nope"})
	if err == nil || !strings.Contains(err.Error(), "Authentication failure") {
		t.Fatalf("%v", err)
	}
	got, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSu, Password: "root-pw"})
	if err != nil || !got.PasswordUsed {
		t.Fatalf("%+v %v", got, err)
	}
	if out, code, err := shell(t, h, "echo su-ok; exit 2"); err != nil || out != "su-ok\n" || code == nil || *code != 2 {
		t.Fatalf("%q %v %v", out, code, err)
	}
}

// A stop kills what the command started, from the elevated shell; the
// shell takes the next command.
func TestBecomeStop(t *testing.T) {
	h, dir := becomeHost(t, "sudo-pw")
	if _, err := h.Become(context.Background(), minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo}); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "child")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := h.Shell(ctx, "sleep 30 & echo $! > "+pidFile+"; wait", &bytes.Buffer{})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("the command's child %d lives on", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if out, _, err := shell(t, h, "echo next"); err != nil || out != "next\n" {
		t.Fatalf("%q %v", out, err)
	}
}

// Core's become taken up on a connection that cannot elevate: shell
// commands fail, never as the login; the operators are told once.
func TestAdoptFails(t *testing.T) {
	h, _ := becomeHost(t, "wrong")
	b := minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo}
	h.Adopt(&b)
	_, _, err := shell(t, h, "echo never")
	if !errors.Is(err, minion.ErrBecome) {
		t.Fatalf("%v", err)
	}
	if why, first := h.BecomeFailure(); why == "" || !first {
		t.Fatalf("%q %v", why, first)
	}
	if _, first := h.BecomeFailure(); first {
		t.Fatal("told twice")
	}
	// The same become again keeps it; another one (the password fixed)
	// elevates.
	h.Adopt(&b)
	if h.Acting() == nil {
		t.Fatal("dropped")
	}
	good := b
	good.Password = "sudo-pw"
	h.Adopt(&good)
	if out, _, err := shell(t, h, "echo now"); err != nil || out != "now\n" {
		t.Fatalf("%q %v", out, err)
	}
	h.Adopt(nil)
	if h.Acting() != nil {
		t.Fatal("still acting")
	}
}

// A become while the one core gave does not elevate on the connection (the
// login's password no longer taken) goes from the login, as with none in
// effect, so becoming again gets the session past it. One that fails from
// the login too leaves the session as it was.
func TestBecomeAfterAdoptFails(t *testing.T) {
	h, _ := becomeHost(t, "wrong")
	ctx := context.Background()
	old := minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo}
	h.Adopt(&old)
	if _, _, err := shell(t, h, "echo never"); !errors.Is(err, minion.ErrBecome) {
		t.Fatalf("%v", err)
	}
	again := minion.Become{Task: []byte("0123456789abcdef"), User: "root", Method: minion.BecomeSudo, Password: "sudo-pw", Credential: "c1"}
	got, err := h.Become(ctx, again)
	if err != nil || !got.PasswordUsed {
		t.Fatalf("%+v %v", got, err)
	}
	if a := h.Acting(); a == nil || !a.Same(again) {
		t.Fatalf("acting %+v", a)
	}
	if why, _ := h.BecomeFailure(); why != "" {
		t.Fatalf("still failing: %q", why)
	}
	if out, _, err := shell(t, h, "echo now"); err != nil || out != "now\n" {
		t.Fatalf("%q %v", out, err)
	}

	h.Adopt(&old)
	refused := again
	refused.Password = "nope"
	if _, err := h.Become(ctx, refused); err == nil || !strings.Contains(err.Error(), "refused the password (the become's credential)") {
		t.Fatalf("%v", err)
	}
	if a := h.Acting(); a == nil || !a.Same(old) {
		t.Fatalf("acting %+v", a)
	}
}

// A become while the one core gave elevates on the connection goes on
// inside it, as from a shell elevated earlier: su from root asks nothing.
func TestBecomeFromAdopted(t *testing.T) {
	h, _ := becomeHost(t, "sudo-pw")
	h.Adopt(&minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo})
	got, err := h.Become(context.Background(), minion.Become{Task: []byte("0123456789abcdef"), User: "postgres", Method: minion.BecomeSu})
	if err != nil || got.PasswordUsed {
		t.Fatalf("%+v %v", got, err)
	}
	if out, _, err := shell(t, h, "echo nested $FAKE_USER"); err != nil || out != "nested postgres\n" {
		t.Fatalf("%q %v", out, err)
	}
}

// A become from an elevated shell goes on inside it: su from root asks
// nothing. One refused leaves the shell as it was.
func TestBecomeFromElevated(t *testing.T) {
	h, _ := becomeHost(t, "sudo-pw")
	ctx := context.Background()
	if _, err := h.Become(ctx, minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo}); err != nil {
		t.Fatal(err)
	}
	got, err := h.Become(ctx, minion.Become{Task: []byte("0123456789abcdef"), User: "postgres", Method: minion.BecomeSu})
	if err != nil || got.PasswordUsed {
		t.Fatalf("%+v %v", got, err)
	}
	if a := h.Acting(); a == nil || a.User != "postgres" {
		t.Fatalf("acting %+v", a)
	}
	if out, _, err := shell(t, h, "echo nested $FAKE_USER"); err != nil || out != "nested postgres\n" {
		t.Fatalf("%q %v", out, err)
	}

	// From su's shell (no FAKE_AS_ROOT there): su asks, a wrong one refused.
	h2, _ := becomeHost(t, "")
	if _, err := h2.Become(ctx, minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSu, Password: "root-pw"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SU_PASSWORD", "other-pw")
	_, err = h2.Become(ctx, minion.Become{Task: []byte("fedcba9876543210"), User: "bob", Method: minion.BecomeSu, Password: "nope"})
	if err == nil || !strings.Contains(err.Error(), "Authentication failure") {
		t.Fatalf("%v", err)
	}
	if a := h2.Acting(); a == nil || a.User != "root" {
		t.Fatalf("acting %+v after a refusal", a)
	}
	if out, _, err := shell(t, h2, "echo still"); err != nil || out != "still\n" {
		t.Fatalf("%q %v", out, err)
	}
}

// fellHost is a host whose session became postgres from root (sudo, then
// su inside the root shell), and the pid of postgres's shell.
func fellHost(t *testing.T) (*Host, string, int) {
	t.Helper()
	h, dir := becomeHost(t, "sudo-pw")
	ctx := context.Background()
	if _, err := h.Become(ctx, minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Become(ctx, minion.Become{Task: []byte("0123456789abcdef"), User: "postgres", Method: minion.BecomeSu}); err != nil {
		t.Fatal(err)
	}
	// The command's parent is the subshell its line made, whose parent is
	// postgres's shell.
	out, _, err := shell(t, h, "echo $FAKE_USER; ps -o ppid= -p $PPID")
	lines := strings.Fields(out)
	if err != nil || len(lines) != 2 || lines[0] != "postgres" {
		t.Fatalf("%q %v", out, err)
	}
	pid, err := strconv.Atoi(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	return h, dir, pid
}

// The shell a become went on into ends (killed): the root shell under it
// takes no command. The next one goes to a shell elevated again as the
// become in effect, which su from the login cannot make without a password:
// it fails, never runs as root.
func TestBecomeFell(t *testing.T) {
	h, dir, pid := fellHost(t)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	e := h.elev()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.Lock()
		fell := len(e.idle) == 1 && e.idle[0].fallen()
		e.mu.Unlock()
		if fell {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fall is not seen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	ran := filepath.Join(dir, "ran")
	_, _, err := shell(t, h, "echo $FAKE_USER > "+ran)
	if !errors.Is(err, minion.ErrBecome) || !strings.Contains(err.Error(), "postgres's password") {
		t.Fatalf("%v", err)
	}
	if b, err := os.ReadFile(ran); err == nil {
		t.Fatalf("it ran, as %q", b)
	}
	if why, first := h.BecomeFailure(); why == "" || !first {
		t.Fatalf("%q %v", why, first)
	}
}

// The same with the command right after the kill: whichever shell reads its
// line, never root's.
func TestBecomeFellRacing(t *testing.T) {
	for i := range 5 {
		h, dir, pid := fellHost(t)
		ran := filepath.Join(dir, "ran")
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		out, _, err := shell(t, h, "echo $FAKE_USER > "+ran+"; echo done")
		b, _ := os.ReadFile(ran)
		if strings.TrimSpace(string(b)) == "root" {
			t.Fatalf("%d: ran as root (%q %v)", i, out, err)
		}
		if err == nil && out != "done\n" {
			t.Fatalf("%d: %q", i, out)
		}
		if strings.Contains(out, h.elev().marker) {
			t.Fatalf("%d: a marker in the output: %q", i, out)
		}
	}
}

// A shell started from the login after su returned asks again: a fall
// mends with the become's password, the command going to the new shell.
func TestBecomeFellElevatesAgain(t *testing.T) {
	h, dir := becomeHost(t, "sudo-pw")
	ctx := context.Background()
	if _, err := h.Become(ctx, minion.Become{Task: make([]byte, 16), User: "root", Method: minion.BecomeSudo}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SU_PASSWORD", "pg-pw")
	pg := minion.Become{Task: []byte("0123456789abcdef"), User: "postgres", Method: minion.BecomeSu, Password: "pg-pw", Credential: "c1"}
	if _, err := h.Become(ctx, pg); err != nil {
		t.Fatal(err)
	}
	out, _, err := shell(t, h, "ps -o ppid= -p $PPID")
	pid, perr := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || perr != nil {
		t.Fatalf("%q %v %v", out, err, perr)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	e := h.elev()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.Lock()
		fell := len(e.idle) == 1 && e.idle[0].fallen()
		e.mu.Unlock()
		if fell {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fall is not seen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	ran := filepath.Join(dir, "ran")
	if out, _, err := shell(t, h, "echo $FAKE_USER > "+ran+"; echo again"); err != nil || out != "again\n" {
		t.Fatalf("%q %v", out, err)
	}
	if b, _ := os.ReadFile(ran); strings.TrimSpace(string(b)) != "postgres" {
		t.Fatalf("ran as %q", b)
	}
}

// Who a command ran as: the elevated shell's become and user.
func TestShellSaysWho(t *testing.T) {
	h, _ := becomeHost(t, "sudo-pw")
	task := []byte("fedcba9876543210")
	if _, err := h.Become(context.Background(), minion.Become{Task: task, User: "root", Method: minion.BecomeSudo}); err != nil {
		t.Fatal(err)
	}
	exit, err := h.Shell(context.Background(), "true", &bytes.Buffer{})
	if err != nil || exit.As == nil || string(exit.As.Task) != string(task) || exit.As.User != me(t) {
		t.Fatalf("%+v %v", exit.As, err)
	}
	h.Unbecome()
	if exit, err := h.Shell(context.Background(), "true", &bytes.Buffer{}); err != nil || exit.As != nil {
		t.Fatalf("%+v %v", exit.As, err)
	}
}
