//go:build unix

package minion

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// becomeHost is the test's machine as a host that becomes: a become takes a
// while, as sudo's would; shell commands then run as its user (in name: the
// test's own), and each says so (Exit.As), as sshhost's elevated shells do.
type becomeHost struct {
	osHost
	delay time.Duration

	mu     sync.Mutex
	acting *Become
	// ran is who each shell command ran as, by command: "" the login.
	ran map[string]string
}

func newBecomeHost(delay time.Duration) *becomeHost {
	return &becomeHost{delay: delay, ran: map[string]string{}}
}

func (h *becomeHost) Become(ctx context.Context, b Become) (Became, error) {
	select {
	case <-time.After(h.delay):
	case <-ctx.Done():
		return Became{}, ctx.Err()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	c := b
	h.acting = &c
	return Became{User: b.User, UID: uidOf(b.User)}, nil
}

func (h *becomeHost) Unbecome() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.acting = nil
}

func (h *becomeHost) Acting() *Become {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.acting == nil {
		return nil
	}
	b := *h.acting
	return &b
}

func (h *becomeHost) Login() string                 { return "alice" }
func (h *becomeHost) BecomeFailure() (string, bool) { return "", false }

func (h *becomeHost) Shell(ctx context.Context, command string, out io.Writer) (Exit, error) {
	return h.ShellStarted(ctx, command, out, func() {})
}

// ShellStarted: what it runs as is the session's now, as sshhost's holds its
// shell before it says so.
func (h *becomeHost) ShellStarted(ctx context.Context, command string, out io.Writer, started func()) (Exit, error) {
	a := h.Acting()
	started()
	exit, err := h.osHost.Shell(ctx, command, out)
	h.mu.Lock()
	h.ran[command] = ""
	if a != nil {
		h.ran[command] = a.User
		exit.As = &Ran{Task: a.Task, User: a.User, UID: uidOf(a.User)}
	}
	h.mu.Unlock()
	return exit, err
}

func (h *becomeHost) ranAs(command string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	u, ok := h.ran[command]
	return u, ok
}

func uidOf(user string) int64 {
	if user == "root" {
		return 0
	}
	return 1001
}

// asCoreSees is who core records each task ran as, from the minion's items
// in the order they went: a task takes the session's identity when it is
// acked (or its first result is), unless it said its own (docs:
// contracts/minion-messages/identity). "" is the process's own;
// acting, the session's user as the connection opened.
func asCoreSees(t *testing.T, acting string, items []any) map[string]string {
	t.Helper()
	as := map[string]string{}
	set := map[string]bool{}
	acked := map[string]bool{}
	ack := func(id []byte) {
		k := hex.EncodeToString(id)
		if acked[k] {
			return
		}
		acked[k] = true
		if !set[k] {
			as[k], set[k] = acting, true
		}
	}
	for _, it := range items {
		switch v := it.(type) {
		case protocol.IdentityItem:
			if err := v.Validate(); err != nil {
				t.Fatalf("identity %+v: %v", v, err)
			}
			who := ""
			if !v.Own() {
				who = v.User
			}
			if v.Scope == protocol.IdentitySession {
				acting = who
				continue
			}
			k := hex.EncodeToString(v.Task)
			as[k], set[k] = who, true
		case protocol.AckItem:
			for _, id := range v.Tasks {
				ack(id)
			}
		case protocol.ResultItem:
			ack(v.Task)
		}
	}
	return as
}

// runAll starts the tasks back to back, as core's push brings them, and
// takes the runner's messages until each task's end went: their items, in
// order.
func runAll(t *testing.T, r *Runner, tasks ...protocol.TaskItem) []any {
	t.Helper()
	for _, ti := range tasks {
		r.start(ti)
	}
	var all []any
	ended := map[string]bool{}
	deadline := time.Now().Add(10 * time.Second)
	for len(ended) < len(tasks) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d tasks ended; items %+v", len(ended), len(tasks), all)
		}
		for _, it := range next(r) {
			all = append(all, it)
			if p, ok := it.(protocol.ResultItem); ok && p.Done {
				ended[hex.EncodeToString(p.Task)] = true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return all
}

func shellOf(id byte, command string) protocol.TaskItem {
	return taskOf(id, CmdShell, protocol.Args{ArgShellCommand: command})
}

func becomeOf(id byte, user, method string) protocol.TaskItem {
	return taskOf(id, CmdBecome, protocol.Args{ArgBecomeUser: user, ArgBecomeMethod: method})
}

// The operator's way through, queued at once: become root, a shell, su to
// another user, a shell, unbecome, a shell. Each shell runs as the session
// is once the becomes before it ended, and core records each as who it ran
// as: the tasks acked before an identity are in an ack before it, and a
// shell that ran as another than its ack said says so.
func TestRunnerBecomesInOrder(t *testing.T) {
	h := newBecomeHost(100 * time.Millisecond)
	r := newRunnerWith(Config{Host: h}, CmdBecome, CmdUnbecome, CmdShell, CmdLs)
	dir := t.TempDir()
	all := runAll(t, r,
		becomeOf(1, "root", BecomeSudo), shellOf(2, "echo one"), taskOf(3, CmdLs, protocol.Args{ArgLsPath: dir}),
		becomeOf(4, "postgres", BecomeSu), shellOf(5, "echo two"),
		taskOf(6, CmdUnbecome, nil), shellOf(7, "echo three"))

	want := map[string]string{"echo one": "root", "echo two": "postgres", "echo three": ""}
	for command, user := range want {
		if got, ok := h.ranAs(command); !ok || got != user {
			t.Errorf("%q ran as %q (ran: %v), want %q", command, got, ok, user)
		}
	}
	seen := asCoreSees(t, "", all)
	for id, user := range map[byte]string{2: "root", 3: "", 5: "postgres", 7: ""} {
		if got := seen[hex.EncodeToString(taskID(id))]; got != user {
			t.Errorf("core records task %d as %q, want %q; items %+v", id, got, user, all)
		}
	}
}

// Tasks after an identity went: acked after it, a shell as it says, so
// nothing more of it; a file command says its own, before its ack.
func TestRunnerAfterBecome(t *testing.T) {
	h := newBecomeHost(0)
	r := newRunnerWith(Config{Host: h}, CmdBecome, CmdShell, CmdLs)
	first := runAll(t, r, becomeOf(1, "root", BecomeSudo))
	if ids := identities(first); len(ids) != 1 || ids[0].Scope != protocol.IdentitySession || ids[0].User != "root" {
		t.Fatalf("identities %+v", ids)
	}
	dir := t.TempDir()
	then := runAll(t, r, shellOf(2, "echo after"), taskOf(3, CmdLs, protocol.Args{ArgLsPath: dir}))
	ids := identities(then)
	if len(ids) != 1 || ids[0].Scope != protocol.IdentityTask || string(ids[0].Task) != string(taskID(3)) || !ids[0].Own() {
		t.Fatalf("identities %+v", ids)
	}
	if i, a := indexOf(then, ids[0]), ackIndex(then, taskID(3)); i < 0 || a < 0 || i > a {
		t.Fatalf("the ls's identity (%d) is not before its ack (%d)", i, a)
	}
	seen := asCoreSees(t, "root", then)
	if seen[hex.EncodeToString(taskID(2))] != "root" || seen[hex.EncodeToString(taskID(3))] != "" {
		t.Fatalf("core records %v", seen)
	}
}

// A connection that opens with core's become (Acting) the host could not
// take up: shell commands run as the login, and say so; file commands too.
func TestRunnerActingNotTaken(t *testing.T) {
	h := newBecomeHost(0)
	r := newRunnerWith(Config{Host: h, Acting: taskID(9)}, CmdShell, CmdLs)
	all := runAll(t, r, shellOf(1, "echo plain"), taskOf(2, CmdLs, protocol.Args{ArgLsPath: t.TempDir()}))
	seen := asCoreSees(t, "root", all)
	if seen[hex.EncodeToString(taskID(1))] != "" || seen[hex.EncodeToString(taskID(2))] != "" {
		t.Fatalf("core records %v; items %+v", seen, all)
	}
}

// A shell that waits for a become before it is cancelled ends so, never
// run.
func TestRunnerCancelWhileBecoming(t *testing.T) {
	h := newBecomeHost(time.Second)
	r := newRunnerWith(Config{Host: h}, CmdBecome, CmdShell)
	r.start(becomeOf(1, "root", BecomeSudo))
	r.start(shellOf(2, "echo never"))
	r.stop(taskID(2), 0)
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.mu.Lock()
		var ended bool
		var errText string
		for _, task := range r.tasks {
			if task.cmd == uint64(CmdShell) && task.ended {
				ended, errText = true, task.err
			}
		}
		r.mu.Unlock()
		if ended {
			if errText != "cancelled" {
				t.Fatalf("ended %q", errText)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the shell waits on")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ran := h.ranAs("echo never"); ran {
		t.Fatal("it ran")
	}
}

// A call's tasks before a become are in an ack before its identity, those
// after in one after it.
func TestCallBecomesInOrder(t *testing.T) {
	h := newBecomeHost(0)
	c := &Caller{Host: h, Ops: testOps(CmdBecome, CmdUnbecome, CmdShell, CmdLs)}
	dir := t.TempDir()
	items := callWith(t, c, taskOf(1, CmdLs, protocol.Args{ArgLsPath: dir}), shellOf(2, "echo before"), becomeOf(3, "root", BecomeSudo),
		shellOf(4, "echo after"))
	if _, ok := items[0].(protocol.AckItem); !ok {
		t.Fatalf("first %T", items[0])
	}
	if a, ok := items[0].(protocol.AckItem); !ok || len(a.Tasks) != 3 {
		t.Fatalf("first ack %+v", items[0])
	}
	if id, ok := items[1].(protocol.IdentityItem); !ok || id.Scope != protocol.IdentitySession || id.User != "root" {
		t.Fatalf("second %+v", items[1])
	}
	if a, ok := items[2].(protocol.AckItem); !ok || len(a.Tasks) != 1 || string(a.Tasks[0]) != string(taskID(4)) {
		t.Fatalf("third %+v", items[2])
	}
	seen := asCoreSees(t, "", items)
	for id, user := range map[byte]string{1: "", 2: "", 4: "root"} {
		if got := seen[hex.EncodeToString(taskID(id))]; got != user {
			t.Errorf("task %d as %q, want %q", id, got, user)
		}
	}
	// Taken up again by the next call (its acting) but not by the host: as
	// the login, said.
	h.Unbecome()
	c.Acting = taskID(3)
	items = callWith(t, c, shellOf(5, "echo plain"), taskOf(6, CmdLs, protocol.Args{ArgLsPath: dir}))
	seen = asCoreSees(t, "root", items)
	if seen[hex.EncodeToString(taskID(5))] != "" || seen[hex.EncodeToString(taskID(6))] != "" {
		t.Fatalf("core records %v; items %+v", seen, items)
	}
}

// The minion's log says each task's number and command, never its args: a
// become's password, a shell's command line.
func TestLogsNoArgs(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	secret := "hunter2-secret"
	become := taskOf(1, CmdBecome, protocol.Args{ArgBecomePassword: protocol.Credential{ID: "c1", Type: protocol.CredentialTypePlaintext,
		Password: secret}})
	shell := shellOf(2, "echo top-secret-command")

	r := newRunnerWith(Config{Host: newBecomeHost(0), Logf: logf}, CmdBecome, CmdShell)
	runAll(t, r, become, shell)
	c := &Caller{Host: newBecomeHost(0), Ops: testOps(CmdBecome, CmdShell), Logf: logf}
	callWith(t, c, become, shell)

	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 {
		t.Fatal("nothing logged")
	}
	// As %v writes a credential's raw CBOR: its bytes in decimal.
	var nums []string
	for _, c := range []byte(secret) {
		nums = append(nums, strconv.Itoa(int(c)))
	}
	bytesOf := strings.Join(nums, " ")
	for _, l := range lines {
		if strings.Contains(l, secret) || strings.Contains(l, bytesOf) || strings.Contains(l, hex.EncodeToString([]byte(secret))) ||
			strings.Contains(l, "top-secret") {
			t.Errorf("logged %q", l)
		}
	}
}

func identities(items []any) []protocol.IdentityItem {
	var out []protocol.IdentityItem
	for _, it := range items {
		if id, ok := it.(protocol.IdentityItem); ok {
			out = append(out, id)
		}
	}
	return out
}

func indexOf(items []any, id protocol.IdentityItem) int {
	for i, it := range items {
		if v, ok := it.(protocol.IdentityItem); ok && v.Scope == id.Scope && string(v.Task) == string(id.Task) {
			return i
		}
	}
	return -1
}

func ackIndex(items []any, task []byte) int {
	for i, it := range items {
		if a, ok := it.(protocol.AckItem); ok {
			for _, id := range a.Tasks {
				if string(id) == string(task) {
					return i
				}
			}
		}
	}
	return -1
}
