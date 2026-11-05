//go:build unix

package minion

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A cancel stops a shell command and what it started: its children held
// the output open, so the task never ended.
func TestShellCancelStopsWhatItStarted(t *testing.T) {
	r := newTestRunner(CmdShell)
	id := make([]byte, 16)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: id, Cmd: uint64(CmdShell), Args: protocol.Args{ArgShellCommand: "echo started; sleep 30; echo never"}})
	time.Sleep(300 * time.Millisecond)
	r.stop(id, 0)
	task := waitEnd(t, r, 5*time.Second)
	if task.ok || task.err != "cancelled" || !strings.Contains(string(task.out), "started") || strings.Contains(string(task.out), "never") {
		t.Fatalf("ok %v err %q out %q", task.ok, task.err, task.out)
	}
}

// The timeout stops it the same way.
func TestShellTimeout(t *testing.T) {
	r := newTestRunner(CmdShell)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: make([]byte, 16), Cmd: uint64(CmdShell),
		Args: protocol.Args{ArgShellCommand: "sleep 30", ArgShellTimeout: uint64(300)}})
	task := waitEnd(t, r, 5*time.Second)
	if task.ok || !strings.Contains(task.err, "timeout") {
		t.Fatalf("ok %v err %q", task.ok, task.err)
	}
}

// A command's exit code is its task's; one that cannot start fails it.
func TestShellExit(t *testing.T) {
	r := newTestRunner(CmdShell)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: make([]byte, 16), Cmd: uint64(CmdShell), Args: protocol.Args{ArgShellCommand: "echo out; exit 3"}})
	task := waitEnd(t, r, 5*time.Second)
	if !task.ok || task.exit == nil || *task.exit != 3 || string(task.out) != "out\n" {
		t.Fatalf("ok %v exit %v out %q", task.ok, task.exit, task.out)
	}
}

// A task id seen before is acked again but not run again; a cancel for a
// task the runner does not have gets unknown_task; a command the minion
// does not know fails.
func TestTaskOnceAndUnknownCancel(t *testing.T) {
	r := newTestRunner(CmdVolumes)
	id := make([]byte, 16)
	vols := protocol.TaskItem{T: protocol.ItemTask, Task: id, Cmd: uint64(CmdVolumes)}
	r.start(vols)
	if task := waitEnd(t, r, 2*time.Second); !task.ok {
		t.Fatalf("volumes: %+v", task)
	}
	r.start(vols)
	r.mu.Lock()
	tasks, acks := len(r.tasks), len(r.acks)
	r.mu.Unlock()
	if tasks != 1 || acks != 2 {
		t.Fatalf("tasks %d acks %d", tasks, acks)
	}
	other := make([]byte, 16)
	other[0] = 9
	r.stop(other, 3)
	if len(r.errs) != 1 || r.errs[0].Code != protocol.ErrItemUnknownTask || *r.errs[0].Item != 3 || !bytes.Equal(r.errs[0].Task, other) {
		t.Fatalf("errs %+v", r.errs)
	}

	r = newTestRunner()
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: id, Cmd: 77})
	if task := waitEnd(t, r, 2*time.Second); task.ok || !strings.Contains(task.err, "not one this minion knows") {
		t.Fatalf("a command it does not know: %+v", task)
	}
}

// drain takes every result part the runner has to send, message by message.
func drain(r *Runner) []protocol.ResultItem {
	var parts []protocol.ResultItem
	for range 100 {
		items := r.Outgoing()
		r.mu.Lock()
		r.inflight = nil
		r.mu.Unlock()
		got := false
		for _, it := range items {
			if p, ok := it.(protocol.ResultItem); ok {
				parts = append(parts, p)
				got = true
			}
		}
		if !got {
			break
		}
	}
	return parts
}

// ls sends its folder as a listing in pieces, no data: the first names it,
// the last says so, and every entry comes once.
func TestLsSendsAListing(t *testing.T) {
	dir := t.TempDir()
	for i := range 1200 {
		if err := os.WriteFile(filepath.Join(dir, "f"+strings.Repeat("0", 4-len(itoa(i)))+itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := newTestRunner(CmdLs)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: make([]byte, 16), Cmd: uint64(CmdLs), Args: protocol.Args{ArgLsPath: dir}})
	waitEnd(t, r, 5*time.Second)
	parts := drain(r)
	var pieces []protocol.LsPiece
	for i, p := range parts {
		if len(p.Data) > 0 {
			t.Fatalf("part %d has data", i)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		pieces = append(pieces, p.Ls...)
	}
	if !parts[len(parts)-1].Done || !*parts[len(parts)-1].OK {
		t.Fatalf("the last part is not a done ok: %+v", parts[len(parts)-1])
	}
	if len(pieces) != 3 || pieces[0].Path != dir || pieces[0].Sep != "/" || !pieces[2].Last || pieces[1].Last {
		t.Fatalf("pieces: %d, first %+v", len(pieces), pieces[0].Path)
	}
	n := 0
	for i, p := range pieces {
		if p.ID != 0 || p.Part != uint64(i) || p.Partial || p.Err != 0 { //nolint:gosec // a small count
			t.Fatalf("piece %d: id %d part %d", i, p.ID, p.Part)
		}
		// Every entry is the test's: its owner and group, named once a
		// piece (one name when they are the same).
		if owners := len(p.Owners); owners < 1 || owners > 2 {
			t.Fatalf("piece %d: owners %v", i, p.Owners)
		}
		n += len(p.Entries)
	}
	if n != 1200 {
		t.Fatalf("%d entries", n)
	}
}

// A folder ls may not read is a listing that says so, and the task fails.
func TestLsUnreadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "closed")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if closeDir(t, dir) {
		t.Skip("this account reads every directory")
	}
	r := newTestRunner(CmdLs)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: make([]byte, 16), Cmd: uint64(CmdLs), Args: protocol.Args{ArgLsPath: dir}})
	waitEnd(t, r, 5*time.Second)
	parts := drain(r)
	last := parts[len(parts)-1]
	if !last.Done || *last.OK {
		t.Fatalf("the task did not fail: %+v", last)
	}
	var pieces []protocol.LsPiece
	for _, p := range parts {
		pieces = append(pieces, p.Ls...)
	}
	if len(pieces) != 1 || pieces[0].Err != protocol.ListingErrDenied || !pieces[0].Last || pieces[0].Path != dir {
		t.Fatalf("pieces %+v", pieces)
	}
}

// Core items the runner does not take get unknown_item, naming the item; a
// rehello gets a hello in the next message, alone (under the build id core
// takes no other item with it), the rest in the one after.
func TestCoreItemsTheRunnerDoesNotTake(t *testing.T) {
	r := newRunnerWith(Config{Hello: func() protocol.HelloItem { return protocol.HelloItem{T: protocol.ItemHello, PID: 7, Conn: 2} }})
	rehello, _ := protocol.MarshalCBOR(protocol.RehelloItem{T: protocol.ItemRehello})
	resume, _ := protocol.MarshalCBOR(protocol.ResumeItem{T: protocol.ItemResume, Task: make([]byte, 16), Ctx: []byte("x")})
	future, _ := protocol.MarshalCBOR(map[int]any{0: 99})
	r.Take(protocol.CoreMessage{V: protocol.MinionMessageV3, Items: []cbor.RawMessage{rehello, resume, future}}, nil)
	if !r.Pending() {
		t.Fatal("nothing to say after a rehello")
	}
	items := r.Outgoing()
	if h, ok := items[0].(protocol.HelloItem); !ok || len(items) != 1 || h.PID != 7 || h.Conn != 2 {
		t.Fatalf("items %#v, not the hello alone", items)
	}
	if !r.Pending() {
		t.Fatal("nothing to say after the hello")
	}
	items = r.Outgoing()
	var errs []protocol.ErrItem
	for _, it := range items {
		if e, ok := it.(protocol.ErrItem); ok {
			errs = append(errs, e)
		}
	}
	if len(errs) != 2 || errs[0].Code != protocol.ErrItemUnknownItem || *errs[0].Item != 1 ||
		errs[1].Code != protocol.ErrItemUnknownItem || *errs[1].Item != 2 || !strings.Contains(errs[1].Msg, "item 99") {
		t.Fatalf("errs %+v", errs)
	}
	if next := r.Outgoing(); len(next) != 1 {
		t.Fatalf("the hello asked again: %#v", next)
	}
}

// A connection that carries little (its channel's max_message) gets small
// listing pieces and small result parts.
func TestListingWithinTheConnection(t *testing.T) {
	r := newTestRunner()
	r.SetLimit(3000)
	tk := &Task{id: make([]byte, 16)}
	var entries []Entry
	for i := range 200 {
		entries = append(entries, Entry{LsEntry: protocol.LsEntry{Name: "file-" + strings.Repeat("x", 20) + itoa(i), Type: protocol.EntryFile},
			OwnerName: "root", GroupName: "root"})
	}
	r.list(tk, "/srv", "/", "/", entries, false, 0)
	if len(tk.pieces) < 5 {
		t.Fatalf("%d pieces for 200 entries over a 3000-byte connection", len(tk.pieces))
	}
	n := 0
	for i, p := range tk.pieces {
		if tk.sizes[i] > 1200 {
			t.Fatalf("piece %d is %d bytes", i, tk.sizes[i])
		}
		n += len(p.Entries)
		if p.Last != (i == len(tk.pieces)-1) || p.Part != uint64(i) { //nolint:gosec // a small count
			t.Fatalf("piece %d: part %d last %v", i, p.Part, p.Last)
		}
	}
	if n != len(entries) {
		t.Fatalf("%d entries in the pieces, not %d", n, len(entries))
	}
	r.tasks = append(r.tasks, tk)
	tk.ended, tk.ok = true, true
	for range 50 {
		items := r.Outgoing()
		size := 0
		for _, it := range items {
			b, _ := protocol.MarshalCBOR(it)
			size += len(b)
		}
		if size > 3000 {
			t.Fatalf("a message of %d bytes over a 3000-byte connection", size)
		}
		r.Delivered()
		if !r.Pending() {
			return
		}
	}
	t.Fatal("the listing never all went")
}

// An empty folder is one piece, the last.
func TestListingEmpty(t *testing.T) {
	r := newTestRunner()
	tk := &Task{id: make([]byte, 16)}
	r.list(tk, "/empty", "/", "/", nil, false, 0)
	if len(tk.pieces) != 1 || !tk.pieces[0].Last || tk.pieces[0].Path != "/empty" {
		t.Fatalf("pieces %+v", tk.pieces)
	}
}

// A command that panics fails its task and says so in feedback.
func TestCrash(t *testing.T) {
	fb := NewFeedback(nil)
	r := newRunnerWith(Config{Feedback: fb})
	r.exec = func(_ context.Context, _ *Task, _ protocol.TaskItem) { panic("boom") }
	crash := make([]byte, 16)
	crash[0] = 5
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: crash, Cmd: uint64(CmdVolumes)})
	task := waitEnd(t, r, 5*time.Second)
	if task.ok || !strings.Contains(task.err, "crashed: boom") {
		t.Fatalf("the crashed task: %+v", task)
	}
	got, _ := fb.Take(1<<20, true)
	if len(got) != 1 || got[0].Code != "task_panic" || got[0].Level != protocol.FeedbackError || string(got[0].Task) != string(crash) {
		t.Fatalf("%+v", got)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// asCore is a part's data as core keeps it: named (protocol.NamedResultData).
func asCore(t *testing.T, result string, data []byte) []byte {
	t.Helper()
	named, err := protocol.NamedResultData(result, data)
	if err != nil {
		t.Fatalf("%s data: %v", result, err)
	}
	return named
}

// coreSays is core's answer with these items.
func coreSays(t *testing.T, items ...any) protocol.CoreMessage {
	t.Helper()
	var raw []cbor.RawMessage
	for _, it := range items {
		b, err := protocol.MarshalCBOR(it)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b)
	}
	return protocol.CoreMessage{Items: raw}
}

// nextMessage is the runner's next message once it has one.
func nextMessage(t *testing.T, r *Runner) []any {
	t.Helper()
	for range 200 {
		if r.Pending() {
			if items := r.Outgoing(); len(items) > 0 {
				return items
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("nothing to send")
	return nil
}

// next is the runner's next message, as if it went through.
func next(r *Runner) []any {
	items := r.Outgoing()
	r.mu.Lock()
	r.inflight = nil
	r.mu.Unlock()
	return items
}

// Core asks which tasks the minion still has: it acks those its runner has
// (one running, one ended whose end core has not had) and names each it
// does not with unknown_task: a command that ran in an earlier connection.
func TestReack(t *testing.T) {
	r := newTestRunner()
	running, ended, gone := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 16)
	r.mu.Lock()
	r.tasks = append(r.tasks, &Task{id: running}, &Task{id: ended, ended: true})
	r.mu.Unlock()
	raw, err := protocol.MarshalCBOR(protocol.ReackItem{T: protocol.ItemReack, Tasks: [][]byte{running, ended, gone}})
	if err != nil {
		t.Fatal(err)
	}
	r.Take(protocol.CoreMessage{V: protocol.MinionMessageV3, Items: []cbor.RawMessage{raw}}, nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.acks) != 2 || !bytes.Equal(r.acks[0], running) || !bytes.Equal(r.acks[1], ended) {
		t.Fatalf("acks %x", r.acks)
	}
	if len(r.errs) != 1 || r.errs[0].Code != protocol.ErrItemUnknownTask || !bytes.Equal(r.errs[0].Task, gone) || *r.errs[0].Item != 0 {
		t.Fatalf("errs %+v", r.errs)
	}
}
