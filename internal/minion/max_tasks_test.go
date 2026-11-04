//go:build unix

package minion

import (
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// getTasksIn is the max a message's get_tasks asks for; nil without one.
func getTasksIn(items []any) *uint64 {
	for _, it := range items {
		if g, ok := it.(protocol.GetTasksItem); ok {
			return g.Max
		}
	}
	return nil
}

// maxTasksSaid is the limit a message says back, if it says one.
func maxTasksSaid(items []any) *uint64 {
	for _, it := range items {
		if m, ok := it.(protocol.MaxTasksItem); ok {
			return &m.Max
		}
	}
	return nil
}

// Several tasks run at once, up to the limit: through a call the minion
// asks for the room it has left, none when it is full; on a persistent
// connection its get_tasks is the limit itself, which core counts its
// tasks under way against.
func TestMaxTasksIntake(t *testing.T) {
	two := uint64(2)
	r := newRunnerWith(Config{MaxTasks: two}, CmdShell)
	if m := getTasksIn(next(r)); m == nil || *m != 2 {
		t.Fatalf("free: %v", m)
	}
	ids := [][]byte{make([]byte, 16), make([]byte, 16)}
	ids[1][0] = 1
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: ids[0], Cmd: uint64(CmdShell), Args: protocol.Args{ArgShellCommand: "sleep 30"}})
	if m := getTasksIn(next(r)); m == nil || *m != 1 {
		t.Fatalf("one running: %v", m)
	}
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: ids[1], Cmd: uint64(CmdShell), Args: protocol.Args{ArgShellCommand: "sleep 30"}})
	if m := getTasksIn(next(r)); m != nil {
		t.Fatalf("full: asks for %d", *m)
	}
	// Both run at once.
	time.Sleep(200 * time.Millisecond)
	r.mu.Lock()
	running := 0
	for _, task := range r.tasks {
		if !task.ended {
			running++
		}
	}
	r.mu.Unlock()
	if running != 2 {
		t.Fatalf("%d running", running)
	}
	r.SetPersistent(true)
	if m := getTasksIn(next(r)); m == nil || *m != 2 {
		t.Fatalf("persistent: %v", m)
	}
	r.SetPersistent(false)
	for _, id := range ids {
		r.stop(id, 0)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		drain(r)
		if m := getTasksIn(next(r)); m != nil && *m == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the room did not come back once both ended")
}

// Core's max_tasks changes the limit at once, whatever runs, and the
// minion says it back in its next message (sent at once: pending); 0
// takes no tasks; a limit past the most is refused.
func TestMaxTasksFromCore(t *testing.T) {
	r := newTestRunner()
	if r.MaxTasks() != protocol.DefaultMaxTasks {
		t.Fatalf("the default: %d", r.MaxTasks())
	}
	r.Take(coreSays(t, protocol.MaxTasksItem{T: protocol.ItemMaxTasks, Max: 0}), nil)
	if !r.Pending() {
		t.Fatal("the answer waits for the schedule")
	}
	items := next(r)
	if m := maxTasksSaid(items); m == nil || *m != 0 || getTasksIn(items) != nil {
		t.Fatalf("paused: said %v, asks %v", m, getTasksIn(items))
	}
	if maxTasksSaid(next(r)) != nil {
		t.Fatal("said twice")
	}
	r.SetPersistent(true)
	if m := getTasksIn(next(r)); m == nil || *m != 0 {
		t.Fatalf("paused on a persistent connection: %v", m)
	}
	r.Take(coreSays(t, protocol.MaxTasksItem{T: protocol.ItemMaxTasks, Max: protocol.MaxTasksLimit + 1}), nil)
	items = next(r)
	if maxTasksSaid(items) != nil || r.MaxTasks() != 0 {
		t.Fatalf("a limit past the most taken: %d", r.MaxTasks())
	}
	bad := false
	for _, it := range items {
		if e, ok := it.(protocol.ErrItem); ok && e.Code == protocol.ErrItemBadMessage {
			bad = true
		}
	}
	if !bad {
		t.Fatalf("no err for it: %+v", items)
	}
	// A rehello says the limit it has now.
	r.hello = func() protocol.HelloItem {
		return protocol.HelloItem{T: protocol.ItemHello, PID: 1, OS: "linux", Arch: "amd64"}
	}
	r.Take(coreSays(t, protocol.MaxTasksItem{T: protocol.ItemMaxTasks, Max: 7}, protocol.RehelloItem{T: protocol.ItemRehello}), nil)
	said := false
	for _, it := range next(r) {
		if h, ok := it.(protocol.HelloItem); ok {
			said = h.MaxTasks != nil && *h.MaxTasks == 7
		}
	}
	if !said {
		t.Fatal("the rehello did not say the limit it has")
	}
}
