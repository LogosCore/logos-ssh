//go:build unix

package minion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// testCaller answers calls on the test's machine with every command, by
// the numbers testOps gives them.
func testCaller(limit int) *Caller {
	ops := testOps(CmdLs, CmdWalk, CmdDownload, CmdStreamDownload, CmdUpload, CmdStreamUpload, CmdRm, CmdShell, CmdVolumes)
	return &Caller{Host: osHost{}, Ops: ops, Limit: limit,
		Hello: func() protocol.HelloItem {
			return protocol.HelloItem{T: protocol.ItemHello, PID: 0, OS: "linux", Arch: "amd64"}
		}}
}

// callWith is core's call with these items, answered within a minute.
func callWith(t *testing.T, c *Caller, items ...any) []any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return c.Answer(ctx, coreSays(t, items...))
}

func taskID(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func taskOf(id byte, cmd Command, args protocol.Args) protocol.TaskItem {
	return protocol.TaskItem{T: protocol.ItemTask, Task: taskID(id), Cmd: uint64(cmd), Args: args} //nolint:gosec // a small command
}

// results are an answer's result parts; chunks its chunks; asks its acks of
// a transfer.
func results(items []any) []protocol.ResultItem {
	var out []protocol.ResultItem
	for _, it := range items {
		if r, ok := it.(protocol.ResultItem); ok {
			out = append(out, r)
		}
	}
	return out
}

func chunks(items []any) []protocol.ChunkItem {
	var out []protocol.ChunkItem
	for _, it := range items {
		if c, ok := it.(protocol.ChunkItem); ok {
			out = append(out, c)
		}
	}
	return out
}

func asks(items []any) []protocol.AckItem {
	var out []protocol.AckItem
	for _, it := range items {
		if a, ok := it.(protocol.AckItem); ok && a.Xfer != nil {
			out = append(out, a)
		}
	}
	return out
}

// Every answer acks the call's tasks first and asks for more last; a
// rehello gets the hello; an item it does not take gets unknown_item; a
// cancel for a task that ended within its call gets unknown_task.
func TestCallAnswer(t *testing.T) {
	c := testCaller(0)
	items := callWith(t, c, protocol.RehelloItem{T: protocol.ItemRehello}, taskOf(1, CmdShell, protocol.Args{ArgShellCommand: "echo hi; exit 3"}),
		protocol.SleepUpdateItem{T: protocol.ItemSleepUpdate, Interval: 1}, protocol.CancelItem{T: protocol.ItemCancel, Task: taskID(7)})
	if a, ok := items[0].(protocol.AckItem); !ok || len(a.Tasks) != 1 || !bytes.Equal(a.Tasks[0], taskID(1)) {
		t.Fatalf("first %#v", items[0])
	}
	if g, ok := items[len(items)-1].(protocol.GetTasksItem); !ok || *g.Max != DefaultCallTasks {
		t.Fatalf("last %#v", items[len(items)-1])
	}
	if _, ok := items[1].(protocol.HelloItem); !ok {
		t.Fatalf("no hello: %#v", items[1])
	}
	r := results(items)
	if len(r) != 1 || !r[0].Done || !*r[0].OK || r[0].Exit == nil || *r[0].Exit != 3 || string(r[0].Out) != "hi\n" {
		t.Fatalf("the shell: %+v", r)
	}
	var codes []int
	for _, it := range items {
		if e, ok := it.(protocol.ErrItem); ok {
			codes = append(codes, e.Code)
		}
	}
	if !slices.Equal(codes, []int{protocol.ErrItemUnknownItem, protocol.ErrItemUnknownTask}) {
		t.Fatalf("errs %v", codes)
	}
}

// A shell command runs within the call: one that would outlast it is
// stopped before the call's deadline.
func TestCallShellWithinTheCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
	defer cancel()
	start := time.Now()
	items := testCaller(0).Answer(ctx, coreSays(t, taskOf(1, CmdShell, protocol.Args{ArgShellCommand: "sleep 30"})))
	r := results(items)
	if len(r) != 1 || *r[0].OK || !strings.Contains(r[0].Err, "timeout") || time.Since(start) > 3*time.Second {
		t.Fatalf("%+v in %s", r, time.Since(start))
	}
}

// ls answers with the folder's listing; rm removes; tasks past the
// answer's room are not acked, so core sends them again.
func TestCallLsRmAndRoom(t *testing.T) {
	dir := t.TempDir()
	for i := range 300 {
		if err := os.WriteFile(filepath.Join(dir, "file-"+strings.Repeat("x", 40)+itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := testCaller(16 << 10)
	items := callWith(t, c, taskOf(1, CmdLs, protocol.Args{ArgLsPath: dir}), taskOf(2, CmdLs, protocol.Args{ArgLsPath: dir}))
	a := items[0].(protocol.AckItem)
	r := results(items)
	if len(a.Tasks) != 1 || len(r) != 1 || !*r[0].OK || len(r[0].Ls) == 0 || r[0].Ls[0].Path != dir {
		t.Fatalf("acked %d, results %+v", len(a.Tasks), r)
	}
	n, last := 0, r[0].Ls[len(r[0].Ls)-1]
	for _, p := range r[0].Ls {
		n += len(p.Entries)
	}
	if want := (16 << 10) / 150; n != want || !last.Last || !last.Partial {
		t.Fatalf("%d entries, partial %v (at most %d)", n, last.Partial, want)
	}
	file := filepath.Join(dir, "file-"+strings.Repeat("x", 40)+"0")
	r = results(callWith(t, c, taskOf(3, CmdRm, protocol.Args{ArgRmPath: file})))
	if len(r) != 1 || !*r[0].OK || !strings.Contains(string(r[0].Out), "(file)") {
		t.Fatalf("rm: %+v", r)
	}
}

// A download goes a chunk a call, each from where core's ack says, with
// the ctx core echoes: a chunk whose ack is lost comes again as it was.
// Core has the file's SHA-256 with the last chunk and in the task's data.
func TestCallDownload(t *testing.T) {
	body := make([]byte, protocol.MaxChunkData*2+1234)
	_, _ = rand.Read(body)
	path := filepath.Join(t.TempDir(), "loot.bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	c := testCaller(0)
	items := callWith(t, c, taskOf(1, CmdDownload, protocol.Args{ArgDownloadPath: path}))
	ch := chunks(items)
	if len(ch) != 1 || ch[0].Off != 0 || ch[0].Total == nil || *ch[0].Total != uint64(len(body)) || ch[0].Name != path || ch[0].Ctx == nil {
		t.Fatalf("the first chunk: %+v", ch)
	}
	got := append([]byte(nil), ch[0].Data...)
	prev, cur := ch[0], ch[0]
	lost := false
	var end []protocol.ResultItem
	for len(end) == 0 {
		next := uint64(len(got))
		ack := protocol.AckItem{T: protocol.ItemAck, Xfer: cur.Xfer, Next: &next, Ctx: cur.Ctx}
		if !lost && next > uint64(len(ch[0].Data)) {
			// The last chunk's answer is lost: core acks from before it,
			// with the ctx it had then.
			lost = true
			back := prev.Off + uint64(len(prev.Data))
			got = got[:back]
			ack = protocol.AckItem{T: protocol.ItemAck, Xfer: cur.Xfer, Next: &back, Ctx: prev.Ctx}
		}
		items = callWith(t, c, ack)
		if end = results(items); len(end) > 0 {
			break
		}
		ch = chunks(items)
		if len(ch) != 1 || ch[0].Off != uint64(len(got)) {
			t.Fatalf("a chunk from %d: %+v", len(got), ch)
		}
		got = append(got, ch[0].Data...)
		prev, cur = cur, ch[0]
		if uint64(len(got)) == uint64(len(body)) {
			sum := sha256.Sum256(body)
			if !bytes.Equal(ch[0].SHA256, sum[:]) {
				t.Fatalf("the last chunk's sha256: %x", ch[0].SHA256)
			}
		}
	}
	sum := sha256.Sum256(body)
	f, err := protocol.ReadFileDownload(0, asCore(t, protocol.ResultFileDownload, end[0].Data))
	if !lost || !bytes.Equal(got, body) || err != nil || !bytes.Equal(f.SHA256, sum[:]) || f.Size != uint64(len(body)) {
		t.Fatalf("lost %v, the file %v, data %+v %v", lost, bytes.Equal(got, body), f, err)
	}
}

// A stream announces its file and sends nothing while held; let go, it
// sends from where core says (from 0 again too), and ends with its data.
func TestCallStreamDownload(t *testing.T) {
	body := make([]byte, protocol.MaxChunkData+77)
	_, _ = rand.Read(body)
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	c := testCaller(0)
	ch := chunks(callWith(t, c, taskOf(1, CmdStreamDownload, protocol.Args{ArgStreamDownloadPath: path})))
	if len(ch) != 1 || len(ch[0].Data) != 0 || *ch[0].Total != uint64(len(body)) {
		t.Fatalf("announce: %+v", ch)
	}
	xfer, ctx := ch[0].Xfer, ch[0].Ctx
	zero := uint64(0)
	if items := callWith(t, c, protocol.AckItem{T: protocol.ItemAck, Xfer: xfer, Next: &zero, Hold: true, Ctx: ctx}); len(items) != 1 {
		t.Fatalf("held, it said %#v", items)
	}
	var got []byte
	for range 10 {
		next := uint64(len(got))
		items := callWith(t, c, protocol.AckItem{T: protocol.ItemAck, Xfer: xfer, Next: &next, Ctx: ctx})
		if r := results(items); len(r) == 1 {
			f, err := protocol.ReadFileStream(0, asCore(t, protocol.ResultFileStream, r[0].Data))
			sum := sha256.Sum256(body)
			if !bytes.Equal(got, body) || err != nil || !bytes.Equal(f.SHA256, sum[:]) {
				t.Fatalf("the end: %+v %v", f, err)
			}
			return
		}
		ch = chunks(items)
		if len(ch) != 1 || ch[0].Off != next || (next == 0 && ch[0].Total == nil) {
			t.Fatalf("from %d: %+v", next, ch)
		}
		got, ctx = append(got, ch[0].Data...), ch[0].Ctx
	}
	t.Fatal("the stream did not end")
}

// coreSends answers the minion's asks for a file's chunks, as core does,
// echoing the ctx of each ask.
func coreSends(body []byte, task []byte, a protocol.AckItem) protocol.ChunkItem {
	off := *a.Next
	end := min(off+protocol.MaxChunkData, uint64(len(body)))
	c := protocol.ChunkItem{T: protocol.ItemChunk, Xfer: a.Xfer, Off: off, Data: body[off:end], Ctx: a.Ctx}
	if off == 0 {
		total := uint64(len(body))
		c.Total, c.Task = &total, task
	}
	if end == uint64(len(body)) {
		sum := sha256.Sum256(body)
		c.SHA256 = sum[:]
	}
	return c
}

// An upload asks for its chunks one a call, from what it has; a chunk sent
// again is written once; whole and checked, the file is in place.
func TestCallUpload(t *testing.T) {
	body := make([]byte, protocol.MaxChunkData*2+300)
	_, _ = rand.Read(body)
	sum := sha256.Sum256(body)
	offer := protocol.FileOffer{Xfer: bytes.Repeat([]byte{9}, 16), Name: "tool.bin", Size: uint64(len(body)), SHA256: sum[:]}
	dir := t.TempDir()
	c := testCaller(0)
	items := callWith(t, c, taskOf(1, CmdUpload, protocol.Args{ArgUploadFile: offer, ArgUploadPath: dir}))
	ask := asks(items)
	resent := false
	for range 10 {
		if len(ask) != 1 {
			t.Fatalf("asks %+v", ask)
		}
		chunk := coreSends(body, taskID(1), ask[0])
		items = callWith(t, c, chunk)
		if !resent && chunk.Off == 0 {
			// The answer is lost: core sends the same chunk again.
			resent = true
			items = callWith(t, c, chunk)
		}
		if r := results(items); len(r) == 1 {
			if a := asks(items); len(a) != 1 || *a[0].Next != uint64(len(body)) {
				t.Fatalf("no last ack: %+v", a)
			}
			got, _ := os.ReadFile(filepath.Join(dir, "tool.bin"))
			entries, _ := os.ReadDir(dir)
			if !*r[0].OK || !bytes.Equal(got, body) || len(entries) != 1 {
				t.Fatalf("the end %+v, written %v, %d entries", r[0], bytes.Equal(got, body), len(entries))
			}
			return
		}
		ask = asks(items)
	}
	t.Fatal("the upload did not end")
}

// A stream to the minion: held, it asks nothing; bytes come, core acks and
// it asks from what it has; the first chunk says the size, the last the
// SHA-256. A cancel removes what came.
func TestCallUploadStream(t *testing.T) {
	body := make([]byte, protocol.MaxChunkData+300)
	_, _ = rand.Read(body)
	offer := protocol.FileOffer{Xfer: bytes.Repeat([]byte{8}, 16), Name: "big.iso", Stream: true}
	dir := t.TempDir()
	c := testCaller(0)
	ask := asks(callWith(t, c, taskOf(1, CmdStreamUpload, protocol.Args{ArgStreamUploadStream: offer, ArgStreamUploadPath: dir})))
	zero := uint64(0)
	if items := callWith(t, c, protocol.AckItem{T: protocol.ItemAck, Xfer: offer.Xfer, Next: &zero, Hold: true, Ctx: ask[0].Ctx}); len(asks(items)) != 0 {
		t.Fatalf("held, it asked: %#v", items)
	}
	ask = asks(callWith(t, c, protocol.AckItem{T: protocol.ItemAck, Xfer: offer.Xfer, Next: &zero, Ctx: ask[0].Ctx}))
	for range 10 {
		items := callWith(t, c, coreSends(body, taskID(1), ask[0]))
		if r := results(items); len(r) == 1 {
			got, _ := os.ReadFile(filepath.Join(dir, "big.iso"))
			if !*r[0].OK || !bytes.Equal(got, body) {
				t.Fatalf("the end %+v", r[0])
			}
			break
		}
		ask = asks(items)
	}

	// Another, stopped halfway: its partial file goes.
	offer.Xfer = bytes.Repeat([]byte{7}, 16)
	ask = asks(callWith(t, c, taskOf(2, CmdStreamUpload, protocol.Args{ArgStreamUploadStream: offer, ArgStreamUploadPath: filepath.Join(dir, "b.iso")})))
	ask = asks(callWith(t, c, coreSends(body, taskID(2), ask[0])))
	r := results(callWith(t, c, protocol.CancelItem{T: protocol.ItemCancel, Task: taskID(2), Ctx: ask[0].Ctx}))
	entries, _ := os.ReadDir(dir)
	if len(r) != 1 || *r[0].OK || !strings.Contains(r[0].Err, "partial file is removed") || len(entries) != 1 {
		t.Fatalf("stopped: %+v, %d entries", r, len(entries))
	}
}

// A walk too big for one answer goes on across calls, depth first in name
// order, as core resumes it with its ctx; every folder comes once.
func TestCallWalk(t *testing.T) {
	root := t.TempDir()
	var want []string
	for _, d := range []string{"a", "a/a1", "a/a1/x", "a/a2", "b", "b/b1", "c", ".h"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		for i := range 40 {
			if err := os.WriteFile(filepath.Join(root, d, "f-"+strings.Repeat("y", 30)+itoa(i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	want = []string{".", ".h", "a", "a/a1", "a/a1/x", "a/a2", "b", "b/b1", "c"}
	c := testCaller(8 << 10)
	r := results(callWith(t, c, taskOf(1, CmdWalk, protocol.Args{ArgWalkPath: root})))
	var folders []string
	parts := 0
	for parts = 1; parts < 50; parts++ {
		if len(r) != 1 {
			t.Fatalf("part %d: %+v", parts, r)
		}
		for _, p := range r[0].Ls {
			if p.Part == 0 {
				rel, _ := filepath.Rel(root, p.Path)
				folders = append(folders, rel)
			}
		}
		if r[0].Done {
			break
		}
		r = results(callWith(t, c, protocol.ResumeItem{T: protocol.ItemResume, Task: taskID(1), Ctx: r[0].Ctx}))
	}
	w, err := protocol.ReadDirWalk(r[0].Seq, asCore(t, protocol.ResultDirWalk, r[0].Data))
	if !slices.Equal(folders, want) || parts < 3 || !*r[0].OK || err != nil || w.Folders != uint64(len(want)) || w.Entries != 8*40+9 {
		t.Fatalf("folders %v in %d parts, %+v %v", folders, parts, w, err)
	}

	// Not into hidden folders, two levels at most; stopped after a part.
	r = results(callWith(t, c, taskOf(2, CmdWalk, protocol.Args{ArgWalkPath: root, ArgWalkHidden: false, ArgWalkDepth: int64(1)})))
	if r[0].Done {
		t.Fatal("done in one part")
	}
	r = results(callWith(t, c, protocol.CancelItem{T: protocol.ItemCancel, Task: taskID(2), Ctx: r[0].Ctx}))
	if len(r) != 1 || !r[0].Done || *r[0].OK || r[0].Err != "stopped" {
		t.Fatalf("stopped: %+v", r)
	}
}

// The volumes go in parts within the answer, the last ending the task.
func TestCallVolumes(t *testing.T) {
	r := results(callWith(t, testCaller(0), taskOf(1, CmdVolumes, nil)))
	if len(r) != 1 || !r[0].Done || !*r[0].OK {
		t.Fatalf("%+v", r)
	}
	v, err := protocol.ReadVolumes(0, asCore(t, protocol.ResultVolumes, r[0].Data))
	if err != nil || len(v.Volumes) != 1 || v.Volumes[0].Path != "/" {
		t.Fatalf("%+v %v", v, err)
	}
}
