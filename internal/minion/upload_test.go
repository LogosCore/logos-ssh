//go:build unix

package minion

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// fakeCore answers a minion's asks for a file's chunks, as core does.
type fakeCore struct {
	body  []byte
	offer protocol.FileOffer
	task  []byte
	// drop answers the first ask from off with no chunk (a reply with no
	// room for one).
	drop int64
	// toldAll: the minion's last ack said it has all of the file.
	toldAll bool
}

func (c *fakeCore) answer(t *testing.T, items []any) protocol.CoreMessage {
	t.Helper()
	var out []any
	for _, it := range items {
		a, ok := it.(protocol.AckItem)
		if !ok || a.Xfer == nil {
			continue
		}
		if *a.Next == uint64(len(c.body)) {
			c.toldAll = true
			continue
		}
		if int64(*a.Next) == c.drop {
			c.drop = -1
			continue
		}
		off := *a.Next
		end := min(off+protocol.MaxChunkData, uint64(len(c.body)))
		ch := protocol.ChunkItem{T: protocol.ItemChunk, Xfer: a.Xfer, Off: off, Data: c.body[off:end]}
		if off == 0 {
			total := uint64(len(c.body))
			ch.Total, ch.Task = &total, c.task
		}
		if end == uint64(len(c.body)) {
			sum := sha256.Sum256(c.body)
			ch.SHA256 = sum[:]
		}
		out = append(out, ch)
	}
	return coreSays(t, out...)
}

func newFakeCore(t *testing.T, size int, name string) *fakeCore {
	t.Helper()
	body := make([]byte, size)
	_, _ = rand.Read(body)
	sum := sha256.Sum256(body)
	return &fakeCore{body: body, task: bytes.Repeat([]byte{6}, 16), drop: -1,
		offer: protocol.FileOffer{Xfer: bytes.Repeat([]byte{9}, 16), Name: name, Size: uint64(size), SHA256: sum[:]}}
}

// runUpload runs an upload against core until it ends.
func runUpload(t *testing.T, core *fakeCore, args protocol.Args) *Task {
	t.Helper()
	args[ArgUploadFile] = core.offer
	r := newTestRunner(CmdUpload)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: core.task, Cmd: uint64(CmdUpload), Args: args})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		ended := len(r.tasks) == 1 && r.tasks[0].ended && !r.tasks[0].recv.telling()
		r.mu.Unlock()
		if ended {
			break
		}
		if !r.Pending() {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		items := r.Outgoing()
		r.Delivered()
		r.Take(core.answer(t, items), items)
	}
	return waitEnd(t, r, time.Second)
}

// A file comes in chunks the minion asks for, each from what it has; an
// ask with no answer is asked again. Into a folder, it goes under its name,
// with no temporary file left; its data says where and what was written.
func TestUpload(t *testing.T) {
	core := newFakeCore(t, protocol.MaxChunkData*2+777, "tool.bin")
	core.drop = protocol.MaxChunkData
	dir := t.TempDir()
	task := runUpload(t, core, protocol.Args{ArgUploadPath: dir, ArgUploadOverwrite: false})
	if !task.ok || len(task.chunks) != 1 || !core.toldAll {
		t.Fatalf("ended %+v, told all %v", task, core.toldAll)
	}
	dest := filepath.Join(dir, "tool.bin")
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, core.body) {
		t.Fatalf("written: %v", err)
	}
	f, err := protocol.ReadFileUpload(0, asCore(t, protocol.ResultFileUpload, task.chunks[0]))
	if err != nil || f.Path != dest || f.Size != uint64(len(core.body)) || !bytes.Equal(f.SHA256, core.offer.SHA256) {
		t.Fatalf("data: %+v %v", f, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("left %d entries", len(entries))
	}
}

// A file already there fails the task, nothing asked for, unless overwrite.
func TestUploadExists(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	core := newFakeCore(t, 10, "a.txt")
	task := runUpload(t, core, protocol.Args{ArgUploadPath: dest, ArgUploadOverwrite: false})
	if task.ok || !strings.Contains(task.err, "exists") {
		t.Fatalf("ended %+v", task)
	}
	task = runUpload(t, newFakeCore(t, 10, "a.txt"), protocol.Args{ArgUploadPath: dest, ArgUploadOverwrite: true})
	if got, _ := os.ReadFile(dest); !task.ok || len(got) != 10 {
		t.Fatalf("overwritten: %+v, %d bytes", task, len(got))
	}
	// Its mode is kept.
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
		t.Fatalf("its mode: %v", info.Mode())
	}
}

// A file that does not check out fails the task; nothing is left.
func TestUploadBadSum(t *testing.T) {
	dir := t.TempDir()
	core := newFakeCore(t, 100, "a.bin")
	core.offer.SHA256 = make([]byte, 32)
	task := runUpload(t, core, protocol.Args{ArgUploadPath: filepath.Join(dir, "a.bin"), ArgUploadOverwrite: false})
	if task.ok || !strings.Contains(task.err, "SHA-256") {
		t.Fatalf("ended %+v", task)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %d entries", len(entries))
	}
}

// A stream core sends: the offer says no size or SHA-256; core holds the
// minion while it has nothing, and the minion asks nothing until released;
// the first chunk says the size, the last the SHA-256.
func TestUploadStream(t *testing.T) {
	core := newFakeCore(t, protocol.MaxChunkData+300, "big.iso")
	offer := core.offer
	core.offer = protocol.FileOffer{Xfer: offer.Xfer, Name: offer.Name, Stream: true}
	dir := t.TempDir()
	r := newTestRunner(CmdStreamUpload)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: core.task, Cmd: uint64(CmdStreamUpload),
		Args: protocol.Args{ArgStreamUploadStream: core.offer, ArgUploadPath: dir, ArgUploadOverwrite: false}})

	// The first ask, answered with hold: nothing more is asked.
	var asked bool
	for tries := 0; !asked && tries < 5; tries++ {
		items := nextMessage(t, r)
		r.Delivered()
		for _, it := range items {
			if a, ok := it.(protocol.AckItem); ok && a.Xfer != nil {
				asked = true
			}
		}
	}
	if !asked {
		t.Fatal("no ask")
	}
	zero := uint64(0)
	r.Take(coreSays(t, protocol.AckItem{T: protocol.ItemAck, Xfer: offer.Xfer, Next: &zero, Hold: true}), nil)
	if r.Pending() {
		t.Fatal("held: still asking")
	}
	// Released: it asks, and takes the file as core sends it.
	r.Take(coreSays(t, protocol.AckItem{T: protocol.ItemAck, Xfer: offer.Xfer, Next: &zero}), nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		ended := len(r.tasks) == 1 && r.tasks[0].ended && !r.tasks[0].recv.telling()
		r.mu.Unlock()
		if ended {
			break
		}
		if !r.Pending() {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		items := r.Outgoing()
		r.Delivered()
		r.Take(core.answer(t, items), items)
	}
	task := waitEnd(t, r, time.Second)
	got, _ := os.ReadFile(filepath.Join(dir, "big.iso"))
	if !task.ok || !bytes.Equal(got, core.body) {
		t.Fatalf("ended %+v, %d bytes written", task, len(got))
	}
	f, err := protocol.ReadFileUpload(0, asCore(t, protocol.ResultFileUpload, task.chunks[0]))
	if err != nil || f.Size != uint64(len(core.body)) || !bytes.Equal(f.SHA256, offer.SHA256) {
		t.Fatalf("data: %+v %v", f, err)
	}
}
