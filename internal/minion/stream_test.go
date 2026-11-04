//go:build unix

package minion

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

func startStream(t *testing.T, body []byte) (*Runner, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	r := newTestRunner(CmdStreamDownload)
	r.start(protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{4}, 16), Cmd: uint64(CmdStreamDownload), Args: protocol.Args{ArgDownloadPath: path}})
	return r, path
}

// streamAck is core's ack of a stream.
func streamAck(t *testing.T, xfer []byte, next uint64, hold bool) protocol.CoreMessage {
	return coreSays(t, protocol.AckItem{T: protocol.ItemAck, Xfer: xfer, Next: &next, Hold: hold})
}

// A stream announces its file without data, then sends nothing while
// held; released, it sends from where core says, going back when told (a
// download resumed from earlier), and ends when core has it all, without
// hold, its SHA-256 known as it read the file in order once.
func TestStream(t *testing.T) {
	body := make([]byte, protocol.MaxChunkData*2+99)
	_, _ = rand.Read(body)
	r, path := startStream(t, body)

	var announce protocol.ChunkItem
	for tries := 0; tries < 5; tries++ {
		items := nextMessage(t, r)
		r.Delivered()
		if c, _, ok := chunkIn(items); ok {
			announce = c
			break
		}
	}
	if announce.Off != 0 || len(announce.Data) != 0 || announce.Total == nil || *announce.Total != uint64(len(body)) || announce.Name != path {
		t.Fatalf("announce: %+v", announce)
	}
	xfer := announce.Xfer
	r.Take(streamAck(t, xfer, 0, true), nil)
	if r.Pending() || r.PollEvery() != 0 {
		t.Fatal("held before it ran: something to send, or a short poll")
	}

	// Released: from 0; then back to 0 again; then on.
	got := map[uint64][]byte{}
	next := func(off uint64, hold bool) protocol.ChunkItem {
		t.Helper()
		r.Take(streamAck(t, xfer, off, hold), nil)
		items := nextMessage(t, r)
		r.Delivered()
		c, _, ok := chunkIn(items)
		if !ok || c.Off != off {
			t.Fatalf("no chunk from %d: %+v", off, c)
		}
		got[c.Off] = c.Data
		// Every chunk from 0 says what the first must (a stream resumed
		// from the start too): core refuses one that does not.
		if err := c.Validate(); err != nil {
			t.Fatalf("chunk from %d: %v", off, err)
		}
		return c
	}
	first := next(0, false)
	next(uint64(len(first.Data)), false)
	next(0, false) // resumed from the start
	off := uint64(len(first.Data))
	for off < uint64(len(body)) {
		c := next(off, false)
		off += uint64(len(c.Data))
		if off == uint64(len(body)) && c.SHA256 == nil {
			t.Fatal("the last chunk without its sha256")
		}
	}
	// All sent, held until the downloader has it: core asks the minion to
	// come back soon (a poll), for the next message only.
	held := streamAck(t, xfer, off, true)
	poll, _ := protocol.MarshalCBOR(protocol.PollItem{T: protocol.ItemPoll, Within: 1000})
	held.Items = append(held.Items, poll)
	r.Take(held, nil)
	if r.PollEvery() != time.Second {
		t.Fatal("core's poll not taken")
	}
	r.Outgoing()
	if r.PollEvery() != 0 {
		t.Fatal("core's poll outlived the message it was for")
	}
	r.Take(streamAck(t, xfer, off, false), nil)
	task := waitEnd(t, r, 2*time.Second)
	if !task.ok || len(task.chunks) != 1 {
		t.Fatalf("ended %+v", task)
	}
	f, err := protocol.ReadFileStream(0, asCore(t, protocol.ResultFileStream, task.chunks[0]))
	sum := sha256.Sum256(body)
	if err != nil || f.Size != uint64(len(body)) || !bytes.Equal(f.SHA256, sum[:]) {
		t.Fatalf("data: %+v %v", f, err)
	}
}

// A stream resumed ahead of what was read ends without a SHA-256.
func TestStreamResumedAhead(t *testing.T) {
	body := make([]byte, 5000)
	r, _ := startStream(t, body)
	var c protocol.ChunkItem
	for tries, ok := 0, false; !ok && tries < 5; tries++ {
		items := nextMessage(t, r)
		r.Delivered()
		c, _, ok = chunkIn(items)
	}
	var items []any
	r.Take(streamAck(t, c.Xfer, 1000, false), nil)
	items = nextMessage(t, r)
	r.Delivered()
	if got, _, _ := chunkIn(items); got.Off != 1000 || got.SHA256 != nil {
		t.Fatalf("from 1000: off %d, sha256 %x", got.Off, got.SHA256)
	}
	r.Take(streamAck(t, c.Xfer, 5000, false), nil)
	task := waitEnd(t, r, 2*time.Second)
	f, err := protocol.ReadFileStream(0, asCore(t, protocol.ResultFileStream, task.chunks[0]))
	if err != nil || f.SHA256 != nil {
		t.Fatalf("data: %+v %v", f, err)
	}
}
