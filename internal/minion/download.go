package minion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A download sends a file core asked for (docs:
// contracts/minion-messages/file-transfers): in chunks of at most
// protocol.MaxChunkData, one in each message, each the next from where
// core's last ack said it has the file, so a lost message or a restart of
// core only sends a chunk again. The file is read as it goes and hashed on
// its first read; the last chunk says the whole's SHA-256. The task ends,
// with the file_download data, once core has every byte; core's refusal
// (too large, say) or a stop ends it failed.

// transfer is a file being sent.
type transfer struct {
	id    []byte
	path  string
	file  ReadFile
	total uint64
	// acked is how far core has the file: the next chunk starts there.
	acked uint64
	// waiting: a chunk went in the last message, its ack not taken yet.
	waiting bool
	// hashed is how far the hash has read: a chunk sent again is not hashed
	// twice.
	hashed uint64
	sum    hash.Hash
	// end is closed when core has the file, or it failed (err).
	end  chan struct{}
	err  string
	over bool

	// A stream: announced once core acked the empty first chunk; held
	// while core's last ack said hold; started once an ack without hold
	// came. gap: a chunk was read past what is hashed (a download resumed
	// ahead), so the whole's SHA-256 is not known.
	stream    bool
	announced bool
	held      bool
	started   bool
	gap       bool
}

// sendFile sends a file core asked for: as a download, or as a stream,
// which ends with other data.
func (r *Runner) sendFile(ctx context.Context, t *Task, args protocol.Args, stream bool) {
	key := uint64(ArgDownloadPath)
	if stream {
		key = ArgStreamDownloadPath
	}
	path, _ := protocol.ArgString(args, key)
	if path == "" {
		r.End(t, false, nil, "no path")
		return
	}
	abs, err := r.host.Abs(path)
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	f, err := r.host.Open(abs)
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	defer func() { _ = f.Close() }() // read only: nothing to lose on close
	info, err := f.Stat()
	if err != nil {
		r.End(t, false, nil, err.Error())
		return
	}
	if !info.Mode.IsRegular() {
		r.End(t, false, nil, abs+" is not a file")
		return
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	x := &transfer{id: id, path: abs, file: f, total: uint64(max(info.Size, 0)), sum: sha256.New(), end: make(chan struct{}), stream: stream}
	r.mu.Lock()
	t.xfer = x
	r.mu.Unlock()
	r.logf("task %s: sending %s (%d bytes) as transfer %s", hex.EncodeToString(t.id)[:8], abs, x.total, hex.EncodeToString(id)[:8])
	r.Nudge()

	select {
	case <-x.end:
	case <-ctx.Done():
		r.mu.Lock()
		x.finish("stopped")
		r.mu.Unlock()
	}
	r.mu.Lock()
	failed := x.err
	r.mu.Unlock()
	if failed != "" {
		r.End(t, false, nil, failed)
		return
	}
	if stream {
		r.mu.Lock()
		var sum []byte
		if !x.gap && x.hashed == x.total {
			sum = x.sum.Sum(nil)
		}
		r.mu.Unlock()
		r.Write(t, []byte(fmt.Sprintf("%s: %d bytes streamed\n", abs, x.total)),
			protocol.FileStream{Xfer: id, Path: abs, Size: x.total, SHA256: sum})
	} else {
		r.Write(t, nil, protocol.FileDownload{Xfer: id, Path: abs, Size: x.total, SHA256: x.sum.Sum(nil)})
	}
	r.End(t, true, nil, "")
}

// finish ends the transfer: err empty when core has the file. Under r.mu.
func (x *transfer) finish(err string) {
	if x.over {
		return
	}
	x.over, x.err = true, err
	close(x.end)
}

// sending: the transfer has a chunk to put in the next message.
func (x *transfer) sending() bool {
	return x != nil && !x.over && !x.waiting && !x.held
}

// chunk is the next chunk, of at most room bytes, read from the file and
// hashed on its first read. Under r.mu.
func (x *transfer) chunk(t *Task, room int) (protocol.ChunkItem, error) {
	if x.stream && !x.announced {
		// A stream announces the file first, without data, until core
		// acks it.
		total := x.total
		x.waiting = true
		return protocol.ChunkItem{T: protocol.ItemChunk, Xfer: x.id, Total: &total, Task: t.id, Name: x.path, Data: []byte{}}, nil
	}
	n := min(uint64(min(room, protocol.MaxChunkData)), x.total-x.acked)
	data := make([]byte, n)
	if _, err := x.file.ReadAt(data, int64(x.acked)); err != nil && !errors.Is(err, io.EOF) { //nolint:gosec // an offset within the file
		return protocol.ChunkItem{}, err
	} else if errors.Is(err, io.EOF) {
		return protocol.ChunkItem{}, fmt.Errorf("%s got shorter while sent", x.path)
	}
	if x.acked > x.hashed {
		// Read ahead of the hash (a stream resumed from further on): the
		// whole's SHA-256 is not known.
		x.gap = true
	}
	if end := x.acked + n; !x.gap && end > x.hashed {
		x.sum.Write(data[x.hashed-x.acked:])
		x.hashed = end
	}
	c := protocol.ChunkItem{T: protocol.ItemChunk, Xfer: x.id, Off: x.acked, Data: data}
	if x.acked == 0 {
		total := x.total
		c.Total, c.Task, c.Name = &total, t.id, x.path
	}
	if x.acked+n == x.total && !x.gap && x.hashed == x.total {
		c.SHA256 = x.sum.Sum(nil)
	}
	x.waiting = true
	return c, nil
}
