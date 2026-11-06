package minion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A minion that keeps nothing between calls (docs:
// contracts/channel-core-connections/, bind-call minions; the Dumbo page is
// one): core calls it with a message and it answers in the call, running
// the call's tasks as they come. What it needs to go on with a walk or a
// file travels in their ctx, which core echoes: a walk's part says where it
// stands and core resumes it; a file goes a chunk a call, each ack saying
// where to go on from. An agentless channel answers its bind-call targets
// so (docs: contracts/agentless-channels/).

// Caller answers core's calls to a minion that keeps nothing between them.
type Caller struct {
	// Host is what the call's commands act on.
	Host Host
	// Ops are the minion's commands, by number (op).
	Ops map[uint64]Command
	// MaxTasks is how many tasks a call may bring (each answer's
	// get_tasks); 0: DefaultCallTasks.
	MaxTasks uint64
	// Limit is the largest message the connection carries
	// (protocol.BuildConnection.MessageLimit); 0: the protocol's.
	Limit int
	// Hello is what a rehello gets; nil: nothing.
	Hello func() protocol.HelloItem
	// Logf logs a line; nil: nothing is logged.
	Logf func(format string, args ...any)
	// Acting is the task that made the session's identity, as the call
	// carries it (its acting): nil, the process's own.
	Acting []byte
}

// DefaultCallTasks is how many tasks a call may bring unless the Caller
// says.
const DefaultCallTasks = 4

// walkTime is the longest a call lists a walk's folders for: the rest goes
// in the calls after, as core resumes it.
const walkTime = 10 * time.Second

// callMargin is what a call keeps of its deadline to answer in.
const callMargin = 2 * time.Second

// lateStart is the least of its deadline a call has left for a task after
// its first: with less, the task waits for the next call, not acked, rather
// than run for a moment and fail.
const lateStart = callMargin + 3*time.Second

// Answer is the minion's answer to core's message: its items, the call's
// tasks run within ctx (the call's deadline). Tasks that do not fit the
// answer are not acked: core sends them again in the next call.
func (c *Caller) Answer(ctx context.Context, msg protocol.CoreMessage) []any {
	w := c.call(ctx)
	var out []any
	// The acks and identities go first, as they came: the session's identity
	// is for the tasks acked after it, so the tasks before it go in an ack
	// before it (docs: contracts/minion-messages/identity).
	var order []any
	var acks [][]byte
	took := 0
	for i, raw := range msg.Items {
		switch protocol.ItemType(raw) {
		case protocol.ItemRehello:
			if c.Hello != nil {
				out = w.add(out, c.Hello())
			}
		case protocol.ItemTask:
			var t protocol.TaskItem
			if protocol.UnmarshalCBOR(raw, &t) != nil || t.Validate() != nil {
				out = w.add(out, errAbout(protocol.ErrItemBadMessage, "the task does not read", i, nil))
				continue
			}
			if took > 0 && (w.used > w.room/2 || w.late()) {
				// Less than half the answer's room left, for a task whose
				// result may take as much, or too little of the call's
				// time for one to run: core sends it again, in the next
				// call.
				continue
			}
			took++
			// While the session runs as another user, as said, a command
			// that does not become says it runs as the login.
			cmd := c.Ops[t.Cmd]
			if cmd != CmdBecome && cmd != CmdUnbecome && !becomes(cmd) && w.said != nil {
				order = w.add(order, ownIdentity(protocol.IdentityTask, t.Task))
			}
			acks = append(acks, t.Task)
			items, id := w.runTask(t)
			if id != nil {
				if len(acks) > 0 {
					order = append(order, protocol.AckItem{T: protocol.ItemAck, Tasks: acks})
					acks = nil
				}
				order = w.add(order, *id)
				w.said = nil
				if id.How != 0 {
					w.said = id.Task
				}
			}
			out = w.add(out, items...)
		case protocol.ItemCancel:
			var x protocol.CancelItem
			if protocol.UnmarshalCBOR(raw, &x) != nil || x.Validate() != nil {
				out = w.add(out, errAbout(protocol.ErrItemBadMessage, "the cancel does not read", i, nil))
				continue
			}
			out = w.add(out, w.cancel(x, i)...)
		case protocol.ItemResume:
			var x protocol.ResumeItem
			if protocol.UnmarshalCBOR(raw, &x) != nil || x.Validate() != nil {
				out = w.add(out, errAbout(protocol.ErrItemBadMessage, "the resume does not read", i, nil))
				continue
			}
			out = w.add(out, w.resume(x, i)...)
		case protocol.ItemAck:
			// A transfer's (with xfer); core's acks of results say nothing
			// to a minion that keeps nothing.
			var x protocol.AckItem
			if protocol.UnmarshalCBOR(raw, &x) == nil && x.Validate() == nil && x.Xfer != nil {
				out = w.add(out, w.acked(x)...)
			}
		case protocol.ItemChunk:
			var x protocol.ChunkItem
			if protocol.UnmarshalCBOR(raw, &x) != nil || x.Validate() != nil {
				out = w.add(out, errAbout(protocol.ErrItemBadMessage, "the chunk does not read", i, nil))
				continue
			}
			out = w.add(out, w.chunk(x, i)...)
		case protocol.ItemErr:
			var x protocol.ErrItem
			if protocol.UnmarshalCBOR(raw, &x) == nil {
				w.refused(x)
			}
		case protocol.ItemHelloResponse:
		default:
			out = w.add(out, errAbout(protocol.ErrItemUnknownItem,
				fmt.Sprintf("this minion does not take %s", protocol.ItemName(protocol.ItemType(raw))), i, nil))
		}
	}
	if len(acks) > 0 {
		order = append(order, protocol.AckItem{T: protocol.ItemAck, Tasks: acks})
	}
	out = append(order, out...)
	most := c.MaxTasks
	if most == 0 {
		most = DefaultCallTasks
	}
	return append(out, protocol.GetTasksItem{T: protocol.ItemGetTasks, Max: &most})
}

// call is one call's answer under way.
type call struct {
	c     *Caller
	ctx   context.Context
	host  Host
	limit int
	// room is what the answer gives what the call's items say (results,
	// chunks); used is what they took so far.
	room, used int
	// folders are the folders a walk read in this call, by path: going
	// back up asks for them again.
	folders map[string][]Entry
	logf    func(format string, args ...any)
	// said is the session's identity as the call said it so far: the task
	// that made it (a become), nil the process's own.
	said []byte
}

// late reports whether too little of the call's deadline is left for
// another task to start.
func (w *call) late() bool {
	deadline, ok := w.ctx.Deadline()
	return ok && time.Until(deadline) < lateStart
}

func (c *Caller) call(ctx context.Context) *call {
	limit := c.Limit
	if limit <= 0 || limit > protocol.MaxMinionMessageSize {
		limit = protocol.MaxMinionMessageSize
	}
	logf := c.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &call{c: c, ctx: ctx, host: c.Host, limit: limit, room: limit * 2 / 3, folders: map[string][]Entry{}, logf: logf, said: c.Acting}
}

// add adds items to the answer, counting their size.
func (w *call) add(out []any, items ...any) []any {
	for _, it := range items {
		if b, err := protocol.MarshalCBOR(it); err == nil {
			w.used += len(b)
		}
	}
	return append(out, items...)
}

// chunkRoom is how much of a file the next chunk carries: as much as the
// answer has room for, 4 KiB at least so a transfer always moves on.
func (w *call) chunkRoom() int {
	return max(4<<10, min(protocol.MaxChunkData, w.limit*2/3, w.room-w.used))
}

// The answer's sizes, from the connection's: a listing says at most
// maxEntries entries (partial past it), a walk's part takes listings up to
// walkBytes.
func (w *call) maxEntries() int { return max(1, min(5000, w.limit/150)) }
func (w *call) walkBytes() int  { return min(600000, w.limit*4/5) }

func errAbout(code int, msg string, item int, task []byte) protocol.ErrItem {
	return protocol.ErrItem{T: protocol.ItemErr, Code: code, Msg: msg, Item: &item, Task: task}
}

// done is a task's one result, ended ok: its output and its data (one of
// core's results).
func done(task, out []byte, data any) protocol.ResultItem {
	ok := true
	r := protocol.ResultItem{T: protocol.ItemResult, Task: task, Done: true, OK: &ok, Out: out}
	if data != nil {
		if b, err := protocol.WireResultData(data); err == nil {
			r.Data = b
		}
	}
	return r
}

// failed is a task's one result, ended failed, saying why.
func failed(task []byte, why string) protocol.ResultItem {
	ok := false
	return protocol.ResultItem{T: protocol.ItemResult, Task: task, Done: true, OK: &ok, Err: why}
}

// runTask runs a task within the call: what it says now, and the session's
// identity when the task changed it (a become, an unbecome).
func (w *call) runTask(t protocol.TaskItem) ([]any, *protocol.IdentityItem) {
	switch w.c.Ops[t.Cmd] {
	case CmdBecome:
		text, id, errText := doBecome(w.ctx, w.host, t.Task, t.Args)
		if errText != "" {
			return []any{failed(t.Task, errText)}, nil
		}
		return []any{done(t.Task, []byte(text), nil)}, &id
	case CmdUnbecome:
		text, id, errText := doUnbecome(w.host, t.Task)
		if errText != "" {
			return []any{failed(t.Task, errText)}, nil
		}
		return []any{done(t.Task, []byte(text), nil)}, &id
	}
	return w.run(t), nil
}

// run runs a task within the call: what it says now (its result, or a
// transfer's first item).
func (w *call) run(t protocol.TaskItem) []any {
	w.logf("task %s: command %d", hex.EncodeToString(t.Task)[:8], t.Cmd)
	switch w.c.Ops[t.Cmd] {
	case CmdLs:
		return []any{w.ls(t)}
	case CmdRm:
		out, errText := removePath(w.host, t.Args)
		if errText != "" {
			return []any{failed(t.Task, errText)}
		}
		return []any{done(t.Task, []byte(out), nil)}
	case CmdShell:
		return w.shell(t)
	case CmdVolumes:
		return w.volumes(t)
	case CmdDownload:
		return w.startSend(t, false)
	case CmdStreamDownload:
		return w.startSend(t, true)
	case CmdUpload:
		return w.startReceive(t, false)
	case CmdStreamUpload:
		return w.startReceive(t, true)
	case CmdWalk:
		return w.startWalk(t)
	}
	return []any{failed(t.Task, fmt.Sprintf("command %d is not one this minion knows", t.Cmd))}
}

// ls lists a folder in one result: its entries in pieces, at most
// maxEntries of them (partial past it).
func (w *call) ls(t protocol.TaskItem) protocol.ResultItem {
	path, _ := protocol.ArgString(t.Args, ArgLsPath)
	if path == "" {
		path = "."
	}
	abs, err := w.host.Abs(path)
	if err != nil {
		return failed(t.Task, err.Error())
	}
	l := w.listing(abs, 0)
	if l.err != nil {
		r := failed(t.Task, l.err.Error())
		r.Ls = l.pieces
		return r
	}
	r := done(t.Task, nil, nil)
	r.Ls = l.pieces
	return r
}

// folderListing is a folder's listing in a call: its pieces, how many
// entries, the folders in it (links are not), and why it could not be read
// at all.
type folderListing struct {
	pieces  []protocol.LsPiece
	size    int
	entries int
	dirs    []Entry
	err     error
}

// listing lists the folder at abs (id: the listing's number in its task).
// One it may not read is a listing that says so; one that is gone, none.
func (w *call) listing(abs string, id uint64) folderListing {
	parent := w.host.Dir(abs)
	if parent == abs {
		parent = "" // a root
	}
	entries, err := w.host.ReadDir(abs)
	if err != nil && len(entries) == 0 {
		l := folderListing{err: err}
		if errors.Is(err, fs.ErrPermission) {
			l.pieces, _ = listingPieces(id, abs, w.host.Sep(), parent, nil, false, protocol.ListingErrDenied, w.limit/2)
		}
		return l
	}
	partial := err != nil
	if len(entries) > w.maxEntries() {
		entries, partial = entries[:w.maxEntries()], true
	}
	l := folderListing{entries: len(entries)}
	for _, e := range entries {
		if e.Type == protocol.EntryDir {
			l.dirs = append(l.dirs, e)
		}
	}
	slices.SortFunc(l.dirs, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	w.folders[abs] = l.dirs
	var sizes []int
	l.pieces, sizes = listingPieces(id, abs, w.host.Sep(), parent, entries, partial, 0, w.limit/2)
	for _, s := range sizes {
		l.size += s
	}
	return l
}

// capped keeps what is written to it up to most bytes, and says whether
// more came.
type capped struct {
	buf  bytes.Buffer
	most int
	cut  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if left := c.most - c.buf.Len(); left < len(p) {
		c.buf.Write(p[:max(left, 0)])
		c.cut = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

// shell runs a command within the call: its output in one result, as much
// as the answer has room for.
func (w *call) shell(t protocol.TaskItem) []any {
	most := time.Duration(0)
	if deadline, ok := w.ctx.Deadline(); ok {
		most = max(time.Until(deadline)-callMargin, time.Second)
	}
	out := &capped{most: max(1<<10, min(w.limit*2/3, w.room-w.used))}
	end := runShell(w.ctx, w.host, t.Args, most, out, nil)
	if out.cut {
		out.buf.WriteString("\n[the output goes on: cut to fit the answer]\n")
	}
	ok := end.ok
	r := protocol.ResultItem{T: protocol.ItemResult, Task: t.Task, Done: true, OK: &ok, Out: out.buf.Bytes(), Exit: end.exit, Err: end.err}
	var items []any
	if end.ran && !ranAsSaid(end.as, w.said) {
		// Ran as another than core took it to, when it was acked: who.
		items = append(items, ranIdentity(t.Task, end.as))
	}
	if end.notAs {
		// A minion that keeps nothing says it in the answer, once a
		// connection.
		if msg, first := becomeFailure(w.host); first {
			items = append(items, feedbackItem(protocol.FeedbackError, "become_failed", t.Task, msg))
		}
	}
	return append(items, r)
}

// feedbackItem is a warning or an error for the operators, in an answer.
func feedbackItem(level int, code string, task []byte, msg string) protocol.FeedbackItem {
	if len(msg) > protocol.MaxFeedbackMsg {
		msg = msg[:protocol.MaxFeedbackMsg-3] + "..."
	}
	f := protocol.FeedbackItem{T: protocol.ItemFeedback, ID: make([]byte, protocol.FeedbackIDSize), Level: level, Code: code,
		Task: task, Msg: msg, At: uint64(max(time.Now().Unix(), 0)), Count: 1}
	_, _ = rand.Read(f.ID)
	return f
}

// volumes lists the host's volumes within the call: parts of half a
// message each, the last ending the task.
func (w *call) volumes(t protocol.TaskItem) []any {
	vols, err := w.host.Volumes()
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	parts := volumeParts(vols, w.host.Sep(), w.limit/2)
	out := make([]any, 0, len(parts))
	for i, p := range parts {
		r := protocol.ResultItem{T: protocol.ItemResult, Task: t.Task, Seq: uint64(i)} //nolint:gosec // a small count
		if b, err := protocol.WireResultData(p); err == nil {
			r.Data = b
		}
		if i == len(parts)-1 {
			ok := true
			r.Done, r.OK = true, &ok
		}
		out = append(out, r)
	}
	return out
}

// callCtx is what a minion that keeps nothing needs to go on with a task,
// in its transfer's or its part's ctx, which core echoes.
type callCtx struct {
	// Kind: kindSend, kindStream, kindReceive, kindReceiveStream, kindWalk.
	Kind string `cbor:"1,keyasint"`
	// Path is the file sent, the file a transfer puts in place, or the
	// walk's own folder.
	Path string `cbor:"2,keyasint"`
	Task []byte `cbor:"3,keyasint"`
	// Size is the file's (0 for a stream to the minion, until its first
	// chunk says it).
	Size uint64 `cbor:"4,keyasint,omitempty"`
	// Tmp is where a file core sends is written until whole; Want its
	// SHA-256, as core said it.
	Tmp  string `cbor:"5,keyasint,omitempty"`
	Want []byte `cbor:"6,keyasint,omitempty"`
	// Hashed is how far Sum (a SHA-256's state) has hashed the file in
	// order; Gap: it missed bytes, so the file is hashed again at the end.
	Hashed uint64 `cbor:"7,keyasint,omitempty"`
	Sum    []byte `cbor:"8,keyasint,omitempty"`
	Gap    bool   `cbor:"9,keyasint,omitempty"`

	// A walk's: the folder it listed last (from Path; "" for Path itself),
	// the next part's seq, its counts, and what it enters.
	Last       string `cbor:"10,keyasint,omitempty"`
	Seq        uint64 `cbor:"11,keyasint,omitempty"`
	Folders    uint64 `cbor:"12,keyasint,omitempty"`
	Entries    uint64 `cbor:"13,keyasint,omitempty"`
	Unread     uint64 `cbor:"14,keyasint,omitempty"`
	Skipped    uint64 `cbor:"15,keyasint,omitempty"`
	Depth      int64  `cbor:"16,keyasint,omitempty"`
	MaxFolders int64  `cbor:"17,keyasint,omitempty"`
	NoHidden   bool   `cbor:"18,keyasint,omitempty"`
	AnyFS      bool   `cbor:"19,keyasint,omitempty"`
	Dev        uint64 `cbor:"20,keyasint,omitempty"`
	HasDev     bool   `cbor:"21,keyasint,omitempty"`
}

const (
	kindSend          = "d"
	kindStream        = "s"
	kindReceive       = "u"
	kindReceiveStream = "v"
	kindWalk          = "w"
)

// errCtxTooLong: what a task needs to go on does not fit a ctx (a path too
// long).
var errCtxTooLong = errors.New("too long to go on from")

func (x callCtx) encode() ([]byte, error) {
	b, err := protocol.MarshalCBOR(x)
	if err != nil {
		return nil, err
	}
	if len(b) > protocol.MaxTransferCtx {
		return nil, errCtxTooLong
	}
	return b, nil
}

// readCtx is what a ctx core echoed says; false for none, or one that is
// not this minion's.
func readCtx(b []byte) (callCtx, bool) {
	var x callCtx
	if len(b) == 0 || protocol.UnmarshalCBOR(b, &x) != nil || len(x.Task) != 16 || x.Path == "" {
		return x, false
	}
	return x, true
}

// hashOn hashes data, the file's from off, when it follows what the ctx
// hashed; a gap otherwise (a part sent again is already in).
func (x *callCtx) hashOn(off uint64, data []byte) {
	if x.Gap || off+uint64(len(data)) <= x.Hashed {
		return
	}
	if off != x.Hashed {
		x.Gap = true
		return
	}
	h := sha256.New()
	if len(x.Sum) > 0 {
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(x.Sum); err != nil {
			x.Gap = true
			return
		}
	}
	h.Write(data)
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		x.Gap = true
		return
	}
	x.Sum, x.Hashed = state, off+uint64(len(data))
}

// sum is the SHA-256 of the file at path, size bytes: from the ctx's
// state when it hashed all of it in order, read again otherwise.
func (w *call) sum(x callCtx, path string, size uint64) ([]byte, error) {
	if !x.Gap && x.Hashed == size {
		h := sha256.New()
		if len(x.Sum) > 0 {
			if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(x.Sum); err != nil {
				return w.hashFile(path)
			}
		}
		return h.Sum(nil), nil
	}
	return w.hashFile(path)
}

func (w *call) hashFile(path string) ([]byte, error) {
	f, err := w.host.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read only: nothing to lose on close
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<62)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// startSend sends a file core asked for: its first chunk now (download),
// or a stream's announcement, a first chunk without data, until core lets
// it go (stream_download).
func (w *call) startSend(t protocol.TaskItem, stream bool) []any {
	path, _ := protocol.ArgString(t.Args, ArgDownloadPath)
	if path == "" {
		return []any{failed(t.Task, "no path")}
	}
	abs, err := w.host.Abs(path)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	info, err := w.host.Stat(abs)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	if !info.Mode.IsRegular() {
		return []any{failed(t.Task, abs+" is not a file")}
	}
	x := callCtx{Kind: kindSend, Path: abs, Task: t.Task, Size: uint64(max(info.Size, 0))}
	xfer := make([]byte, 16)
	_, _ = rand.Read(xfer)
	if stream {
		x.Kind = kindStream
		ctx, err := x.encode()
		if err != nil {
			return []any{failed(t.Task, "the path is too long to send")}
		}
		total := x.Size
		return []any{protocol.ChunkItem{T: protocol.ItemChunk, Xfer: xfer, Data: []byte{}, Total: &total, Task: t.Task, Name: abs, Ctx: ctx}}
	}
	c, err := w.fileChunk(xfer, x, 0)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	return []any{c}
}

// fileChunk is the chunk of the file the ctx sends from off: a first
// chunk (from 0) says the file's size, task and path, the last its
// SHA-256.
func (w *call) fileChunk(xfer []byte, x callCtx, off uint64) (protocol.ChunkItem, error) {
	n := min(uint64(w.chunkRoom()), x.Size-off) //nolint:gosec // a positive room
	data := make([]byte, n)
	if n > 0 {
		f, err := w.host.Open(x.Path)
		if err != nil {
			return protocol.ChunkItem{}, err
		}
		_, err = f.ReadAt(data, int64(off)) //nolint:gosec // an offset within the file
		_ = f.Close()                       // read only: nothing to lose on close
		if errors.Is(err, io.EOF) {
			return protocol.ChunkItem{}, fmt.Errorf("%s got shorter while sent", x.Path)
		}
		if err != nil {
			return protocol.ChunkItem{}, err
		}
	}
	x.hashOn(off, data)
	c := protocol.ChunkItem{T: protocol.ItemChunk, Xfer: xfer, Off: off, Data: data}
	if off == 0 {
		total := x.Size
		c.Total, c.Task, c.Name = &total, x.Task, x.Path
	}
	if off+n == x.Size {
		sum, err := w.sum(x, x.Path, x.Size)
		if err != nil {
			return protocol.ChunkItem{}, err
		}
		c.SHA256 = sum
	}
	ctx, err := x.encode()
	if err != nil {
		return protocol.ChunkItem{}, errors.New("the path is too long to send")
	}
	c.Ctx = ctx
	return c, nil
}

// acked goes on with a transfer core acked: the file core sends gets the
// next chunk it asks for, or its end once core has every byte; a stream
// held waits (core calls again when it may go on); a stream to the minion
// is asked for from where the minion has it.
func (w *call) acked(a protocol.AckItem) []any {
	x, ok := readCtx(a.Ctx)
	if !ok || a.Hold || a.Next == nil {
		return nil
	}
	next := *a.Next
	switch x.Kind {
	case kindSend, kindStream:
		if next >= x.Size {
			sum, err := w.sum(x, x.Path, x.Size)
			if err != nil {
				return []any{failed(x.Task, x.Path+" changed or is gone while it was sent: "+err.Error())}
			}
			if x.Kind == kindStream {
				return []any{done(x.Task, []byte(fmt.Sprintf("%s: %d bytes streamed\n", x.Path, x.Size)),
					protocol.FileStream{Xfer: a.Xfer, Path: x.Path, Size: x.Size, SHA256: sum})}
			}
			return []any{done(x.Task, nil, protocol.FileDownload{Xfer: a.Xfer, Path: x.Path, Size: x.Size, SHA256: sum})}
		}
		c, err := w.fileChunk(a.Xfer, x, next)
		if err != nil {
			return []any{failed(x.Task, x.Path+" changed or is gone while it was sent: "+err.Error())}
		}
		return []any{c}
	case kindReceiveStream:
		// Bytes came for a stream to the minion: it asks for them, from
		// where it has the file.
		info, err := w.host.Stat(x.Tmp)
		if err != nil {
			return nil // its task ended
		}
		have := uint64(max(info.Size, 0))
		return []any{protocol.AckItem{T: protocol.ItemAck, Xfer: a.Xfer, Next: &have, Ctx: a.Ctx}}
	}
	return nil
}

// startReceive gets ready to put a file core sends on the host (upload),
// or streams (stream_upload): a temporary file beside where it goes, then
// the ask for its first chunk.
func (w *call) startReceive(t protocol.TaskItem, stream bool) []any {
	fileArg, pathArg, overwriteArg := uint64(ArgUploadFile), uint64(ArgUploadPath), uint64(ArgUploadOverwrite)
	if stream {
		fileArg, pathArg, overwriteArg = ArgStreamUploadStream, ArgStreamUploadPath, ArgStreamUploadOverwrite
	}
	offer, err := protocol.ArgFile(t.Args, fileArg)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	if offer.Stream != stream {
		return []any{failed(t.Task, "core sent a stream where a file was wanted, or the other way round")}
	}
	path, _ := protocol.ArgString(t.Args, pathArg)
	overwrite, _ := t.Args[overwriteArg].(bool)
	if path == "" {
		return []any{failed(t.Task, "no path")}
	}
	abs, err := w.host.Abs(path)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	if info, err := w.host.Stat(abs); err == nil && info.IsDir() {
		abs = w.host.Join(abs, w.host.Base(offer.Name))
	}
	switch info, err := w.host.Lstat(abs); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return []any{failed(t.Task, err.Error())}
	case !info.Mode.IsRegular():
		return []any{failed(t.Task, fmt.Sprintf("%s exists and is not a file", abs))}
	case !overwrite:
		return []any{failed(t.Task, fmt.Sprintf("%s exists", abs))}
	}
	dir := w.host.Dir(abs)
	tmp := w.host.Join(dir, "."+w.host.Base(abs)+"."+hex.EncodeToString(offer.Xfer[:4])+".part")
	x := callCtx{Kind: kindReceive, Path: abs, Task: t.Task, Size: offer.Size, Tmp: tmp, Want: offer.SHA256}
	if stream {
		x.Kind, x.Size = kindReceiveStream, 0
	}
	ctx, err := x.encode()
	if err != nil {
		return []any{failed(t.Task, "the path is too long")}
	}
	if err := w.host.WriteAt(tmp, 0, nil, true); err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	w.logf("task %s: receiving %d bytes in transfer %s", hex.EncodeToString(t.Task)[:8], offer.Size, hex.EncodeToString(offer.Xfer)[:8])
	if !stream && offer.Size == 0 {
		return w.place(offer.Xfer, x, offer.SHA256, 0)
	}
	zero := uint64(0)
	return []any{protocol.AckItem{T: protocol.ItemAck, Xfer: offer.Xfer, Next: &zero, Ctx: ctx}}
}

// chunk writes a chunk of a file core sends where its temporary file ends
// (one sent again, or out of order, is written once), and asks for the
// next, or puts the file in place once whole.
func (w *call) chunk(c protocol.ChunkItem, item int) []any {
	x, ok := readCtx(c.Ctx)
	if !ok || (x.Kind != kindReceive && x.Kind != kindReceiveStream) || x.Tmp == "" {
		return []any{errAbout(protocol.ErrItemBadMessage, "a chunk the minion did not ask for", item, nil)}
	}
	info, err := w.host.Stat(x.Tmp)
	if err != nil {
		return []any{failed(x.Task, "its temporary file is gone")}
	}
	have := uint64(max(info.Size, 0))
	if c.Off == have && len(c.Data) > 0 {
		if err := w.host.WriteAt(x.Tmp, int64(have), c.Data, false); err != nil { //nolint:gosec // an offset within the file
			_ = w.host.Remove(x.Tmp)
			return []any{failed(x.Task, "the file does not write: "+err.Error())}
		}
		x.hashOn(have, c.Data)
		have += uint64(len(c.Data))
	}
	ask := func() []any {
		next := have
		ctx, err := x.encode()
		if err != nil {
			ctx = c.Ctx
		}
		return []any{protocol.AckItem{T: protocol.ItemAck, Xfer: c.Xfer, Next: &next, Ctx: ctx}}
	}
	if x.Kind == kindReceiveStream {
		// A stream's size comes with its first chunk, its SHA-256 with its
		// last: of all core passed on.
		if c.Total != nil {
			x.Size = *c.Total
		}
		last := c.SHA256 != nil && c.Off+uint64(len(c.Data)) == have
		empty := c.Total != nil && *c.Total == 0 && have == 0
		if !last && !empty {
			return ask()
		}
		want := c.SHA256
		if empty {
			sum := sha256.Sum256(nil)
			want = sum[:]
		}
		return w.place(c.Xfer, x, want, have)
	}
	if have < x.Size {
		return ask()
	}
	return w.place(c.Xfer, x, x.Want, x.Size)
}

// place checks a whole file core sent and moves it into place: the last
// ack (the minion has every byte) and the task's end.
func (w *call) place(xfer []byte, x callCtx, want []byte, size uint64) []any {
	ctx, _ := x.encode()
	last := protocol.AckItem{T: protocol.ItemAck, Xfer: xfer, Next: &size, Ctx: ctx}
	sum, err := w.sum(x, x.Tmp, size)
	if err != nil || !bytes.Equal(sum, want) {
		_ = w.host.Remove(x.Tmp)
		return []any{last, failed(x.Task, "the file's SHA-256 is not the one core said")}
	}
	mode := fs.FileMode(0o644)
	if info, err := w.host.Stat(x.Path); err == nil {
		mode = info.Mode.Perm()
	}
	if err := w.host.Chmod(x.Tmp, mode); err != nil {
		_ = w.host.Remove(x.Tmp)
		return []any{last, failed(x.Task, err.Error())}
	}
	if err := w.host.Rename(x.Tmp, x.Path); err != nil {
		_ = w.host.Remove(x.Tmp)
		return []any{last, failed(x.Task, err.Error())}
	}
	return []any{last, done(x.Task, []byte(fmt.Sprintf("%s: %d bytes\n", x.Path, size)),
		protocol.FileUpload{Xfer: xfer, Path: x.Path, Size: size, SHA256: sum})}
}

// cancel ends a task an operator stopped, from what its ctx says: a file
// core sends loses what came of it; a walk ends where it stood. Any other
// ended within its call already: core hears that the minion has no such
// task, and ends it.
func (w *call) cancel(c protocol.CancelItem, item int) []any {
	x, ok := readCtx(c.Ctx)
	switch {
	case ok && (x.Kind == kindReceive || x.Kind == kindReceiveStream):
		had := "nothing"
		if info, err := w.host.Stat(x.Tmp); err == nil {
			had = fmt.Sprintf("%d bytes", info.Size)
			if x.Kind == kindReceive {
				had = fmt.Sprintf("%d of %d bytes", info.Size, x.Size)
			}
		}
		_ = w.host.Remove(x.Tmp)
		return []any{failed(x.Task, "stopped: "+had+" had come; the partial file is removed")}
	case ok && (x.Kind == kindSend || x.Kind == kindStream):
		return []any{failed(x.Task, "stopped")}
	case ok && x.Kind == kindWalk:
		ok := false
		r := protocol.ResultItem{T: protocol.ItemResult, Task: x.Task, Seq: x.Seq, Done: true, OK: &ok, Err: "stopped"}
		if b, err := protocol.WireResultData(x.walked()); err == nil {
			r.Data = b
		}
		return []any{r}
	}
	return []any{errAbout(protocol.ErrItemUnknownTask, "no such task: this minion runs its tasks within the call", item, c.Task)}
}

// refused: core refused an item of the minion's about a file going to it
// (an ack asking for a chunk); its ctx says where the partial file is,
// removed as a stop removes it. Core ends the task.
func (w *call) refused(e protocol.ErrItem) {
	if x, ok := readCtx(e.Ctx); ok && (x.Kind == kindReceive || x.Kind == kindReceiveStream) && x.Tmp != "" {
		_ = w.host.Remove(x.Tmp)
	}
}

// startWalk starts a walk (walk_dir) in this call. A walk goes depth first,
// folders in name order, so where it stands is one folder: the last it
// listed. Each call lists folders while its answer stays within walkBytes
// and walkTime, then hands over a part with the walk's ctx; core answers
// with a resume giving it back, and the next call goes on from the folder
// after it. Links are never followed; depth, hidden and one_fs say which
// folders it enters, max_folders when it stops (0: no limit).
func (w *call) startWalk(t protocol.TaskItem) []any {
	path, _ := protocol.ArgString(t.Args, ArgWalkPath)
	if path == "" {
		path = "."
	}
	root, err := w.host.Abs(path)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	info, err := w.host.Stat(root)
	if err != nil {
		return []any{failed(t.Task, err.Error())}
	}
	if !info.IsDir() {
		return []any{failed(t.Task, root+" is not a directory")}
	}
	depth, _ := protocol.ArgInt(t.Args, ArgWalkDepth)
	most, _ := protocol.ArgInt(t.Args, ArgWalkMaxFolders)
	x := callCtx{Kind: kindWalk, Path: root, Task: t.Task, Depth: max(depth, 0), MaxFolders: max(most, 0),
		NoHidden: !argBool(t.Args, ArgWalkHidden, true), AnyFS: !argBool(t.Args, ArgWalkOneFS, true), Dev: info.Dev, HasDev: info.HasDev}
	return []any{w.walk(x, "", false)}
}

// resume goes on with a walk core gave back where it stood.
func (w *call) resume(r protocol.ResumeItem, item int) []any {
	x, ok := readCtx(r.Ctx)
	if !ok || x.Kind != kindWalk {
		return []any{errAbout(protocol.ErrItemBadMessage, "a resume the minion cannot go on from", item, nil)}
	}
	next, more := w.nextFolder(x, x.Last)
	return []any{w.walk(x, next, !more)}
}

// walked is where a walk stands, as its data says it.
func (x callCtx) walked() protocol.DirWalk {
	return protocol.DirWalk{Root: x.Path, Folders: x.Folders, Entries: x.Entries, Unread: x.Unread, Skipped: x.Skipped}
}

// walk lists from the folder cur (relative to the walk's own; finished: no
// folder left) and says the part.
func (w *call) walk(x callCtx, cur string, finished bool) protocol.ResultItem {
	start := time.Now()
	stop := start.Add(walkTime)
	if deadline, ok := w.ctx.Deadline(); ok && deadline.Add(-callMargin).Before(stop) {
		stop = deadline.Add(-callMargin)
	}
	var pieces []protocol.LsPiece
	size := 0
	last := x.Last
	for {
		if finished || (x.MaxFolders > 0 && int64(x.Folders) >= x.MaxFolders) { //nolint:gosec // a count of folders
			finished = true
			break
		}
		if len(pieces) > 0 && !time.Now().Before(stop) {
			break
		}
		abs := w.walkPath(x, cur)
		l := w.listing(abs, x.Folders)
		// A folder that would take the answer past walkBytes goes in the
		// next call; one alone always goes.
		if len(pieces) > 0 && size+l.size > w.walkBytes() {
			break
		}
		x.Folders++
		x.Entries += uint64(l.entries) //nolint:gosec // a count of entries
		if l.err != nil {
			x.Unread++
		}
		for _, d := range l.dirs {
			if !w.enters(x, w.relPath(cur, d.Name), d) {
				x.Skipped++
			}
		}
		pieces = append(pieces, l.pieces...)
		size += l.size
		last = cur
		next, more := w.nextFolder(x, cur)
		cur, finished = next, !more
	}
	data := x.walked()
	part := protocol.ResultItem{T: protocol.ItemResult, Task: x.Task, Seq: x.Seq, Ls: pieces}
	if finished {
		ok := true
		part.Done, part.OK = true, &ok
		if b, err := protocol.WireResultData(data); err == nil {
			part.Data = b
		}
		return part
	}
	data.Current = w.walkPath(x, cur)
	if b, err := protocol.WireResultData(data); err == nil {
		part.Data = b
	}
	x.Last, x.Seq = last, x.Seq+1
	ctx, err := x.encode()
	if err != nil {
		// Where it stands no longer fits a ctx (a path too long): it ends
		// here, said so.
		ok := false
		part.Done, part.OK, part.Err = true, &ok, "the walk stops: a folder's path is too long to go on from"
		return part
	}
	part.Ctx = ctx
	return part
}

// walkPath is the folder rel of the walk, absolute.
func (w *call) walkPath(x callCtx, rel string) string {
	if rel == "" {
		return x.Path
	}
	return w.host.Join(x.Path, rel)
}

// relPath is name in the folder rel, from the walk's own.
func (w *call) relPath(rel, name string) string {
	if rel == "" {
		return name
	}
	return rel + w.host.Sep() + name
}

// enters: the walk goes into the folder d at rel: not deeper than it goes,
// not hidden when not asked into them, on the walk's file system when it
// stays on one.
func (w *call) enters(x callCtx, rel string, d Entry) bool {
	if d.Type != protocol.EntryDir {
		return false
	}
	if x.Depth > 0 && int64(strings.Count(rel, w.host.Sep())+1) > x.Depth {
		return false
	}
	if x.NoHidden && d.Hidden {
		return false
	}
	if !x.AnyFS && x.HasDev && d.HasDev && d.Dev != x.Dev {
		return false
	}
	return true
}

// subdirs are the folders in the folder rel, in name order: read once a
// call, as going back up asks for the same ones again.
func (w *call) subdirs(x callCtx, rel string) []Entry {
	abs := w.walkPath(x, rel)
	if dirs, ok := w.folders[abs]; ok {
		return dirs
	}
	entries, _ := w.host.ReadDir(abs)
	var dirs []Entry
	for _, e := range entries {
		if e.Type == protocol.EntryDir {
			dirs = append(dirs, e)
		}
	}
	slices.SortFunc(dirs, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	w.folders[abs] = dirs
	return dirs
}

// nextFolder is the folder after rel in the walk's order: the first in it
// the walk enters, else the next of its own folder's, or of the one above;
// false when none is left.
func (w *call) nextFolder(x callCtx, rel string) (string, bool) {
	for _, d := range w.subdirs(x, rel) {
		if child := w.relPath(rel, d.Name); w.enters(x, child, d) {
			return child, true
		}
	}
	sep := w.host.Sep()
	for rel != "" {
		parent, name := "", rel
		if i := strings.LastIndex(rel, sep); i >= 0 {
			parent, name = rel[:i], rel[i+len(sep):]
		}
		for _, d := range w.subdirs(x, parent) {
			if d.Name > name {
				if next := w.relPath(parent, d.Name); w.enters(x, next, d) {
					return next, true
				}
			}
		}
		rel = parent
	}
	return "", false
}
