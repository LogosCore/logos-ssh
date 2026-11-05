package minion

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Tasks (docs: contracts/minion-messages/tasks-and-results): the minion
// asks for tasks while it has room for them, acks each, runs it in the
// background and sends its output as result parts: formed for each message
// from what the task wrote since, so a message that fails is sent again as
// it was ((task, seq) stays the same). A task id it saw in the last 24 hours
// runs once.

// maxOutPerMessage keeps a message's output well under the 768 KiB limit;
// the rest goes in the next messages, which come at once. A connection that
// carries less (its channel's max_message, BuildConnection.MaxMessage) gets
// two thirds of what it carries (perMessageLocked).
const maxOutPerMessage = 512 << 10

// lsChunk is how many folder entries one listing piece carries at most: a
// big folder goes in pieces (docs: contracts/minion-messages/tasks-and-results,
// Listings), several to a result part while the message has room, and a
// piece is cut sooner when its entries would not fit half a message.
const lsChunk = 500

// taskMemory is how long the runner remembers a task id.
const taskMemory = 24 * time.Hour

// Task is a task the runner runs: its output not yet sent, and how it ended.
type Task struct {
	id      []byte
	cmd     uint64
	nextSeq uint64
	out     []byte
	// chunks are structured output not yet sent, a result part each,
	// encoded (protocol.ResultData).
	chunks [][]byte
	// pieces are listings not yet sent, with their encoded sizes; listings
	// the task has started, numbering the next.
	pieces   []protocol.LsPiece
	sizes    []int
	listings uint64
	ended    bool
	ok       bool
	exit     *int64
	err      string
	sentEnd  bool
	cancel   context.CancelFunc
	// xfer is the file a download sends (download.go); nil for others.
	xfer *transfer
	// recv is the file an upload receives (upload.go); nil for others.
	recv *receiving
}

// ID is the task's id, 16 bytes.
func (t *Task) ID() []byte { return t.id }

// Config is what a runner runs with.
type Config struct {
	// Host is what the runner's commands act on.
	Host Host
	// Ops are the minion's commands, by number (op): a task of another
	// fails, saying so.
	Ops map[uint64]Command
	// MaxTasks is how many tasks the runner runs at once as it starts; core
	// changes it live (a max_tasks item).
	MaxTasks uint64
	// Feedback is the queue the runner sends feedback from, first in each
	// message, and reports its own into (a command that panics); nil: none.
	Feedback *Feedback
	// Hello is what a rehello gets: the minion's hello, said again, with
	// the limit of tasks it has now. Nil: a rehello gets nothing.
	Hello func() protocol.HelloItem
	// Logf logs a line; nil: nothing is logged.
	Logf func(format string, args ...any)
}

// Runner holds the tasks of a session and what the next message says.
type Runner struct {
	mu       sync.Mutex
	host     Host
	ops      map[uint64]Command
	feedback *Feedback
	logf     func(format string, args ...any)
	seen     map[string]time.Time
	acks     [][]byte
	errs     []protocol.ErrItem
	tasks    []*Task
	// inflight is the last message's items when it failed: sent again first.
	inflight []any
	wake     chan struct{}
	// limit is the largest message the connection in use carries
	// (protocol.BuildConnection.MessageLimit), set by the program around the
	// runner: what the next message keeps within.
	limit int
	// poll is how soon core asked the minion to come back (a poll item: a
	// stream of its may go on any moment); 0 for none. It holds until the
	// next message goes.
	poll time.Duration
	// helloAsked: core asked for a hello (rehello); hello makes it.
	helloAsked bool
	// afterHello: the hello went alone, as a rehello's answer; the rest
	// goes in the next message.
	afterHello bool
	hello      func() protocol.HelloItem
	// maxTasks is how many tasks it runs at once: the build's, then core's
	// (a max_tasks); maxTasksSay: core's came, and the next message says
	// the minion has it. persistent: the connection in use stays open, so
	// a get_tasks is a standing allowance there, not this message's.
	maxTasks    uint64
	maxTasksSay bool
	persistent  bool
	// exec carries out a task's command: run, but in tests.
	exec func(ctx context.Context, t *Task, ti protocol.TaskItem)
}

// NewRunner is a runner for a session, with nothing to send yet.
func NewRunner(cfg Config) *Runner {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Runner{host: cfg.Host, ops: cfg.Ops, feedback: cfg.Feedback, logf: logf,
		seen: map[string]time.Time{}, wake: make(chan struct{}, 1), hello: cfg.Hello, maxTasks: min(cfg.MaxTasks, protocol.MaxTasksLimit)}
}

// SetLimit says the largest message the connection in use carries.
func (r *Runner) SetLimit(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limit = n
}

// perMessageLocked is the room a message gives output, data, listings and
// a chunk: two thirds of what the connection carries, maxOutPerMessage at
// most, leaving the rest to acks, errs and the message's own keys.
func (r *Runner) perMessageLocked() int {
	if r.limit <= 0 {
		return maxOutPerMessage
	}
	return min(maxOutPerMessage, r.limit*2/3)
}

// SetPersistent says whether the connection in use stays open (a
// WebSocket, a TCP connection): a get_tasks is a standing allowance there.
func (r *Runner) SetPersistent(p bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.persistent = p
}

// MaxTasks is how many tasks the runner runs at once now.
func (r *Runner) MaxTasks() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.maxTasks
}

// Nudge asks for an early message: there is something to send.
// AskHello has the next message say the minion's hello, as a rehello does:
// how a persistent connection starts, the minion speaking first.
func (r *Runner) AskHello() {
	r.mu.Lock()
	r.helloAsked = true
	r.mu.Unlock()
	r.Nudge()
}

func (r *Runner) Nudge() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Wake fires when the runner has something to send sooner than the
// program's schedule.
func (r *Runner) Wake() <-chan struct{} { return r.wake }

// Pending reports whether something waits to be sent.
func (r *Runner) Pending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.inflight) > 0 || len(r.acks) > 0 || len(r.errs) > 0 || r.helloAsked || r.afterHello || r.maxTasksSay {
		return true
	}
	if r.feedback.Pending() {
		return true
	}
	for _, t := range r.tasks {
		if len(t.out) > 0 || len(t.chunks) > 0 || len(t.pieces) > 0 || (t.ended && !t.sentEnd) || t.xfer.sending() || t.recv.asking() || t.recv.telling() {
			return true
		}
	}
	return false
}

// Outgoing is the next message's items: the failed message's again, or a
// hello core asked for, acks, errs, feedback, output,
// a file's next chunk, asks for a file core sends, a max_tasks (core set
// the limit), and a get_tasks while the limit leaves room.
func (r *Runner) Outgoing() []any {
	r.mu.Lock()
	defer r.mu.Unlock()
	// The wait core asked for was for this message.
	r.poll = 0
	if len(r.inflight) > 0 {
		return r.inflight
	}
	var items []any
	if r.helloAsked && r.hello != nil {
		// With the limit it has now (core's, if core set one): said here,
		// under the lock the closure must not take.
		h := r.hello()
		n := r.maxTasks
		h.MaxTasks = &n
		// Alone: before the minion has a session it speaks under the build
		// id, where core takes no other item with a hello
		// (protocol.ValidateBuildMessage). The rest goes in the next
		// message, under the session id the hello_response gives.
		r.helloAsked, r.afterHello = false, true
		return []any{h}
	}
	r.helloAsked, r.afterHello = false, false
	if len(r.acks) > 0 {
		items = append(items, protocol.AckItem{T: protocol.ItemAck, Tasks: r.acks})
		r.acks = nil
	}
	for _, e := range r.errs {
		items = append(items, e)
	}
	r.errs = nil
	// Feedback first, in the room a message has (most of it, to leave the
	// tasks theirs), then parts while the message has room: output, then a
	// chunk of data each, then listing pieces, as many to a part as fit.
	full := r.perMessageLocked()
	room := full
	if fb, left := r.feedback.Take(full/2, true); len(fb) > 0 {
		for _, f := range fb {
			items = append(items, f)
		}
		room = max(full-(full/2-left), 0)
	}
parts:
	for _, t := range r.tasks {
		for !t.sentEnd && (len(t.out) > 0 || len(t.chunks) > 0 || len(t.pieces) > 0 || t.ended) {
			part := protocol.ResultItem{T: protocol.ItemResult, Task: t.id, Seq: t.nextSeq}
			if len(t.out) > 0 {
				n := min(len(t.out), room)
				if n == 0 {
					break parts
				}
				part.Out, t.out, room = t.out[:n], t.out[n:], room-n
			} else if len(t.chunks) > 0 {
				size := len(t.chunks[0])
				if size > room && room < full {
					break parts // the next message, which comes at once
				}
				part.Data, t.chunks, room = t.chunks[0], t.chunks[1:], max(room-size, 0)
			} else if len(t.pieces) > 0 {
				for len(t.pieces) > 0 && (t.sizes[0] <= room || (len(part.Ls) == 0 && room == full)) {
					part.Ls = append(part.Ls, t.pieces[0])
					room = max(room-t.sizes[0], 0)
					t.pieces, t.sizes = t.pieces[1:], t.sizes[1:]
				}
				if len(part.Ls) == 0 {
					break parts // the next message, which comes at once
				}
			}
			if t.ended && len(t.out) == 0 && len(t.chunks) == 0 && len(t.pieces) == 0 {
				ok := t.ok
				part.Done, part.OK, part.Exit, part.Err = true, &ok, t.exit, t.err
				t.sentEnd = true
			}
			t.nextSeq++
			items = append(items, part)
			if room == 0 {
				break parts
			}
		}
	}
	// A file's next chunk, one per message, in the room left.
	for _, t := range r.tasks {
		if !t.xfer.sending() || room == 0 {
			continue
		}
		c, err := t.xfer.chunk(t, room)
		if err != nil {
			t.xfer.finish(err.Error())
			continue
		}
		items = append(items, c)
		room -= len(c.Data)
	}
	// A file core sends: the ask for its next chunk, which core's answer
	// brings.
	for _, t := range r.tasks {
		if t.recv.asking() || t.recv.telling() {
			items = append(items, t.recv.ask())
		}
	}
	// The limit core set, said back: core sends it until the minion has it.
	if r.maxTasksSay {
		items = append(items, protocol.MaxTasksItem{T: protocol.ItemMaxTasks, Max: r.maxTasks})
		r.maxTasksSay = false
	}
	// Tasks, as many as the limit leaves room for. On a persistent
	// connection the limit itself: a standing allowance, which core counts
	// the tasks under way against. Through a call, this message's: the
	// room left (none asked when there is none).
	if r.persistent {
		most := r.maxTasks
		items = append(items, protocol.GetTasksItem{T: protocol.ItemGetTasks, Max: &most})
	} else if room := r.roomLocked(); room > 0 {
		items = append(items, protocol.GetTasksItem{T: protocol.ItemGetTasks, Max: &room})
	}
	return items
}

// roomLocked is how many more tasks the limit leaves room for: the limit
// less the tasks whose end has not gone yet.
func (r *Runner) roomLocked() uint64 {
	running := uint64(0)
	for _, t := range r.tasks {
		if !t.sentEnd {
			running++
		}
	}
	if running >= r.maxTasks {
		return 0
	}
	return r.maxTasks - running
}

// Delivered says the last message went through: tasks whose end it carried
// are done with.
func (r *Runner) Delivered() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight = nil
	r.tasks = slices.DeleteFunc(r.tasks, func(t *Task) bool { return t.sentEnd })
	// A chunk delivered: the next goes from where core's ack says, taken
	// with the answer; none said, this one again.
	for _, t := range r.tasks {
		if t.xfer != nil {
			t.xfer.waiting = false
		}
	}
	// An ask answered by no chunk (core had no room in its reply) is asked
	// again; Take, after this, clears it too when a chunk came.
	for _, t := range r.tasks {
		if t.recv != nil {
			t.recv.asked = false
		}
	}
}

// Failed says the message with items did not go through: it is sent again
// as it was.
func (r *Runner) Failed(items []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight = items
}

// Take reads core's items: tasks to run (each once), cancels, how far core
// has a file being sent or why it does not take it (an err naming one of
// the sent items, a chunk), chunks of a file it sends, a poll, a max_tasks
// and a rehello. sent are the items of the message it answers.
func (r *Runner) Take(answer protocol.CoreMessage, sent []any) {
	for i, raw := range answer.Items {
		switch protocol.ItemType(raw) {
		case protocol.ItemAck:
			var a protocol.AckItem
			if protocol.UnmarshalCBOR(raw, &a) == nil && a.Validate() == nil && a.Xfer != nil {
				r.acked(a.Xfer, *a.Next, a.Hold)
			}
		case protocol.ItemErr:
			var e protocol.ErrItem
			if protocol.UnmarshalCBOR(raw, &e) == nil && e.Item != nil && *e.Item >= 0 && *e.Item < len(sent) {
				switch it := sent[*e.Item].(type) {
				case protocol.ChunkItem:
					r.refused(it.Xfer, e.Msg)
				case protocol.AckItem:
					if it.Xfer != nil {
						r.refused(it.Xfer, e.Msg)
					}
				}
			}
		case protocol.ItemChunk:
			var c protocol.ChunkItem
			if protocol.UnmarshalCBOR(raw, &c) != nil || c.Validate() != nil {
				r.queueErr(protocol.ErrItemBadMessage, "the chunk does not read", i)
				continue
			}
			r.chunk(c, i)
		case protocol.ItemTask:
			var t protocol.TaskItem
			if protocol.UnmarshalCBOR(raw, &t) != nil || t.Validate() != nil {
				r.queueErr(protocol.ErrItemBadMessage, "the task does not read", i)
				continue
			}
			r.start(t)
		case protocol.ItemCancel:
			var c protocol.CancelItem
			if protocol.UnmarshalCBOR(raw, &c) != nil || c.Validate() != nil {
				r.queueErr(protocol.ErrItemBadMessage, "the cancel does not read", i)
				continue
			}
			r.stop(c.Task, i)
		case protocol.ItemReack:
			// Core asks which of these tasks the minion still has: back over
			// a new connection, it has none of those that ran in the one
			// that went.
			var rk protocol.ReackItem
			if protocol.UnmarshalCBOR(raw, &rk) != nil || rk.Validate() != nil {
				r.queueErr(protocol.ErrItemBadMessage, "the reack does not read", i)
				continue
			}
			r.reack(rk.Tasks, i)
		case protocol.ItemPoll:
			// Come back sooner than the schedule: a stream of the minion's
			// may go on any moment.
			var p protocol.PollItem
			if protocol.UnmarshalCBOR(raw, &p) == nil && p.Validate() == nil {
				r.mu.Lock()
				r.poll = time.Duration(p.Within) * time.Millisecond
				r.mu.Unlock()
			}
		case protocol.ItemMaxTasks:
			// How many tasks to run at once, from now: said back in the next
			// message, whatever it was, so core knows the minion has it.
			var m protocol.MaxTasksItem
			if protocol.UnmarshalCBOR(raw, &m) != nil || m.Validate() != nil {
				r.queueErr(protocol.ErrItemBadMessage, "the max_tasks does not read", i)
				continue
			}
			r.mu.Lock()
			if r.maxTasks != m.Max {
				r.logf("max tasks %d, as core says (was %d)", m.Max, r.maxTasks)
			}
			r.maxTasks, r.maxTasksSay = m.Max, true
			r.mu.Unlock()
			r.Nudge()
		case protocol.ItemRehello:
			// Core asks what host and process this is: a hello, in the
			// next message.
			r.mu.Lock()
			r.helloAsked = true
			r.mu.Unlock()
			r.Nudge()
		case protocol.ItemStageResponse, protocol.ItemHelloResponse:
			// Answers of staging and hello (a rehello's): nothing to do.
		case protocol.ItemResume:
			r.queueErr(protocol.ErrItemUnknownItem, "this minion keeps its tasks' state: it takes no resume", i)
		default:
			r.queueErr(protocol.ErrItemUnknownItem, fmt.Sprintf("this minion does not take %s", protocol.ItemName(protocol.ItemType(raw))), i)
		}
	}
}

// acked takes how far core has a file: all of it ends the transfer. For a
// stream it is where to send from (it may go back: a download resumed
// from earlier), and hold says to wait; the whole without hold ends it.
func (r *Runner) acked(xfer []byte, next uint64, hold bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tasks {
		// A stream core sends: hold says it has nothing yet.
		if rx := t.recv; rx != nil && slices.Equal(rx.offer.Xfer, xfer) && !rx.over {
			rx.held, rx.asked = hold, false
			continue
		}
		x := t.xfer
		if x == nil || !slices.Equal(x.id, xfer) || x.over {
			continue
		}
		x.acked, x.waiting = min(next, x.total), false
		if x.stream {
			x.announced, x.held = true, hold
			if !hold {
				x.started = true
				if x.acked == x.total {
					x.finish("")
				}
			}
			continue
		}
		if x.acked == x.total && x.hashed == x.total {
			x.finish("")
		}
	}
}

// PollEvery is how soon to send the next message when core asked for
// sooner than the schedule (a poll: a stream the minion holds may go on any
// moment, its downloader or uploader there). Zero: the schedule. Over a
// persistent connection core pushes instead, and asks for none.
func (r *Runner) PollEvery() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.poll
}

// refused ends a transfer core does not take, or does not send.
func (r *Runner) refused(xfer []byte, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tasks {
		if x := t.xfer; x != nil && slices.Equal(x.id, xfer) {
			x.finish("core refused the file: " + why)
		}
		if x := t.recv; x != nil && slices.Equal(x.offer.Xfer, xfer) {
			x.finish("core did not send the file: " + why)
		}
	}
}

// chunk takes a chunk of a file core sends; one for no transfer the runner
// has gets an unknown_task.
func (r *Runner) chunk(c protocol.ChunkItem, item int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tasks {
		if x := t.recv; x != nil && slices.Equal(x.offer.Xfer, c.Xfer) {
			x.take(c)
			return
		}
	}
	// A first chunk names its task: core ends the task the minion does not
	// have.
	r.errs = append(r.errs, protocol.ErrItem{T: protocol.ItemErr, Code: protocol.ErrItemUnknownTask, Msg: "no such transfer", Item: &item, Task: c.Task})
}

func (r *Runner) queueErr(code int, msg string, item int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, protocol.ErrItem{T: protocol.ItemErr, Code: code, Msg: msg, Item: &item})
}

// start acks a task and runs it, unless it ran already.
func (r *Runner) start(ti protocol.TaskItem) {
	key := hex.EncodeToString(ti.Task)
	r.mu.Lock()
	for k, at := range r.seen {
		if time.Since(at) > taskMemory {
			delete(r.seen, k)
		}
	}
	r.acks = append(r.acks, ti.Task)
	if _, ran := r.seen[key]; ran {
		r.mu.Unlock()
		r.logf("task %s again: acked, not run again", key[:8])
		return
	}
	r.seen[key] = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	t := &Task{id: ti.Task, cmd: ti.Cmd, cancel: cancel}
	r.tasks = append(r.tasks, t)
	r.mu.Unlock()
	r.logf("task %s: command %d %v", key[:8], ti.Cmd, ti.Args)
	go func() {
		defer cancel()
		// A command that panics fails its task, and says so to the
		// operators, rather than taking the minion down.
		defer func() {
			if v := recover(); v != nil {
				r.feedback.Report(protocol.FeedbackError, "task_panic", t.id, "task %s (command %d) crashed: %v", key[:8], ti.Cmd, v)
				r.End(t, false, nil, fmt.Sprintf("the command crashed: %v", v))
				r.Nudge()
			}
		}()
		if r.exec != nil {
			r.exec(ctx, t, ti)
		} else {
			r.run(ctx, t, ti)
		}
		r.Nudge()
	}()
}

// reack answers core's question about tasks (item, a reack): an ack names
// those the runner has (running, or ended with an end core has not had),
// an unknown_task each it does not, which core ends. A runner lives as
// long as its connection: a command that ran in an earlier one went with
// it.
func (r *Runner) reack(ids [][]byte, item int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		if slices.ContainsFunc(r.tasks, func(t *Task) bool { return slices.Equal(t.id, id) }) {
			r.acks = append(r.acks, id)
			continue
		}
		r.errs = append(r.errs, protocol.ErrItem{T: protocol.ItemErr, Code: protocol.ErrItemUnknownTask,
			Msg: "no such task: it ran in a connection that closed", Item: &item, Task: id})
	}
}

// stop cancels a running task; one the runner does not have gets an
// unknown_task.
func (r *Runner) stop(id []byte, item int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tasks {
		if slices.Equal(t.id, id) {
			if !t.ended {
				r.logf("task %s: cancelled", hex.EncodeToString(id)[:8])
				t.cancel()
			}
			return
		}
	}
	// Named, so core ends it (one this process never had: it restarted).
	r.errs = append(r.errs, protocol.ErrItem{T: protocol.ItemErr, Code: protocol.ErrItemUnknownTask, Msg: "no such task running", Item: &item, Task: id})
}

// Write adds output to a task (text, or a chunk of structured output: a
// map, or a struct such as protocol.DirListing), and asks for an early
// message.
func (r *Runner) Write(t *Task, out []byte, data any) {
	var chunk []byte
	if data != nil {
		b, err := protocol.WireResultData(data)
		if err != nil {
			r.logf("task %s: data does not encode: %v", hex.EncodeToString(t.id)[:8], err)
		} else {
			chunk = b
		}
	}
	r.mu.Lock()
	t.out = append(t.out, out...)
	if chunk != nil {
		t.chunks = append(t.chunks, chunk)
	}
	r.mu.Unlock()
	r.Nudge()
}

// list adds a folder's listing to a task's result, in pieces (listingPieces)
// cut so a piece takes half a message at most.
func (r *Runner) list(t *Task, path, sep, parent string, entries []Entry, partial bool, errCode int) {
	r.mu.Lock()
	id := t.listings
	t.listings++
	pieces, sizes := listingPieces(id, path, sep, parent, entries, partial, errCode, r.perMessageLocked()/2)
	t.pieces, t.sizes = append(t.pieces, pieces...), append(t.sizes, sizes...)
	r.mu.Unlock()
	r.Nudge()
}

// listingPieces is a folder's listing (id: its number in its task), in
// pieces of lsChunk entries at most, cut sooner so a piece takes budget
// bytes at most, and their encoded sizes: the first names the folder, the
// last says so. errCode: it could not be read at all (a
// protocol.ListingErr); partial: not all of it.
func listingPieces(id uint64, path, sep, parent string, entries []Entry, partial bool, errCode int, budget int) ([]protocol.LsPiece, []int) {
	var pieces []protocol.LsPiece
	var sizes []int
	for i, part := 0, uint64(0); i == 0 || i < len(entries); part++ {
		p := protocol.LsPiece{ID: id, Part: part}
		if part == 0 {
			p.Path, p.Sep, p.Parent, p.Err = path, sep, parent, errCode
		}
		// Room for the piece's own keys, path and owners, then entries
		// while they fit (one at least, so a listing always moves on).
		used := 64 + len(p.Path) + len(p.Parent)
		for i < len(entries) && len(p.Entries) < lsChunk {
			e := entries[i]
			size := 16 + len(e.OwnerName) + len(e.GroupName)
			if b, err := protocol.MarshalCBOR(e.LsEntry); err == nil {
				size += len(b)
			}
			if len(p.Entries) > 0 && used+size > budget {
				break
			}
			e.Owner, e.Group = p.Owner(e.OwnerName), p.Owner(e.GroupName)
			p.Entries = append(p.Entries, e.LsEntry)
			used += size
			i++
		}
		p.Last = i >= len(entries)
		p.Partial = p.Last && partial
		size := 64
		if b, err := protocol.MarshalCBOR(p); err == nil {
			size = len(b)
		}
		pieces, sizes = append(pieces, p), append(sizes, size)
		if len(entries) == 0 {
			break
		}
	}
	return pieces, sizes
}

// End records how a task ended: ok, its exit code (a command's), and why
// it failed, or what else to say of its end (errText).
func (r *Runner) End(t *Task, ok bool, exit *int64, errText string) {
	r.mu.Lock()
	t.ended, t.ok, t.exit, t.err = true, ok, exit, errText
	r.mu.Unlock()
	state := "ok"
	if !ok {
		state = "failed: " + errText
	}
	r.logf("task %s: command %d %s", hex.EncodeToString(t.id)[:8], t.cmd, state)
}

// run carries out a task's command.
func (r *Runner) run(ctx context.Context, t *Task, ti protocol.TaskItem) {
	switch r.ops[ti.Cmd] {
	case CmdLs:
		r.ls(t, ti.Args)
	case CmdWalk:
		r.walk(ctx, t, ti.Args)
	case CmdDownload:
		r.sendFile(ctx, t, ti.Args, false)
	case CmdStreamDownload:
		r.sendFile(ctx, t, ti.Args, true)
	case CmdUpload:
		r.upload(ctx, t, ti.Args, false)
	case CmdStreamUpload:
		r.upload(ctx, t, ti.Args, true)
	case CmdRm:
		r.rm(t, ti.Args)
	case CmdShell:
		r.shell(ctx, t, ti.Args)
	case CmdVolumes:
		r.volumes(t)
	default:
		r.End(t, false, nil, fmt.Sprintf("command %d is not one this minion knows", ti.Cmd))
	}
}
