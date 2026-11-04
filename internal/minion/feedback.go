package minion

import (
	"crypto/rand"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// Feedback (docs: contracts/minion-messages/sessions, Feedback): the
// warnings and errors a minion has for its operators, what it would
// otherwise only log. Anything may report one (the program's session
// loop, its transports, a task); the runner sends them first in its next
// messages, at once (the wake), and a message that fails goes again with
// them, as any.

// MaxFeedback is how many a queue keeps unsent: past it the oldest go, and
// a warning says how many.
const MaxFeedback = 100

// Feedback is a queue of feedback to send. A minion that outlives its
// sessions keeps one for all of them (what one could not send, the next
// does); a channel that acts as many minions keeps one for each. The zero
// value is not usable: NewFeedback makes one. A nil queue takes and holds
// nothing.
type Feedback struct {
	mu      sync.Mutex
	items   []protocol.FeedbackItem
	dropped int
	// wake asks the runner sending them for an early message.
	wake func()
	logf func(format string, args ...any)
}

// NewFeedback is an empty queue, logging what is reported with logf (nil:
// not logged).
func NewFeedback(logf func(format string, args ...any)) *Feedback {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Feedback{logf: logf}
}

// Report queues a warning or an error (protocol.FeedbackWarning, ...), about
// task when it is one's, and logs it. One like a queued one (the same
// level, code, task and message) is folded into it: its count goes up, its
// time stays the first's.
func (q *Feedback) Report(level int, code string, task []byte, format string, args ...any) {
	if q == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if len(msg) > protocol.MaxFeedbackMsg {
		msg = msg[:protocol.MaxFeedbackMsg-3] + "..."
	}
	q.logf("feedback (%s, %s): %s", protocol.FeedbackLevelName(level), code, msg)
	q.add(protocol.FeedbackItem{T: protocol.ItemFeedback, Level: level, Code: code, Task: task, Msg: msg,
		At: uint64(max(time.Now().Unix(), 0)), Count: 1})
}

func (q *Feedback) add(f protocol.FeedbackItem) {
	q.mu.Lock()
	i := slices.IndexFunc(q.items, func(o protocol.FeedbackItem) bool {
		return o.Level == f.Level && o.Code == f.Code && o.Msg == f.Msg && string(o.Task) == string(f.Task)
	})
	if i >= 0 {
		q.items[i].Count++
	} else {
		f.ID = make([]byte, protocol.FeedbackIDSize)
		_, _ = rand.Read(f.ID)
		if len(q.items) >= MaxFeedback {
			q.items = q.items[1:]
			q.dropped++
		}
		q.items = append(q.items, f)
	}
	wake := q.wake
	q.mu.Unlock()
	if wake != nil {
		wake()
	}
}

// SetWake says whose runner sends the queue's feedback now: wake asks it
// for an early message (Runner.Nudge); nil for none.
func (q *Feedback) SetWake(wake func()) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.wake = wake
}

// Pending reports whether there is feedback to send.
func (q *Feedback) Pending() bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) > 0 || q.dropped > 0
}

// Take is the feedback a message has room for (room bytes, one at least
// when whole: room is the whole message's), oldest first, and the room it
// leaves; a warning first when some were dropped.
func (q *Feedback) Take(room int, whole bool) ([]protocol.FeedbackItem, int) {
	if q == nil {
		return nil, room
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.dropped > 0 {
		f := protocol.FeedbackItem{T: protocol.ItemFeedback, ID: make([]byte, protocol.FeedbackIDSize), Level: protocol.FeedbackWarning,
			Code: "feedback_dropped", Msg: fmt.Sprintf("%d feedback messages dropped: more came than the minion keeps (%d) before they could go", q.dropped, MaxFeedback),
			At: uint64(max(time.Now().Unix(), 0)), Count: 1}
		_, _ = rand.Read(f.ID)
		q.items = append([]protocol.FeedbackItem{f}, q.items...)
		q.dropped = 0
	}
	var out []protocol.FeedbackItem
	for len(q.items) > 0 {
		size := 64 + len(q.items[0].Msg) + len(q.items[0].Code)
		if size > room && (!whole || len(out) > 0) {
			break
		}
		out = append(out, q.items[0])
		q.items = q.items[1:]
		room = max(room-size, 0)
	}
	return out, room
}
