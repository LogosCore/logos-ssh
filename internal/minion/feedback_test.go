//go:build unix

package minion

import (
	"strings"
	"testing"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

// feedbackIn is a message's feedback items.
func feedbackIn(items []any) []protocol.FeedbackItem {
	var out []protocol.FeedbackItem
	for _, it := range items {
		if f, ok := it.(protocol.FeedbackItem); ok {
			out = append(out, f)
		}
	}
	return out
}

// Reported feedback goes with the next message (sent at once: pending);
// one like a queued one is folded into it; past the most kept, the oldest
// go and a warning says so; a message that fails sends them again.
func TestFeedbackQueue(t *testing.T) {
	fb := NewFeedback(nil)
	r := newRunnerWith(Config{Feedback: fb})
	woke := 0
	fb.SetWake(func() { woke++ })
	fb.Report(protocol.FeedbackWarning, "x", nil, "the same")
	fb.Report(protocol.FeedbackWarning, "x", nil, "the same")
	fb.Report(protocol.FeedbackError, "y", nil, "another")
	if !r.Pending() || woke != 3 {
		t.Fatalf("feedback waits for the schedule: pending %v, woke %d", r.Pending(), woke)
	}
	items := r.Outgoing()
	got := feedbackIn(items)
	if len(got) != 2 || got[0].Count != 2 || got[1].Level != protocol.FeedbackError || len(got[0].ID) != 8 || got[0].Validate() != nil {
		t.Fatalf("sent %+v", got)
	}
	r.Failed(items)
	if again := feedbackIn(r.Outgoing()); len(again) != 2 || string(again[0].ID) != string(got[0].ID) {
		t.Fatalf("not sent again as it was: %+v", again)
	}
	r.Delivered()

	for i := range MaxFeedback + 5 {
		fb.Report(protocol.FeedbackWarning, "n", nil, "number %d", i)
	}
	var all []protocol.FeedbackItem
	for range 20 {
		all = append(all, feedbackIn(next(r))...)
	}
	if len(all) != MaxFeedback+1 || all[0].Code != "feedback_dropped" || !strings.Contains(all[0].Msg, "5 feedback messages dropped") ||
		all[1].Msg != "number 5" {
		t.Fatalf("%d sent, first %+v", len(all), all[0])
	}
	// A message too small for all of them takes some, at least one.
	fb = NewFeedback(nil)
	r = newRunnerWith(Config{Feedback: fb})
	r.SetLimit(protocol.MinConnectionMessage)
	for i := range 5 {
		fb.Report(protocol.FeedbackWarning, "n", nil, "%s %d", strings.Repeat("x", 300), i)
	}
	if n := len(feedbackIn(next(r))); n < 1 || n >= 5 {
		t.Fatalf("%d in a small message", n)
	}
	// A runner without a queue sends none, and reports into nothing.
	var none *Feedback
	none.Report(protocol.FeedbackError, "z", nil, "lost")
	if none.Pending() || newTestRunner().Pending() {
		t.Fatal("a nil queue holds something")
	}
}
