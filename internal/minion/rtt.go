package minion

import "time"

// Timing that follows the link (docs: contracts/minion-messages/tunnels.md,
// change 9, the minion's half): the minion sends again what core did not
// ack once the session's round trip has passed, as TCP does (RFC 6298),
// never sooner than tunnelResend (ts.resend) nor later than a minute; and
// a stream's window, the room it gives core, grows while core fills it and
// the host keeps up, to maxWindow (maxTunnelExtra over a tunnel's streams).
// No item changes: each side's timing is its own.

// maxResend bounds how long the minion waits for an ack, however slow the
// link.
const maxResend = time.Minute

// rttState is the session's round trip, as core's acks measure it.
type rttState struct {
	srtt, rttvar time.Duration
	have         bool
}

func (r *rttState) sample(d time.Duration) {
	if !r.have {
		r.srtt, r.rttvar, r.have = d, d/2, true
		return
	}
	diff := r.srtt - d
	if diff < 0 {
		diff = -diff
	}
	r.rttvar = (3*r.rttvar + diff) / 4
	r.srtt = (7*r.srtt + d) / 8
}

// resendAfter is how long the minion waits for core's ack before it sends
// again: the round trip and four times its spread, within ts.resend and
// maxResend (ts.mu held).
func (ts *tunnels) resendAfter() time.Duration {
	if !ts.rtt.have {
		return ts.resend
	}
	return min(max(ts.resend, ts.rtt.srtt+4*ts.rtt.rttvar), maxResend)
}

// measure starts a round trip on what the stream sends, unless one runs:
// its ack ends it. A send again ends any, as it would mislead (Karn's
// rule).
func (st *tstream) measure(end uint64, resent bool, now time.Time) {
	switch {
	case resent:
		st.rttAt = time.Time{}
	case st.rttAt.IsZero():
		st.rttEnd, st.rttAt = end, now
	}
}

// measured takes the stream's round trip once core's ack covers it (ts.mu
// held).
func (ts *tunnels) measured(st *tstream, next uint64) {
	if st.rttAt.IsZero() || next < st.rttEnd {
		return
	}
	if d := time.Since(st.rttAt); d >= 0 {
		ts.rtt.sample(d)
	}
	st.rttAt = time.Time{}
}

// win is the room the minion gives core on the stream now.
func (st *tstream) win() int {
	if st.window == 0 {
		return tunnelWindow
	}
	return st.window
}

// grow doubles the stream's window once core sent up to what the acks let
// it and the host took all of it: the window, not the host, holds the
// stream back. True when it grew (an ack says so).
func (st *tstream) grow() bool {
	w := st.win()
	switch {
	case w >= maxWindow, len(st.in) > 0, st.eofIn:
		return false
	case st.next+uint64(w/8) < st.ackedEnd:
		return false
	case st.t.extra+w > maxTunnelExtra:
		return false
	}
	st.t.extra += w
	st.window = 2 * w
	st.ackDue = true
	return true
}

// shrink gives back what the stream's window grew, as it goes.
func (st *tstream) shrink() {
	st.t.extra -= st.win() - tunnelWindow
	st.window = tunnelWindow
}
