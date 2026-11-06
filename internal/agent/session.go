package agent

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/ops"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshhost"
)

// coreSide is a connection's socket to core (connclient.Conn).
type coreSide interface {
	Send(ctx context.Context, f protocol.ConnFrame) error
	Receive(ctx context.Context) (protocol.ConnFrame, error)
	Close() error
}

// replyWait is how long the minion waits for core's reply to a message
// before it sends it again.
const replyWait = time.Minute

// session is a persistent connection (docs: contracts/agentless-channels/,
// bind-persistent): the minion runs its tasks on the server for as long as
// both the socket to core and the SSH connection are open, and the
// connection ends when either closes.
//
// The minion speaks first, as on any persistent connection: its hello,
// alone, under the id the open gave (the target's open session's, else the
// build's: the minion keeps no ids of its own). A hello under the build id
// opens a session, and the minion goes on under the id core's
// hello_response gives; under a session id it says the session's host again.
// Each message gets core's reply, and core pushes tasks and cancels between
// them, within the minion's standing allowance (its get_tasks). Every frame
// is sealed with the keys the open gave: the minion does not stage, so its
// session keeps its build's keys, and they hold under the session id too.
type session struct {
	t       connection.Target
	c       *sshconn.Conn
	core    coreSide
	request uint64
	under   []byte
	keys    protocol.AES256CBCHMACSHA256Material
	// acting is the task that made the session's identity, as the open
	// said (nil: none): what core takes the first tasks to run as.
	acting []byte

	once sync.Once
	done chan struct{}
}

func newSession(t connection.Target, c *sshconn.Conn, core coreSide, request uint64, under []byte,
	keys protocol.AES256CBCHMACSHA256Material) *session {
	return &session{t: t, c: c, core: core, request: request, under: under, keys: keys, done: make(chan struct{})}
}

// close ends the connection, both sides, once.
func (s *session) close(why string) {
	s.once.Do(func() {
		_ = s.core.Close()
		_ = s.c.Close()
		close(s.done)
		slog.Info("connection closed", "request", s.request, "server", s.t.Addr, "why", why)
	})
}

func (s *session) run() {
	defer s.close("the minion stopped")
	host := sshhost.New(s.c)
	feedback := minion.NewFeedback(logf(s.t.Addr))
	r := minion.NewRunner(minion.Config{Host: host, Ops: ops.Commands, MaxTasks: ops.MaxTasks, Feedback: feedback,
		Hello: host.Hello, Logf: logf(s.t.Addr), Acting: s.acting})
	feedback.SetWake(r.Nudge)
	r.SetPersistent(true)
	r.SetLimit(protocol.MaxMinionMessageSize)

	frames := make(chan protocol.ConnFrame, 16)
	go func() {
		defer close(frames)
		for {
			f, err := s.core.Receive(context.Background())
			if err != nil {
				s.close("core closed the connection's socket")
				return
			}
			select {
			case frames <- f:
			case <-s.done:
				return
			}
		}
	}()
	go func() {
		_ = s.c.Wait()
		s.close("the server closed the SSH connection")
	}()
	keep := time.NewTicker(s.t.Keepalive)
	defer keep.Stop()
	// The minion speaks first: its hello.
	r.AskHello()

	// id is what the minion's messages go under: the open's, then the
	// session's once a hello_response says it. inflight is the message
	// waiting for core's reply (its id and items).
	id := s.under
	var inflight []byte
	var sent []any
	var sentAt time.Time
	spoke := false
	send := func() bool {
		items := r.Outgoing()
		msgID, b, err := minion.Message(nil, items)
		if err != nil {
			s.close("a message does not encode: " + err.Error())
			return false
		}
		frame, err := protocol.SealFrame(s.keys, [16]byte(id), protocol.FrameMinionToCore, b)
		if err != nil {
			s.close("a message does not seal: " + err.Error())
			return false
		}
		if err := s.core.Send(context.Background(), protocol.ConnFrame{ID: id, Data: frame}); err != nil {
			r.Failed(items)
			s.close("send to core: " + err.Error())
			return false
		}
		inflight, sent, sentAt, spoke = msgID, items, time.Now(), true
		return true
	}
	for {
		select {
		case <-s.done:
			return
		case f, ok := <-frames:
			if !ok {
				return
			}
			if len(f.ID) != 16 {
				slog.Info("a frame from core under no id", "request", s.request)
				continue
			}
			plain, err := protocol.OpenFrame(s.keys, [16]byte(f.ID), protocol.FrameCoreToMinion, f.Data)
			if err != nil {
				slog.Info("a frame from core that does not open with the open's keys", "request", s.request)
				continue
			}
			msg, err := minion.ReadCore(plain)
			if err != nil {
				slog.Info("a message from core that does not read", "request", s.request, "err", err)
				continue
			}
			var answered []any
			if msg.Re != nil && inflight != nil && bytes.Equal(msg.Re, inflight) {
				answered = sent
				r.Delivered()
				r.Take(msg, sent)
				inflight, sent = nil, nil
				if sid := sessionID(msg); sid != nil {
					id = sid
				}
			} else {
				r.Take(msg, nil)
			}
			// Core's refusals, said: one of the hello leaves the minion
			// nothing to do on the connection.
			if why, hello := refused(msg, answered); why != "" {
				slog.Info("core refused an item", "request", s.request, "server", s.t.Addr, "why", why)
				if hello {
					s.close("core refused the hello: " + why)
					return
				}
			}
			if sessionClosed(msg) {
				s.close("core closed the session")
				return
			}
		case <-r.Wake():
		case <-keep.C:
			if !s.c.Alive(s.t.Keepalive) {
				s.close("the server did not answer a keepalive")
				return
			}
		}
		if inflight != nil {
			if time.Since(sentAt) < replyWait {
				continue
			}
			// No reply: core takes it again as it was.
			r.Failed(sent)
			inflight, sent = nil, nil
		}
		if (!spoke || r.Pending()) && !send() {
			return
		}
	}
}

// sessionID is the session id a hello_response in msg gives; nil for none.
func sessionID(msg protocol.CoreMessage) []byte {
	for _, raw := range msg.Items {
		if protocol.ItemType(raw) != protocol.ItemHelloResponse {
			continue
		}
		var h protocol.HelloResponseItem
		if protocol.UnmarshalCBOR(raw, &h) == nil && len(h.SID) == 16 {
			return h.SID
		}
	}
	return nil
}

// refused is what core's err items in msg say, and whether one refused the
// hello among answered, the items of the message msg answers.
func refused(msg protocol.CoreMessage, answered []any) (string, bool) {
	var whys []string
	hello := false
	for _, raw := range msg.Items {
		if protocol.ItemType(raw) != protocol.ItemErr {
			continue
		}
		var e protocol.ErrItem
		if protocol.UnmarshalCBOR(raw, &e) != nil {
			continue
		}
		whys = append(whys, e.Msg)
		if e.Item != nil && *e.Item >= 0 && *e.Item < len(answered) {
			if _, ok := answered[*e.Item].(protocol.HelloItem); ok {
				hello = true
			}
		}
	}
	return strings.Join(whys, "; "), hello
}

// sessionClosed: core says the session is closed.
func sessionClosed(msg protocol.CoreMessage) bool {
	for _, raw := range msg.Items {
		if protocol.ItemType(raw) != protocol.ItemErr {
			continue
		}
		var e protocol.ErrItem
		if protocol.UnmarshalCBOR(raw, &e) == nil && e.Code == protocol.ErrItemSessionClosed {
			return true
		}
	}
	return false
}
