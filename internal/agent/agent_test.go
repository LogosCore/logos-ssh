//go:build unix

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/logoscore/logos-golang-channel-core/v3/pkg/linkclient"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/connection"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/ops"
	"github.com/logoscore/logos-ssh/internal/sshconn"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// testKeys are a build's keys, as core gives them to the SSH channel with
// each call and open (protocol.LinkKeys).
var testKeys = protocol.AES256CBCHMACSHA256Material{EncKey: bytes.Repeat([]byte{1}, 32), MACKey: bytes.Repeat([]byte{2}, 32)}

var testLinkKeys = &protocol.LinkKeys{Suite: protocol.CryptoAES256CBCHMACSHA256, Material: testKeys}

// sealedCall is a call as core makes it to an agentless kind: its message
// sealed under its id with the build's keys, which go with it. The
// answer's data comes back opened.
func sealedCall(ctx context.Context, t *testing.T, a *Agent, c linkclient.Call) linkclient.Answer {
	t.Helper()
	frame, err := protocol.SealFrame(testKeys, c.ID, protocol.FrameCoreToMinion, c.Data)
	if err != nil {
		t.Fatal(err)
	}
	c.Data, c.Keys = frame, testLinkKeys
	ans := a.Call(ctx, c)
	if ans.ID != nil && ans.Data != nil {
		plain, err := protocol.OpenFrame(testKeys, *ans.ID, protocol.FrameMinionToCore, ans.Data)
		if err != nil {
			t.Fatalf("the answer does not open with the call's keys: %v", err)
		}
		ans.Data = plain
	}
	return ans
}

// openedMessage is the minion's message in a frame, opened as core opens it.
func openedMessage(t *testing.T, f protocol.ConnFrame) protocol.MinionMessage {
	t.Helper()
	plain, err := protocol.OpenFrame(testKeys, [16]byte(f.ID), protocol.FrameMinionToCore, f.Data)
	if err != nil {
		t.Fatalf("the minion's frame does not open: %v", err)
	}
	return minionMessage(t, plain)
}

// coreMessage is core's message with these items, as CBOR.
func coreMessage(t *testing.T, re []byte, items ...any) ([]byte, []byte) {
	t.Helper()
	// A message starts an exchange (an id) or answers one (re), never both.
	m := protocol.CoreMessage{V: protocol.MinionMessageV3, Re: re, At: uint64(time.Now().Unix())} //nolint:gosec // now
	if re == nil {
		m.ID = protocol.NewMessageID()
	}
	for _, it := range items {
		b, err := protocol.MarshalCBOR(it)
		if err != nil {
			t.Fatal(err)
		}
		m.Items = append(m.Items, cbor.RawMessage(b))
	}
	b, err := protocol.MarshalCBOR(m)
	if err != nil {
		t.Fatal(err)
	}
	return m.ID, b
}

// minionMessage reads the minion's message.
func minionMessage(t *testing.T, b []byte) protocol.MinionMessage {
	t.Helper()
	var m protocol.MinionMessage
	if err := protocol.UnmarshalCBOR(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// checkItems checks the minion's message as core checks it: its head, and
// each item by its type (the hello's pid 0: no process of its own).
func checkItems(t *testing.T, m protocol.MinionMessage) {
	t.Helper()
	if err := protocol.ValidateMessageHead(m.V, m.ID, m.Re, len(m.Items)); err != nil {
		t.Errorf("message head: %v", err)
	}
	for _, raw := range m.Items {
		var err error
		switch typ := protocol.ItemType(raw); typ {
		case protocol.ItemHello:
			err = validated(raw, protocol.HelloItem.Validate)
		case protocol.ItemResult:
			err = validated(raw, protocol.ResultItem.Validate)
		case protocol.ItemAck:
			err = validated(raw, protocol.AckItem.Validate)
		case protocol.ItemChunk:
			err = validated(raw, protocol.ChunkItem.Validate)
		case protocol.ItemGetTasks:
			err = validated(raw, protocol.GetTasksItem.Validate)
		case protocol.ItemFeedback:
			err = validated(raw, protocol.FeedbackItem.Validate)
		case protocol.ItemMaxTasks:
			err = validated(raw, protocol.MaxTasksItem.Validate)
		case protocol.ItemErr:
			err = validated(raw, protocol.ErrItem.Validate)
		default:
			err = errors.New("not an item a minion sends")
		}
		if err != nil {
			t.Errorf("item %d: %v", protocol.ItemType(raw), err)
		}
	}
}

func validated[T any](raw cbor.RawMessage, check func(T) error) error {
	var v T
	if err := protocol.UnmarshalCBOR(raw, &v); err != nil {
		return err
	}
	return check(v)
}

func itemsOf[T any](t *testing.T, m protocol.MinionMessage, typ int) []T {
	t.Helper()
	var out []T
	for _, raw := range m.Items {
		if protocol.ItemType(raw) == typ {
			var v T
			if err := protocol.UnmarshalCBOR(raw, &v); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
	}
	return out
}

func shellTask(id byte, command string) protocol.TaskItem {
	return protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{id}, 16), Cmd: ops.Shell, Args: protocol.Args{minion.ArgShellCommand: command}}
}

// A call answers under the id it came under, as the minion: a rehello with
// the hello, a task with its result; the login is kept for the next call.
// Every item passes core's checks.
func TestCall(t *testing.T) {
	dir := t.TempDir()
	srv := sshtest.New(t, dir)
	a := New("http://core.invalid", "ssh-test", 4)
	defer a.Close("the test ends")
	values := srv.Values()
	values["call_reuse"] = "1m"
	buildID := [16]byte{1, 2, 3}
	id, data := coreMessage(t, nil, protocol.RehelloItem{T: protocol.ItemRehello}, shellTask(7, "echo hi"))
	ans := sealedCall(context.Background(), t, a, linkclient.Call{Request: 1, Values: values, ID: buildID, Data: data})
	if ans.Failure != nil || ans.ID == nil || *ans.ID != buildID || ans.Peer != "127.0.0.1" {
		t.Fatalf("answer %+v", ans)
	}
	m := minionMessage(t, ans.Data)
	checkItems(t, m)
	hello := itemsOf[protocol.HelloItem](t, m, protocol.ItemHello)
	results := itemsOf[protocol.ResultItem](t, m, protocol.ItemResult)
	if !bytes.Equal(m.Re, id) || m.ID != nil || len(hello) != 1 || hello[0].X["host_key"] != srv.Fingerprint() || len(results) != 1 ||
		!*results[0].OK || string(results[0].Out) != "hi\n" {
		t.Fatalf("message %+v: hello %+v, results %+v", m, hello, results)
	}
	if st := a.Stats(); st.LoginsKept != 1 || st.Calls != 1 || st.CallsFailed != 0 {
		t.Fatalf("stats %+v", st)
	}
	// The next call goes over the login kept: a download's first chunk too.
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("file body"), 0o600); err != nil {
		t.Fatal(err)
	}
	download := protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{9}, 16), Cmd: ops.Download,
		Args: protocol.Args{minion.ArgDownloadPath: filepath.Join(dir, "f.txt")}}
	_, data = coreMessage(t, nil, shellTask(8, "echo again"), download)
	if ans = sealedCall(context.Background(), t, a, linkclient.Call{Request: 2, Values: values, ID: buildID, Data: data}); ans.ID == nil {
		t.Fatalf("second answer %+v", ans)
	}
	m = minionMessage(t, ans.Data)
	checkItems(t, m)
	if chunks := itemsOf[protocol.ChunkItem](t, m, protocol.ItemChunk); len(chunks) != 1 || string(chunks[0].Data) != "file body" {
		t.Fatalf("the download's chunks: %+v", chunks)
	}
	if st := a.Stats(); st.LoginsKept != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// A call lives as long as its context (core's deadline, the link): a server
// that answers no open does not hold it, and the login it broke is not kept.
func TestCallEndsWithItsContext(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	a := New("http://core.invalid", "ssh-test", 4)
	defer a.Close("the test ends")
	values := srv.Values()
	values["call_reuse"] = "1m"
	srv.Stall.Store(true) // the login goes; every open after it waits
	_, data := coreMessage(t, nil, protocol.RehelloItem{T: protocol.ItemRehello}, shellTask(7, "echo hi"))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	ans := sealedCall(ctx, t, a, linkclient.Call{Request: 1, Values: values, ID: [16]byte{1}, Data: data})
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the call took %s", took)
	}
	if ans.Failure != nil || ans.ID == nil {
		t.Fatalf("answer %+v", ans)
	}
	m := minionMessage(t, ans.Data)
	checkItems(t, m)
	if results := itemsOf[protocol.ResultItem](t, m, protocol.ItemResult); len(results) != 1 || *results[0].OK {
		t.Fatalf("results %+v", results)
	}
	if st := a.Stats(); st.LoginsKept != 0 {
		t.Fatalf("a broken login kept: %+v", st)
	}
}

// A call core gives no deadline keeps to the channel's call timeout: a
// command that would outlast it is stopped in time, saying so, and the
// answer goes.
func TestCallKeepsToItsTimeout(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	a := New("http://core.invalid", "ssh-test", 4)
	defer a.Close("the test ends")
	a.SetCallTimeout(2500 * time.Millisecond)
	_, data := coreMessage(t, nil, shellTask(7, "sleep 30"))
	start := time.Now()
	ans := sealedCall(context.Background(), t, a, linkclient.Call{Request: 1, Values: srv.Values(), ID: [16]byte{1}, Data: data})
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the call took %s", took)
	}
	if ans.Failure != nil || ans.ID == nil {
		t.Fatalf("answer %+v", ans)
	}
	m := minionMessage(t, ans.Data)
	checkItems(t, m)
	if results := itemsOf[protocol.ResultItem](t, m, protocol.ItemResult); len(results) != 1 || *results[0].OK ||
		!strings.Contains(results[0].Err, "the call's deadline") {
		t.Fatalf("results %+v", results)
	}
}

// A login refused is a failure of its own kind; a message that does not
// open with the call's keys, or a call with none, is refused before any
// login.
func TestCallRefused(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	a := New("http://core.invalid", "ssh-test", 4)
	defer a.Close("the test ends")
	values := srv.Values()
	values["password"] = "wrong"
	_, data := coreMessage(t, nil, protocol.RehelloItem{T: protocol.ItemRehello})
	if ans := sealedCall(context.Background(), t, a, linkclient.Call{Request: 1, Values: values, Data: data}); ans.Failure == nil ||
		ans.Failure.Kind != protocol.LinkFailLogin {
		t.Fatalf("answer %+v", ans)
	}
	if ans := a.Call(context.Background(), linkclient.Call{Request: 2, Values: srv.Values(), Data: []byte{1, 2, 3}, Keys: testLinkKeys}); ans.Failure == nil ||
		ans.Failure.Kind != protocol.LinkFailOther {
		t.Fatalf("a message that does not open with the call's keys: %+v", ans)
	}
	if ans := a.Call(context.Background(), linkclient.Call{Request: 3, Values: srv.Values(), Data: data}); ans.Failure == nil ||
		ans.Failure.Kind != protocol.LinkFailOther {
		t.Fatalf("a call without keys: %+v", ans)
	}
	if st := a.Stats(); st.CallsFailed != 3 {
		t.Fatalf("stats %+v", st)
	}
}

// A hello core refuses leaves the minion nothing to do: the connection
// closes, saying why.
func TestSessionHelloRefused(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	tg, err := connection.ReadTarget(srv.Values())
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshconn.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	core := newFakeCore()
	buildID := bytes.Repeat([]byte{0xb}, 16)
	s := newSession(tg, c, core, 1, buildID, testKeys)
	ended := make(chan struct{})
	go func() {
		s.run()
		close(ended)
	}()
	m := minionMessage(t, core.next(t).Data) // its hello, first
	zero := 0
	_, data := coreMessage(t, m.ID, protocol.ErrItem{T: protocol.ItemErr, Code: protocol.ErrItemBadMessage, Msg: "not taken", Item: &zero})
	core.toMinion <- protocol.ConnFrame{ID: buildID, Data: data}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection outlived core's refusal of the hello")
	}
}

// fakeCore is a connection's socket as core holds it, for tests.
type fakeCore struct {
	toMinion   chan protocol.ConnFrame
	fromMinion chan protocol.ConnFrame
	closed     chan struct{}
}

func newFakeCore() *fakeCore {
	return &fakeCore{toMinion: make(chan protocol.ConnFrame, 16), fromMinion: make(chan protocol.ConnFrame, 16), closed: make(chan struct{})}
}

func (f *fakeCore) Send(_ context.Context, fr protocol.ConnFrame) error {
	// The minion's frames, opened as core opens them: the tests read the
	// messages.
	plain, err := protocol.OpenFrame(testKeys, [16]byte(fr.ID), protocol.FrameMinionToCore, fr.Data)
	if err != nil {
		return fmt.Errorf("the minion's frame does not open: %w", err)
	}
	fr.Data = plain
	select {
	case f.fromMinion <- fr:
		return nil
	case <-f.closed:
		return errors.New("closed")
	}
}

func (f *fakeCore) Receive(_ context.Context) (protocol.ConnFrame, error) {
	select {
	case fr := <-f.toMinion:
		// Core's frames, sealed as core seals them.
		sealed, err := protocol.SealFrame(testKeys, [16]byte(fr.ID), protocol.FrameCoreToMinion, fr.Data)
		if err != nil {
			return protocol.ConnFrame{}, err
		}
		fr.Data = sealed
		return fr, nil
	case <-f.closed:
		return protocol.ConnFrame{}, errors.New("closed")
	}
}

func (f *fakeCore) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fakeCore) next(t *testing.T) protocol.ConnFrame {
	t.Helper()
	select {
	case fr := <-f.fromMinion:
		return fr
	case <-time.After(10 * time.Second):
		t.Fatal("the minion said nothing")
	}
	return protocol.ConnFrame{}
}

// Over a persistent connection the minion speaks first: its hello alone,
// under the id the open gave (here the build's); then under the session id
// core gives, it runs the tasks core pushes, its allowance standing.
func TestSession(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	tg, err := connection.ReadTarget(srv.Values())
	if err != nil {
		t.Fatal(err)
	}
	c, err := sshconn.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	core := newFakeCore()
	buildID := bytes.Repeat([]byte{0xb}, 16)
	s := newSession(tg, c, core, 1, buildID, testKeys)
	ended := make(chan struct{})
	go func() {
		s.run()
		close(ended)
	}()

	fr := core.next(t)
	m := minionMessage(t, fr.Data)
	checkItems(t, m)
	// Under the build id: the hello alone, as core takes it.
	if err := protocol.ValidateBuildMessage(m.Items); err != nil || !bytes.Equal(fr.ID, buildID) ||
		len(itemsOf[protocol.HelloItem](t, m, protocol.ItemHello)) != 1 {
		t.Fatalf("the hello: %+v (%v)", m, err)
	}
	sid := bytes.Repeat([]byte{0x5}, 16)
	_, data := coreMessage(t, m.ID, protocol.HelloResponseItem{T: protocol.ItemHelloResponse, SID: sid})
	core.toMinion <- protocol.ConnFrame{ID: buildID, Data: data}

	// Then its standing allowance, under the session id.
	fr = core.next(t)
	m = minionMessage(t, fr.Data)
	checkItems(t, m)
	if gets := itemsOf[protocol.GetTasksItem](t, m, protocol.ItemGetTasks); !bytes.Equal(fr.ID, sid) || len(gets) != 1 || *gets[0].Max != ops.MaxTasks {
		t.Fatalf("after the hello: %+v", m)
	}
	_, data = coreMessage(t, m.ID)
	core.toMinion <- protocol.ConnFrame{ID: sid, Data: data}

	// A task pushed: acked, run, its result under the session id.
	_, data = coreMessage(t, nil, shellTask(3, "echo pushed"))
	core.toMinion <- protocol.ConnFrame{ID: sid, Data: data}
	var got []protocol.ResultItem
	for len(got) == 0 || !got[len(got)-1].Done {
		fr = core.next(t)
		m = minionMessage(t, fr.Data)
		checkItems(t, m)
		if !bytes.Equal(fr.ID, sid) {
			t.Fatalf("a message under %x, not the session's", fr.ID)
		}
		got = append(got, itemsOf[protocol.ResultItem](t, m, protocol.ItemResult)...)
		_, data = coreMessage(t, m.ID)
		core.toMinion <- protocol.ConnFrame{ID: sid, Data: data}
	}
	if !*got[len(got)-1].OK || !bytes.Contains(bytes.Join([][]byte{got[0].Out, got[len(got)-1].Out}, nil), []byte("pushed")) {
		t.Fatalf("results %+v", got)
	}

	// Core closes the socket: the SSH connection goes with it.
	_ = core.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end")
	}
	if c.Alive(time.Second) {
		t.Fatal("the SSH connection outlived the socket")
	}
}

// A call to a Windows server: its hello says windows, and a listing says
// its paths as Windows writes them. Every item passes core's checks, also
// where the server's PowerShell and cmd say nothing.
func TestCallWindows(t *testing.T) {
	dir := t.TempDir()
	srv := sshtest.NewWindows(t, dir, func(context.Context, string, io.Writer, io.Writer) int { return 1 })
	if err := os.WriteFile(filepath.Join(dir, "Users", srv.User, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New("http://core.invalid", "ssh-test", 4)
	defer a.Close("the test ends")
	ls := protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{5}, 16), Cmd: ops.Ls, Args: protocol.Args{minion.ArgLsPath: "~"}}
	_, data := coreMessage(t, nil, protocol.RehelloItem{T: protocol.ItemRehello}, ls)
	ans := sealedCall(context.Background(), t, a, linkclient.Call{Request: 1, Values: srv.Values(), ID: [16]byte{1}, Data: data})
	if ans.Failure != nil || ans.ID == nil {
		t.Fatalf("answer %+v", ans)
	}
	m := minionMessage(t, ans.Data)
	checkItems(t, m)
	hello := itemsOf[protocol.HelloItem](t, m, protocol.ItemHello)
	results := itemsOf[protocol.ResultItem](t, m, protocol.ItemResult)
	if len(hello) != 1 || hello[0].OS != "windows" || len(results) != 1 || len(results[0].Ls) == 0 {
		t.Fatalf("hello %+v, results %+v", hello, results)
	}
	piece := results[0].Ls[0]
	if piece.Path != `C:\Users\`+srv.User || piece.Sep != `\` || piece.Parent != `C:\Users` || len(piece.Entries) != 1 || piece.Entries[0].Name != "f.txt" {
		t.Fatalf("listing %+v", piece)
	}
}
