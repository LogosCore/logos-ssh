//go:build unix

package agent

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/logoscore/logos-golang-channel-core/v3/pkg/linkclient"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// An open end to end, as core goes about it: the channel logs in, opens
// the connection's socket, and the minion speaks first, under the id the
// open gave: its hello alone. An open that gives no id is refused before
// any login.
func TestOpenMinionSpeaksFirst(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	buildID := [16]byte{0xb, 0xb, 0xb}
	got := make(chan protocol.ConnFrame, 8)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		for {
			_, b, err := ws.Read(r.Context())
			if err != nil {
				return
			}
			if f, err := protocol.DecodeConnFrame(b); err == nil {
				got <- f
			}
		}
	}))
	defer core.Close()
	a := New(core.URL, "ssh-test", 4)
	defer a.Close("the test ends")
	if ans := a.Open(context.Background(), linkclient.Open{Request: 6, Values: srv.Values(), Keys: testLinkKeys}); ans.Failure == nil ||
		ans.Failure.Kind != protocol.LinkFailOther {
		t.Fatalf("an open with no id: %+v", ans)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ans := a.Open(ctx, linkclient.Open{Request: 7, Values: srv.Values(), Under: buildID, Keys: testLinkKeys})
	cancel() // as the control link does once the open answered
	if ans.Failure != nil {
		t.Fatalf("open: %+v", ans.Failure)
	}
	select {
	case f := <-got:
		m := openedMessage(t, f)
		checkItems(t, m)
		if err := protocol.ValidateBuildMessage(m.Items); err != nil || !bytes.Equal(f.ID, buildID[:]) ||
			len(itemsOf[protocol.HelloItem](t, m, protocol.ItemHello)) != 1 {
			t.Fatalf("under %x: %+v (%v)", f.ID, m, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no hello: the minion did not speak first")
	}
}
