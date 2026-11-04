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
// the connection's socket, and core speaks first the moment the socket is
// up (its firstWord, before the channel has even run its session): a
// rehello under the build id, which the minion answers with its hello.
func TestOpenCoreSpeaksAtOnce(t *testing.T) {
	srv := sshtest.New(t, t.TempDir())
	buildID := bytes.Repeat([]byte{0xb}, 16)
	got := make(chan protocol.ConnFrame, 8)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		_, data := coreMessage(t, nil, protocol.RehelloItem{T: protocol.ItemRehello})
		b, err := protocol.EncodeConnFrame(protocol.ConnFrame{ID: buildID, Data: data})
		if err != nil || ws.Write(r.Context(), websocket.MessageBinary, b) != nil {
			return
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ans := a.Open(ctx, linkclient.Open{Request: 7, Values: srv.Values()})
	cancel() // as the control link does once the open answered
	if ans.Failure != nil {
		t.Fatalf("open: %+v", ans.Failure)
	}
	select {
	case f := <-got:
		m := minionMessage(t, f.Data)
		checkItems(t, m)
		if err := protocol.ValidateBuildMessage(m.Items); err != nil || !bytes.Equal(f.ID, buildID) ||
			len(itemsOf[protocol.HelloItem](t, m, protocol.ItemHello)) != 1 {
			t.Fatalf("under %x: %+v (%v)", f.ID, m, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no hello: the minion did not answer core's first word")
	}
}
