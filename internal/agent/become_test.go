//go:build unix

package agent

import (
	"bytes"
	"context"
	"os/user"
	"testing"

	"github.com/logoscore/logos-golang-channel-core/v3/pkg/linkclient"
	"github.com/logoscore/logos-golang-protocol/protocol"
	"github.com/logoscore/logos-ssh/internal/minion"
	"github.com/logoscore/logos-ssh/internal/ops"
	"github.com/logoscore/logos-ssh/internal/sshtest"
)

// A become in a call: the session's identity said, naming the task, after
// its ack and before its end. Core hands the task back with the next calls (acting): shell
// commands run elevated, file commands say they run as the login. A call
// without acting runs as the login, saying nothing. Every item passes
// core's checks.
func TestCallBecome(t *testing.T) {
	dir := t.TempDir()
	srv := sshtest.New(t, dir)
	sshtest.FakeBecome(t, srv.Password, "root-pw")
	a := New("http://core.invalid", "ssh-test", 4)
	defer a.Close("the test ends")
	values := srv.Values()
	values["call_reuse"] = "1m"
	sessionID := [16]byte{5}
	me, _ := user.Current()
	becomeID := bytes.Repeat([]byte{3}, 16)
	become := protocol.TaskItem{T: protocol.ItemTask, Task: becomeID, Cmd: ops.Become, Args: protocol.Args{}}

	call := func(acting *protocol.LinkActing, items ...any) protocol.MinionMessage {
		t.Helper()
		_, data := coreMessage(t, nil, items...)
		ans := sealedCall(context.Background(), t, a, linkclient.Call{Request: 1, Values: values, Credentials: srv.Credentials(),
			ID: sessionID, Data: data, Acting: acting})
		if ans.Failure != nil || ans.Data == nil {
			t.Fatalf("answer %+v", ans)
		}
		m := minionMessage(t, ans.Data)
		checkItems(t, m)
		return m
	}

	m := call(nil, become)
	ids := itemsOf[protocol.IdentityItem](t, m, protocol.ItemIdentity)
	results := itemsOf[protocol.ResultItem](t, m, protocol.ItemResult)
	if len(ids) != 1 || ids[0].Scope != protocol.IdentitySession || !bytes.Equal(ids[0].Task, becomeID) ||
		ids[0].How != protocol.IdentityBecome || ids[0].User != me.Username || ids[0].Credential != "" ||
		len(results) != 1 || !*results[0].OK {
		t.Fatalf("identities %+v, results %+v", ids, results)
	}
	if protocol.ItemType(m.Items[0]) != protocol.ItemAck || protocol.ItemType(m.Items[1]) != protocol.ItemIdentity {
		t.Fatal("not the become's ack, then the session's identity")
	}

	acting := &protocol.LinkActing{Task: becomeID, Cmd: ops.Become, Args: protocol.Args{}}
	ls := protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{4}, 16), Cmd: ops.Ls, Args: protocol.Args{minion.ArgLsPath: dir}}
	m = call(acting, shellTask(5, "echo elevated"), ls)
	ids = itemsOf[protocol.IdentityItem](t, m, protocol.ItemIdentity)
	results = itemsOf[protocol.ResultItem](t, m, protocol.ItemResult)
	if len(ids) != 1 || ids[0].Scope != protocol.IdentityTask || !bytes.Equal(ids[0].Task, ls.Task) || !ids[0].Own() {
		t.Fatalf("identities %+v", ids)
	}
	var shellOut string
	for _, r := range results {
		if r.Task[0] == 5 {
			shellOut = string(r.Out)
		}
	}
	if shellOut != "elevated\n" {
		t.Fatalf("results %+v", results)
	}

	m = call(nil, shellTask(6, "echo plain"))
	if ids := itemsOf[protocol.IdentityItem](t, m, protocol.ItemIdentity); len(ids) != 0 {
		t.Fatalf("identities without a become: %+v", ids)
	}

	// A refused become says nothing of the session.
	sshtest.FakeBecome(t, "another", "root-pw")
	m = call(nil, protocol.TaskItem{T: protocol.ItemTask, Task: bytes.Repeat([]byte{8}, 16), Cmd: ops.Become, Args: protocol.Args{}})
	results = itemsOf[protocol.ResultItem](t, m, protocol.ItemResult)
	if ids := itemsOf[protocol.IdentityItem](t, m, protocol.ItemIdentity); len(ids) != 0 || len(results) != 1 || *results[0].OK {
		t.Fatalf("identities %+v results %+v", ids, results)
	}
}
