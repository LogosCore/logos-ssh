//go:build unix

package minion

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

// A reply reads back as the minion's message answering core's, its items
// as given; core's message reads as a message, a bad one does not.
func TestReplyAndReadCore(t *testing.T) {
	core := protocol.CoreMessage{V: protocol.MinionMessageV3, ID: protocol.NewMessageID(), At: 1}
	rehello, _ := protocol.MarshalCBOR(protocol.RehelloItem{T: protocol.ItemRehello})
	core.Items = []cbor.RawMessage{rehello}
	plain, _ := protocol.MarshalCBOR(core)
	got, err := ReadCore(plain)
	if err != nil || len(got.Items) != 1 || protocol.ItemType(got.Items[0]) != protocol.ItemRehello {
		t.Fatalf("read %+v %v", got, err)
	}
	if _, err := ReadCore([]byte{0xff}); err == nil {
		t.Fatal("junk read as core's message")
	}
	b, err := Reply(core.ID, []any{protocol.GetTasksItem{T: protocol.ItemGetTasks}})
	if err != nil {
		t.Fatal(err)
	}
	var m protocol.MinionMessage
	if err := protocol.UnmarshalCBOR(b, &m); err != nil || !bytes.Equal(m.Re, core.ID) || m.ID != nil || len(m.Items) != 1 ||
		protocol.ItemType(m.Items[0]) != protocol.ItemGetTasks || protocol.ValidateMessageHead(m.V, m.ID, m.Re, len(m.Items)) != nil {
		t.Fatalf("reply %+v %v", m, err)
	}
	id, b, err := Message(nil, nil)
	var own protocol.MinionMessage
	if err != nil || protocol.UnmarshalCBOR(b, &own) != nil || !bytes.Equal(own.ID, id) || own.Re != nil ||
		protocol.ValidateMessageHead(own.V, own.ID, own.Re, len(own.Items)) != nil {
		t.Fatalf("a message the minion starts: %+v %v", own, err)
	}
}
