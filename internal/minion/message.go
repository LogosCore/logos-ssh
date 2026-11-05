package minion

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/logoscore/logos-golang-protocol/protocol"
)

// ReadCore reads core's message from its CBOR, opened from its frame.
func ReadCore(plain []byte) (protocol.CoreMessage, error) {
	var m protocol.CoreMessage
	if err := protocol.UnmarshalCBOR(plain, &m); err != nil {
		return m, fmt.Errorf("core's message: %w", err)
	}
	if err := protocol.ValidateMessageHead(m.V, m.ID, m.Re, len(m.Items)); err != nil {
		return m, fmt.Errorf("core's message: %w", err)
	}
	return m, nil
}

// Reply is the minion's message answering core's message re (its id) with
// items, as CBOR, to seal into a frame.
func Reply(re []byte, items []any) ([]byte, error) {
	_, b, err := Message(re, items)
	return b, err
}

// Message is a minion's message with items: answering core's message re,
// or, re nil, one the minion starts, with an id of its own that core's
// reply answers (a message has one or the other). It returns that id (nil
// for an answer) and the message's CBOR.
func Message(re []byte, items []any) ([]byte, []byte, error) {
	msg := protocol.MinionMessage{V: protocol.MinionMessageV3, Re: re}
	if re == nil {
		msg.ID = protocol.NewMessageID()
	}
	for _, it := range items {
		raw, err := protocol.MarshalCBOR(it)
		if err != nil {
			return nil, nil, err
		}
		msg.Items = append(msg.Items, cbor.RawMessage(raw))
	}
	b, err := protocol.MarshalCBOR(msg)
	return msg.ID, b, err
}
