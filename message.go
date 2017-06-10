package doubleratchet

// Message is a single message exchanged by the parties.
type Message struct {
	Header  MessageHeader
	Payload []byte
}

// MessageHeader that is prepended to every message.
type MessageHeader struct {
	// DHr is the sender's current ratchet public key.
	PublicKey []byte

	// N is the number of the message in the sending chain.
	N uint

	// Pn is the length of the previous sending chain.
	Pn uint
}

// MarshalBinary makes MessageHeader implement the BinaryMarshaler interface.
func (mh MessageHeader) MarshalBinary() ([]byte, error) {
	// TODO: Implement.
	return []byte{}, nil
}
