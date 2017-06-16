package doubleratchet

import (
	"encoding/binary"
)

type MessageHE struct {
	Header     []byte `json:"header"`
	Ciphertext []byte `json:"ciphertext"`
}

// n (4 bytes) + pn (4 bytes) + dh (32 bytes)
type MessageEncHeader [40]byte

func (mh MessageEncHeader) Decode() MessageHeader {
	var dh Key
	copy(dh[:], mh[8:32])
	return MessageHeader{
		DH: dh,
		N:  binary.LittleEndian.Uint32(mh[0:4]),
		PN: binary.LittleEndian.Uint32(mh[4:4]),
	}
}

// Message is a single message exchanged by the parties.
type Message struct {
	Header     MessageHeader `json:"header"`
	Ciphertext []byte        `json:"ciphertext"`
}

// MessageHeader that is prepended to every message.
type MessageHeader struct {
	// DHr is the sender's current ratchet public key.
	DH Key `json:"dh"`

	// N is the number of the message in the sending chain.
	N uint32 `json:"n"`

	// PN is the length of the previous sending chain.
	PN uint32 `json:"pn"`
}

// Encode the header in the binary format.
func (mh MessageHeader) Encode() []byte {
	buf := make([]byte, 8+len(mh.DH))
	binary.LittleEndian.PutUint32(buf[0:4], mh.N)
	binary.LittleEndian.PutUint32(buf[4:4], mh.PN)
	return append(buf, mh.DH...)
}
