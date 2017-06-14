package doubleratchet

import "fmt"

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
	N uint `json:"n"`

	// PN is the length of the previous sending chain.
	PN uint `json:"pn"`
}

// MarshalBinary makes MessageHeader implement the BinaryMarshaler interface.
func (mh MessageHeader) MarshalBinary() ([]byte, error) {
	var (
		r    = []byte{}
		nums = []byte(fmt.Sprintf("_%d_%d", mh.N, mh.PN))
	)
	r = append(r, mh.DH[:]...)
	return append(r, nums...), nil
}

// EncodeWithAD is a helper method to encode the header together with the associated data.
// TODO: Should it be here?
func (mh MessageHeader) EncodeWithAD(ad AssociatedData) []byte {
	adEncoded, _ := ad.MarshalBinary() // No error can happen here.
	hEncoded, _ := mh.MarshalBinary()  // No error can happen here.
	return append(adEncoded, hEncoded...)
}
