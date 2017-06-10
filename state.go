package doubleratchet

// TODO: For Bob to be able to send messages right after he initiated a session it's required
// to populate his sending chain with the shared secret. Should it be the same secret both
// parties agreed upon before the communication or should it be a separate key?
// TODO: When the new public key should be reset?
// TODO: Max chain length? What happens when N in message header closes in on overflowing? Perform Ratchet step?

import "errors"

const (
	// MaxSkip specifies the maximum number of message keys that can be skipped in a single chain.
	MaxSkip = 1000

	// TODO: nonces.
)

// State is a state of the party involved in The Double Ratchet message exchange.
// Operations on this object are NOT THREAD-SAFE, make sure they're done in sequence.
type State struct {
	// 32-byte root key. Both parties MUST agree on this key before starting a ratchet session.
	RK []byte

	// DH Ratchet public key (the remote key).
	DHr []byte

	// DH Ratchet key pair (the self ratchet key).
	DHs DHKeyPair

	// 32-byte Chain Keys for sending and receiving.
	CKs, CKr []byte

	// Message numbers for sending and receiving.
	Ns, Nr uint

	// Number of messages in previous sending chain.
	Pn uint

	// Dictionary of skipped-over message keys, indexed by ratchet public key and message number.
	MkSkipped map[string][]byte

	// MaxSkip should be set high enough to tolerate routine lost or delayed messages,
	// but low enough that a malicious sender can't trigger excessive recipient computation.
	MaxSkip uint

	// Cryptography functions for the Double Ratchet Algorithm to function.
	Crypto Crypto
}

// TODO: Set up optional values with functional options.
// New creates State with the shared key and public key of the other party initiating the session.
// If this party initiates the session, pubKey must be nil.
func New(sharedKey, dhRemotePubKey []byte) (*State, error) {
	if len(sharedKey) == 0 {
		return nil, errors.New("sharedKey must be set")
	}
	s := &State{
		RK:        sharedKey,
		DHr:       dhRemotePubKey,
		MkSkipped: make(map[string][]byte),
		MaxSkip:   MaxSkip,
		Crypto:    CryptoRecommended{},
	}
	// TODO: Implement option arguments and traverse through them.

	s.DHs = s.Crypto.GenerateDH()
	if len(dhRemotePubKey) > 0 {
		s.RK, s.CKs = s.Crypto.KdfRK(sharedKey, s.Crypto.DH(s.DHs, s.DHr))
	}
	return s, nil
}

// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
// the resulting message key.
func (s *State) RatchetEncrypt(plaintext, associatedData []byte) Message {
	var mk []byte
	s.CKs, mk = s.Crypto.KdfCK(s.CKs)

	var (
		h = MessageHeader{
			PublicKey: s.DHs.PublicKey,
			N:         s.Ns,
			Pn:        s.Pn,
		}
		// TODO: Are lengths more than 255 needed?
		adEncoded   = append([]byte{byte(len(associatedData))}, associatedData...)
		hEncoded, _ = h.MarshalBinary() // No error can happen here.
	)
	s.Ns++
	return Message{
		Header:  h,
		Payload: s.Crypto.Encrypt(mk, plaintext, append(adEncoded, hEncoded...)),
	}
}

//// Receive handles receiving a new message from the other party.
//func (s *State) Receive(msg Message) {
//	// TODO: Implement.
//}

//// performDHRatchetStep performs a single ratchet step deriving a new DH output.
//func (s *State) performDHRatchetStep(pubKey []byte) {
//	dhOutput := s.calculateDHOutput(s.DHs.PrivateKey, pubKey)
//	s.DHs = dhOutput
//	// TODO: Derive new receiving/sending chain key.
//	s.calculateDHOutput(s.DHs.PrivateKey, pubKey)
//	// TODO: Derive new sending/receiving chain key.
//	// TODO: Store new root key.
//}
