package doubleratchet

// TODO: For Bob to be able to send messages right after he initiated a session it's required
// to populate his sending chain with the shared secret. Should it be the same secret both
// parties agreed upon before the communication or should it be a separate key?
// TODO: When the new public key should be reset?
// TODO: Max chain length? What happens when N in message header closes in on overflowing? Perform Ratchet step?

// Any Double Ratchet message encrypted using Alice's initial sending chain can serve as
// an "initial ciphertext" for X3DH. To deal with the possibility of lost or out-of-order messages,
// a recommended pattern is for Alice to repeatedly send the same X3DH initial message prepended
// to all of her Double Ratchet messages until she receives Bob's first Double Ratchet response message.

import (
	"fmt"
)

const (
	// MaxSkip specifies the maximum number of message keys that can be skipped in a single chain.
	MaxSkip = 1000

	// TODO: nonces?
)

// State is a state of the party involved in The Double Ratchet message exchange.
// Operations on this object are NOT THREAD-SAFE, make sure they're done in sequence.
// TODO: Store skipper separately.
// TODO: Store state separately?
type State struct {
	// 32-byte root key. Both parties MUST agree on this key before starting a ratchet session.
	RK [32]byte

	// DH Ratchet public key (the remote key).
	DHr [32]byte

	// DH Ratchet key pair (the self ratchet key).
	DHs DHPair

	// 32-byte Chain Keys for sending and receiving.
	CKs, CKr [32]byte

	// Message numbers for sending and receiving.
	Ns, Nr uint

	// Number of messages in previous sending chain.
	PN uint

	// Dictionary of skipped-over message keys, indexed by ratchet public key and message number.
	MkSkipped map[string][32]byte

	// MaxSkip should be set high enough to tolerate routine lost or delayed messages,
	// but low enough that a malicious sender can't trigger excessive recipient computation.
	MaxSkip uint

	// Cryptography functions for the Double Ratchet Algorithm to function.
	Crypto Crypto
}

// TODO: Set up optional values with functional options.
// New creates State with the shared key and public key of the other party initiating the session.
// If this party initiates the session, pubKey must be nil.
func New(sharedKey, dhRemotePubKey [32]byte) (*State, error) {
	if len(sharedKey) == 0 {
		return nil, fmt.Errorf("sharedKey must be set")
	}
	s := &State{
		RK:        sharedKey,
		DHr:       dhRemotePubKey,
		MkSkipped: make(map[string][32]byte),
		MaxSkip:   MaxSkip,
		Crypto:    DefaultCrypto{},
	}
	// TODO: Implement option arguments and traverse through them.

	var err error
	s.DHs, err = s.Crypto.GenerateDH()
	if err != nil {
		return nil, fmt.Errorf("failed to generate dh pair: %s", err)
	}
	// FIXME: Make dhRemotePubKey optional.
	if len(dhRemotePubKey) > 0 {
		s.RK, s.CKs = s.Crypto.KdfRK(sharedKey, s.Crypto.DH(s.DHs, s.DHr))
	}
	return s, nil
}

// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
// the resulting message key.
func (s *State) RatchetEncrypt(plaintext []byte, ad AssociatedData) Message {
	var mk [32]byte
	s.CKs, mk = s.Crypto.KdfCK(s.CKs)
	h := MessageHeader{
		DH: s.DHs.PublicKey,
		N:  s.Ns,
		PN: s.PN,
	}
	s.Ns++
	ciphertext := s.Crypto.Encrypt(mk, plaintext, h.EncodeWithAD(ad))
	return Message{
		Header:     h,
		Ciphertext: ciphertext,
	}
}

// RatchetDecrypt is called to decrypt messages.
func (s *State) RatchetDecrypt(m Message, ad AssociatedData) ([]byte, error) {
	plaintext, err := s.trySkippedMessageKeys(m, ad)
	if err != nil {
		return nil, fmt.Errorf("can't decrypt skipped message: %s", err)
	}
	if plaintext != nil {
		return plaintext, nil
	}
	if m.Header.DH != s.DHs.PublicKey {
		s.skipMessageKeys(m.Header.PN)
		if err := s.dhRatchet(m.Header); err != nil {
			// TODO: Rollback state changes.
			return nil, fmt.Errorf("failed to perform ratchet step: %s", err)
		}
	}
	s.skipMessageKeys(m.Header.N)
	var mk [32]byte
	s.CKr, mk = s.Crypto.KdfCK(s.CKr)
	s.Nr++
	// TODO: Discard the message in case of error and rollback the skipped key.
	return s.Crypto.Decrypt(mk, m.Ciphertext, m.Header.EncodeWithAD(ad))
}

// trySkippedMessageKeys tries to decrypt the message with a skipped message key.
func (s *State) trySkippedMessageKeys(m Message, ad AssociatedData) ([]byte, error) {
	skippedKey := s.skippedKey(m.Header.DH[:], m.Header.N)
	if mk, ok := s.MkSkipped[skippedKey]; ok {
		delete(s.MkSkipped, skippedKey)
		// TODO: Discard the message in case of error and rollback the skipped key.
		return s.Crypto.Decrypt(mk, m.Ciphertext, m.Header.EncodeWithAD(ad))
	}
	return nil, nil
}

// skippedKey forms a key for a skipped message.
func (s *State) skippedKey(dh []byte, n uint) string {
	// TODO: More compact representation.
	nByte := []byte(fmt.Sprintf("_%d", n))
	return string(append(dh, nByte...))
}

// skipMessageKeys skips message keys in the current receiving chain.
func (s *State) skipMessageKeys(until uint) {
	// TODO: What is it?..
	if s.Nr+s.MaxSkip < until {
		// TODO: Return error.
		return
	}
	// TODO: Why?..
	// TODO: Fill CKr with something so that there's no such a check.
	//if s.CKr != nil {
	//for s.Nr < until {
	//	var mk [32]byte
	//	s.CKr, mk = s.Crypto.KdfCK(s.CKr)
	//	s.MkSkipped[s.skippedKey(s.DHr[:], s.Nr)] = mk
	//	s.Nr += 1
	//}
	//}
}

// dhRatchet performs a single ratchet step.
func (s *State) dhRatchet(mh MessageHeader) error {
	// TODO: Discard state changes in case of error.
	var err error

	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = mh.DH
	s.RK, s.CKr = s.Crypto.KdfRK(s.RK, s.Crypto.DH(s.DHs, s.DHr))
	s.DHs, err = s.Crypto.GenerateDH()
	if err != nil {
		return fmt.Errorf("failed to generate dh pair: %s", err)
	}
	s.RK, s.CKs = s.Crypto.KdfRK(s.RK, s.Crypto.DH(s.DHs, s.DHr))
	return nil
}
