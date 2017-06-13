package doubleratchet

// TODO: For Bob to be able to send messages right after he initiated a session it's required
// to populate his sending chain with the shared secret. Should it be the same secret both
// parties agreed upon before the communication or should it be a separate key?
// TODO: Max chain length? What happens when N in message header closes in on overflowing? Perform Ratchet step?

// TODO
// Any Double Ratchet message encrypted using Alice's initial sending chain can serve as
// an "initial ciphertext" for X3DH. To deal with the possibility of lost or out-of-order messages,
// a recommended pattern is for Alice to repeatedly send the same X3DH initial message prepended
// to all of her Double Ratchet messages until she receives Bob's first Double Ratchet response message.

import (
	"fmt"
)

// State of the party involved in The Double Ratchet Algorithm.
type State interface {
	// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
	// the resulting message key.
	RatchetEncrypt(plaintext []byte, ad AssociatedData) Message

	// RatchetDecrypt is called to decrypt messages.
	RatchetDecrypt(m Message, ad AssociatedData) ([]byte, error)
}

// Operations on this object are NOT THREAD-SAFE, make sure they're done in sequence.
// TODO: Store skipper separately.
// TODO: Store state separately?
type state struct {
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

// New creates state with the shared key and public key of the other party initiating the session.
// If this party initiates the session, pubKey must be nil.
func New(sharedKey [32]byte, opts ...Option) (State, error) {
	if sharedKey == [32]byte{} {
		return nil, fmt.Errorf("sharedKey must be non-zero")
	}
	s := &state{
		RK:        sharedKey,
		MkSkipped: make(map[string][32]byte),
		MaxSkip:   1000,
		Crypto:    DefaultCrypto{},
	}

	var err error
	s.DHs, err = s.Crypto.GenerateDH()
	if err != nil {
		return nil, fmt.Errorf("failed to generate dh pair: %s", err)
	}

	for i := range opts {
		if err := opts[i](s); err != nil {
			return nil, fmt.Errorf("failed to apply option: %s", err)
		}
	}

	return s, nil
}

// Option is a constructor option.
type Option func(*state) error

// WithRemoteKey specifies the remote public key for the sending chain.
func WithRemoteKey(dhRemotePubKey [32]byte) Option {
	return func(s *state) error {
		s.DHr = dhRemotePubKey
		s.RK, s.CKs = s.Crypto.KdfRK(s.RK, s.Crypto.DH(s.DHs, s.DHr))
		return nil
	}
}

// WithMaxSkip specifies the maximum number of skipped message in a single chain.
func WithMaxSkip(maxSkip int) Option {
	return func(s *state) error {
		if maxSkip < 0 {
			return fmt.Errorf("maxSkip must be non-negative")
		}
		s.MaxSkip = uint(maxSkip)
		return nil
	}
}

// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
// the resulting message key.
func (s *state) RatchetEncrypt(plaintext []byte, ad AssociatedData) Message {
	var mk [32]byte
	s.CKs, mk = s.Crypto.KdfCK(s.CKs)
	h := MessageHeader{
		DH: s.DHs.PublicKey(),
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
func (s *state) RatchetDecrypt(m Message, ad AssociatedData) ([]byte, error) {
	// Is the messages one of the skipped?
	plaintext, err := s.trySkippedMessageKeys(m, ad)
	if err != nil {
		return nil, fmt.Errorf("can't decrypt skipped message: %s", err)
	}
	if plaintext != nil {
		return plaintext, nil
	}

	// Is there a new ratchet key?
	if m.Header.DH != s.DHr {
		if err := s.skipMessageKeys(m.Header.PN); err != nil {
			return nil, fmt.Errorf("failed to skip previous chain message keys: %s", err)
		}
		if err := s.dhRatchet(m.Header); err != nil {
			// TODO: Rollback state changes.
			return nil, fmt.Errorf("failed to perform ratchet step: %s", err)
		}
	}

	// After all, apply changes on the current chain.
	if err := s.skipMessageKeys(m.Header.N); err != nil {
		return nil, fmt.Errorf("failed to skip current chain message keys: %s", err)
	}
	var mk [32]byte
	s.CKr, mk = s.Crypto.KdfCK(s.CKr)
	s.Nr++
	plaintext, err = s.Crypto.Decrypt(mk, m.Ciphertext, m.Header.EncodeWithAD(ad))
	if err != nil {
		// TODO: Rollback state changes.
		return nil, fmt.Errorf("failed to decrypt: %s", err)
	}

	return plaintext, nil
}

// trySkippedMessageKeys tries to decrypt the message with a skipped message key.
func (s *state) trySkippedMessageKeys(m Message, ad AssociatedData) ([]byte, error) {
	k := s.skippedKey(m.Header.DH[:], m.Header.N)
	if mk, ok := s.MkSkipped[k]; ok {
		plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, m.Header.EncodeWithAD(ad))
		if err != nil {
			return nil, err
		}
		delete(s.MkSkipped, k)
		return plaintext, nil
	}
	return nil, nil
}

// skippedKey forms a key for a skipped message.
func (s *state) skippedKey(dh []byte, n uint) string {
	// TODO: More compact representation.
	nByte := []byte(fmt.Sprintf("_%d", n))
	return string(append(dh, nByte...))
}

// skipMessageKeys skips message keys in the current receiving chain.
func (s *state) skipMessageKeys(until uint) error {
	// until exceeds the number of messages in the receiving chain on more than s.MaxSkip
	if s.Nr+s.MaxSkip < until {
		return fmt.Errorf("too many messages: %d", until-s.Nr)
	}
	//TODO: Fill s.CKr in the very beginning.
	//if s.CKr != nil {
	//for s.Nr < until {
	//	var mk [32]byte
	//	s.CKr, mk = s.Crypto.KdfCK(s.CKr)
	//	s.MkSkipped[s.skippedKey(s.DHr[:], s.Nr)] = mk
	//	s.Nr += 1
	//}
	//}
	return nil
}

// dhRatchet performs a single ratchet step.
func (s *state) dhRatchet(mh MessageHeader) error {
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
