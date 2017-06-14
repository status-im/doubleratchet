package doubleratchet

// TODO: During each DH ratchet step a new ratchet key pair and sending chain are generated.
// As the sending chain is not needed right away, these steps could be deferred until the party
// is about to send a new message.

import (
	"fmt"
)

// State of the party involved in The Double Ratchet Algorithm.
type State interface {
	// RatchetEncrypt performs a symmetric-key ratchet step, then AEAD-encrypts the message with
	// the resulting message key.
	RatchetEncrypt(plaintext []byte, ad AssociatedData) Message

	// RatchetDecrypt is called to AEAD-decrypt messages.
	RatchetDecrypt(m Message, ad AssociatedData) ([]byte, error)

	// PublicKey returns the session's ratchet public key.
	PublicKey() Key
}

// Operations on this object are NOT THREAD-SAFE, make sure they're done in sequence.
type state struct {
	// 32-byte root key. Both parties MUST agree on this key before starting a ratchet session.
	RK Key

	// DH Ratchet public key (the remote key).
	DHr Key

	// DH Ratchet key pair (the self ratchet key).
	DHs DHPair

	// 32-byte Chain Keys for sending and receiving.
	CKs, CKr Key

	// Message numbers for sending and receiving.
	Ns, Nr uint

	// Number of messages in previous sending chain.
	PN uint

	// Cryptography functions for the Double Ratchet Algorithm to function.
	Crypto Crypto

	// Dictionary of skipped-over message keys, indexed by ratchet public key and message number.
	MkSkipped KeysStorage

	// The maximum number of message keys that can be skipped in a single chain.
	// MaxSkip should be set high enough to tolerate routine lost or delayed messages,
	// but low enough that a malicious sender can't trigger excessive recipient computation.
	MaxSkip uint

	// Number of ratchet steps after which all skipped message keys for that public key will be deleted.
	MaxKeep uint

	// The number of the current ratchet step.
	Step uint

	// Shows what public key for the receiving chain was used at the specified step.
	PubKeys map[uint]Key
}

// New creates state with the shared key and public key of the other party initiating the session.
// If this party initiates the session, pubKey must be nil.
func New(sharedKey Key, opts ...Option) (State, error) {
	if sharedKey == [32]byte{} {
		return nil, fmt.Errorf("sharedKey must be non-zero")
	}
	s := &state{
		RK:        sharedKey,
		CKs:       sharedKey, // Populate CKs and CKr with sharedKey as per specification so that both
		CKr:       sharedKey, // parties could send and receive messages from the very beginning.
		MkSkipped: &KeysStorageInMemory{},
		MaxSkip:   1000,
		MaxKeep:   10,
		Crypto:    DefaultCrypto{},
		PubKeys:   make(map[uint]Key),
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
func WithRemoteKey(dhRemotePubKey Key) Option {
	return func(s *state) error {
		s.DHr = dhRemotePubKey
		s.RK, s.CKs = s.Crypto.KdfRK(s.RK, s.Crypto.DH(s.DHs, s.DHr))
		return nil
	}
}

// WithMaxSkip specifies the maximum number of skipped message in a single chain.
func WithMaxSkip(n int) Option {
	return func(s *state) error {
		if n < 0 {
			return fmt.Errorf("n must be non-negative")
		}
		s.MaxSkip = uint(n)
		return nil
	}
}

// TODO: WithKeysStorage.
// TODO: WithCrypto.
// TODO: WithMaxKeep.

// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
// the resulting message key.
func (s *state) RatchetEncrypt(plaintext []byte, ad AssociatedData) Message {
	var mk Key
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
	// All changes must be applied on a different state object, so that this state won't be modified nor left in a dirty state.
	var sc state = *s

	// DEBUG
	//fmt.Printf("%+v\n\n", sc)
	//defer fmt.Printf("%+v\n\n", s)

	// Is the messages one of the skipped?
	plaintext, err := sc.trySkippedMessageKeys(m, ad)
	if err != nil {
		return nil, fmt.Errorf("can't try skipped message: %s", err)
	}
	if plaintext != nil {
		return plaintext, nil
	}

	// Is there a new ratchet key?
	if m.Header.DH != sc.DHr {
		if err := sc.skipMessageKeys(m.Header.PN); err != nil {
			return nil, fmt.Errorf("failed to skip previous chain message keys: %s", err)
		}
		if err := sc.dhRatchet(m.Header); err != nil {
			return nil, fmt.Errorf("failed to perform ratchet step: %s", err)
		}
	}

	// After all, apply changes on the current chain.
	if err := sc.skipMessageKeys(m.Header.N); err != nil {
		return nil, fmt.Errorf("failed to skip current chain message keys: %s", err)
	}
	var mk Key
	sc.CKr, mk = sc.Crypto.KdfCK(sc.CKr)
	sc.Nr++
	plaintext, err = sc.Crypto.Decrypt(mk, m.Ciphertext, m.Header.EncodeWithAD(ad))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %s", err)
	}

	*s = sc

	return plaintext, nil
}

func (s *state) PublicKey() Key {
	return s.DHs.PublicKey()
}

// trySkippedMessageKeys tries to decrypt the message with a skipped message key.
func (s *state) trySkippedMessageKeys(m Message, ad AssociatedData) ([]byte, error) {
	if mk, ok := s.MkSkipped.Get(m.Header.DH, m.Header.N); ok {
		plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, m.Header.EncodeWithAD(ad))
		if err != nil {
			return nil, fmt.Errorf("can't decrypt message: %s", err)
		}
		s.MkSkipped.DeleteMk(m.Header.DH, m.Header.N)
		return plaintext, nil
	}
	return nil, nil
}

// skipMessageKeys skips message keys in the current receiving chain.
func (s *state) skipMessageKeys(until uint) error {
	nSkipped := s.MkSkipped.Count(s.DHr)
	if until-s.Nr+nSkipped > s.MaxSkip {
		return fmt.Errorf("too many messages")
	}
	for s.Nr < until {
		var mk Key
		s.CKr, mk = s.Crypto.KdfCK(s.CKr)
		// FIXME: Changes to MkSkipped must not affect state.
		s.MkSkipped.Put(s.DHr, s.Nr, mk)
		s.Nr++
	}
	return nil
}

// dhRatchet performs a single ratchet step.
func (s *state) dhRatchet(mh MessageHeader) error {
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

	// FIXME: Changes to PubKeys must not affect the state object.
	s.PubKeys[s.Step] = s.DHr
	s.Step++
	if pubKey, ok := s.PubKeys[s.Step-s.MaxKeep]; ok {
		s.MkSkipped.DeletePk(pubKey)
	}

	return nil
}
