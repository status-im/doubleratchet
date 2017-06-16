package doubleratchet

// TODO: During each DH ratchet step a new ratchet key pair and sending chain are generated.
// As the sending chain is not needed right away, these steps could be deferred until the party
// is about to send a new message.

import (
	"fmt"
)

// Session of the party involved in the Double Ratchet Algorithm.
type Session interface {
	// RatchetEncrypt performs a symmetric-key ratchet step, then AEAD-encrypts the message with
	// the resulting message key.
	RatchetEncrypt(plaintext, associatedData []byte) Message

	// RatchetDecrypt is called to AEAD-decrypt messages.
	RatchetDecrypt(m Message, associatedData []byte) ([]byte, error)

	PublicKeyer
}

// SessionHE is the session of the party involved the Double Ratchet Algorithm with encrypted header modification.
type SessionHE interface {
	// RatchetEncryptHE performs a symmetric-key ratchet step, then AEAD-encrypts
	// the header-encrypted message with the resulting message key.
	RatchetEncryptHE(plaintext, associatedData []byte) MessageHE

	// RatchetDecryptHE is called to AEAD-decrypt header-encrypted messages.
	RatchetDecryptHE(m MessageHE, associatedData []byte) ([]byte, error)

	PublicKeyer
}

type PublicKeyer interface {
	// PublicKey returns the session's ratchet public key.
	PublicKey() Key
}

type rootChain struct {
	Crypto Crypto // TODO: Only KdfRK is used + KdfCK is needed to pass it to chain.

	// 32-byte chain key.
	CK Key
}

func (c rootChain) Step(kdfInput Key) chain {
	ch := chain{
		Crypto: c.Crypto,
	}
	c.CK, ch.CK = c.Crypto.KdfRK(c.CK, kdfInput)
	return ch
}

type chain struct {
	Crypto Crypto // TODO: Only KdfCK is used.

	// 32-byte chain key.
	CK Key

	// Messages count in the chain.
	N uint32

	// Header Key and Next Header Key.
	HK, NHK Key
}

// Step performs chain step and returns message key.
func (c chain) Step() Key {
	var mk Key
	c.CK, mk = c.Crypto.KdfCK(c.CK)
	c.N = 0
	return mk
}

// The double ratchet state.
type state struct {
	Crypto Crypto

	// DH Ratchet public key (the remote key).
	DHr Key

	// DH Ratchet key pair (the self ratchet key).
	DHs DHPair

	// Symmetric ratchet root chain.
	RootCh rootChain

	// Symmetric ratchet sending chain.
	SendCh chain

	// Symmetric ratchet receiving chain.
	RecvCh chain

	// Number of messages in previous sending chain.
	PN uint32
}

func newState(sharedKey Key, c Crypto) (state, error) {
	dhs, err := c.GenerateDH()
	if err != nil {
		return nil, fmt.Errorf("failed to generate dh pair: %s", err)
	}
	return state{
		Crypto: c,
		DHs:    dhs,
		RootCh: rootChain{CK: sharedKey, Crypto: c},
		// Populate CKs and CKr with sharedKey as per specification so that both
		// parties could send and receive messages from the very beginning.
		SendCh: chain{CK: sharedKey, Crypto: c},
		RecvCh: chain{CK: sharedKey, Crypto: c},
	}, nil
}

// dhRatchet performs a single ratchet step.
func (s *state) dhRatchet(mh MessageHeader) error {
	s.PN = s.SendCh.N
	s.DHr = mh.DH
	s.RecvCh = s.RootCh.Step(s.Crypto.DH(s.DHs, s.DHr))
	var err error
	s.DHs, err = s.Crypto.GenerateDH()
	if err != nil {
		return fmt.Errorf("failed to generate dh pair: %s", err)
	}
	s.SendCh = s.RootCh.Step(s.Crypto.DH(s.DHs, s.DHr))
	return nil
}

// SymmetricStep performs a symmetric ratchet step on the sending chain and returns message header
// for a new message.
func (s *state) SymmetricStep() (MessageHeader, Key) {
	return MessageHeader{
		DH: s.DHs.PublicKey(),
		N:  s.SendCh.N,
		PN: s.PN,
	}, s.SendCh.Step()
}

// Operations on this object are NOT THREAD-SAFE, make sure they're done in sequence.
type session struct {
	state state

	// Cryptography functions for the Double Ratchet Algorithm.
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

// New creates session with the shared key.
func New(sharedKey Key, opts ...option) (Session, error) {
	if sharedKey == [32]byte{} {
		return nil, fmt.Errorf("sharedKey must be non-zero")
	}
	var (
		c          = DefaultCrypto{}
		state, err = newState(sharedKey, c)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create state: %s", err)
	}
	s := &session{
		state:     state,
		MkSkipped: &KeysStorageInMemory{},
		MaxSkip:   1000,
		MaxKeep:   100,
		Crypto:    c,
		PubKeys:   make(map[uint]Key),
	}

	for i := range opts {
		if err := opts[i](s); err != nil {
			return nil, fmt.Errorf("failed to apply option: %s", err)
		}
	}

	return s, nil
}

// NewWithRK creates session with the shared key and public key of the other party.
func NewWithRK(sharedKey, remoteKey Key, opts ...option) (Session, error) {
	s, err := New(sharedKey, opts...)
	if err != nil {
		return nil, err
	}
	s.(*session).state.DHr = remoteKey
	return s, nil
}

// option is a constructor option.
type option func(*session) error

// MaxSkip specifies the maximum number of skipped message in a single chain.
func MaxSkip(n int) option {
	return func(s *session) error {
		if n < 0 {
			return fmt.Errorf("n must be non-negative")
		}
		s.MaxSkip = uint(n)
		return nil
	}
}

// MaxKeep specifies the maximum number of ratchet steps before a message is deleted.
func MaxKeep(n int) option {
	return func(s *session) error {
		if n < 0 {
			return fmt.Errorf("n must be non-negative")
		}
		s.MaxKeep = uint(n)
		return nil
	}
}

// TODO: WithKeysStorage.
// TODO: WithCrypto.

// RatchetEncrypt performs a symmetric-key ratchet step, then encrypts the message with
// the resulting message key.
func (s *session) RatchetEncrypt(plaintext, ad []byte) Message {
	var (
		h, mk = s.state.SymmetricStep()
		ct    = s.Crypto.Encrypt(mk, plaintext, append(ad, h.Encode()...))
	)
	return Message{h, ct}
}

func (s *session) RatchetEncryptHE(plaintext, ad []byte) MessageHE {
	var (
		hEnc  MessageEncHeader
		h, mk = s.state.SymmetricStep()
	)
	hEnc[:] = s.Crypto.Encrypt(s.state.SendCh.HK, h.Encode(), nil)
	return MessageHE{
		Header:     hEnc,
		Ciphertext: s.Crypto.Encrypt(mk, plaintext, append(ad, hEnc...)),
	}
}

// RatchetDecrypt is called to decrypt messages.
func (s *session) RatchetDecrypt(m Message, ad []byte) ([]byte, error) {
	// Is the message one of the skipped?
	if mk, ok := s.MkSkipped.Get(m.Header.DH, uint(m.Header.N)); ok {
		plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m.Header.Encode()...))
		if err != nil {
			return nil, fmt.Errorf("can't decrypt skipped message: %s", err)
		}
		s.MkSkipped.DeleteMk(m.Header.DH, uint(m.Header.N))
		return plaintext, nil
	}

	var (
		// All changes must be applied on a different session object, so that this session won't be modified nor left in a dirty session.
		sc state = s.state

		skippedKeys1 []skippedKey
		skippedKeys2 []skippedKey
		err          error
	)

	// Is there a new ratchet key?
	isDHStepped := false
	if m.Header.DH != sc.DHr {
		if skippedKeys1, err = sc.skipMessageKeys(m.Header.PN); err != nil {
			return nil, fmt.Errorf("can't skip previous chain message keys: %s", err)
		}
		if err = sc.dhRatchet(m.Header); err != nil {
			return nil, fmt.Errorf("can't perform ratchet step: %s", err)
		}
		isDHStepped = true
	}

	// After all, update the current chain.
	if skippedKeys2, err = sc.skipMessageKeys(m.Header.N); err != nil {
		return nil, fmt.Errorf("can't skip current chain message keys: %s", err)
	}
	mk := sc.RecvCh.Step()
	plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m.Header.Encode()...))
	if err != nil {
		return nil, fmt.Errorf("can't decrypt: %s", err)
	}

	// Apply changes.
	s.state = sc
	if isDHStepped {
		s.PubKeys[s.Step] = s.state.DHr
		s.Step++
		if pubKey, ok := s.PubKeys[s.Step-s.MaxKeep]; ok {
			s.MkSkipped.DeletePk(pubKey)
			delete(s.PubKeys, s.Step-s.MaxKeep)
		}
		for _, skipped := range skippedKeys1 {
			s.MkSkipped.Put(skipped.dhr, skipped.nr, skipped.mk)
		}
	}
	for _, skipped := range skippedKeys2 {
		s.MkSkipped.Put(skipped.dhr, skipped.nr, skipped.mk)
	}

	return plaintext, nil
}

func (s *session) PublicKey() Key {
	return s.state.DHs.PublicKey()
}

type skippedKey struct {
	dhr Key
	nr  uint
	mk  Key
}

// skipMessageKeys skips message keys in the current receiving chain.
func (s *session) skipMessageKeys(until uint) ([]skippedKey, error) {
	if until < uint(s.state.RecvCh.N) {
		return nil, fmt.Errorf("bad until: probably an out-of-order message that was deleted")
	}
	nSkipped := s.MkSkipped.Count(s.state.DHr)
	if until-uint(s.state.RecvCh.N)+nSkipped > s.MaxSkip {
		return nil, fmt.Errorf("too many messages")
	}
	skipped := []skippedKey{}
	for uint(s.state.RecvCh.N) < until {
		mk := s.state.RecvCh.Step()
		skipped = append(skipped, skippedKey{
			dhr: s.state.DHr,
			nr:  uint(s.state.RecvCh.N - 1),
			mk:  mk,
		})
	}
	return skipped, nil
}
