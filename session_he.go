package doubleratchet

import "fmt"

// SessionHE is the session of the party involved the Double Ratchet Algorithm with encrypted header modification.
type SessionHE interface {
	// RatchetEncryptHE performs a symmetric-key ratchet step, then AEAD-encrypts
	// the header-encrypted message with the resulting message key.
	RatchetEncryptHE(plaintext, associatedData []byte) MessageHE

	// RatchetDecryptHE is called to AEAD-decrypt header-encrypted messages.
	RatchetDecryptHE(m MessageHE, associatedData []byte) ([]byte, error)
}

type sessionHE struct {
	state
}

// TODO: New.

// RatchetEncryptHE performs a symmetric-key ratchet step, then encrypts the header with
// the corresponding header key and the message with resulting message key.
func (s *sessionHE) RatchetEncryptHE(plaintext, ad []byte) MessageHE {
	var (
		h = MessageHeader{
			DH: s.DHs.PublicKey(),
			N:  s.SendCh.N,
			PN: s.PN,
		}
		mk   = s.SendCh.Step()
		hEnc = s.Crypto.Encrypt(s.HKs, h.Encode(), nil)
	)
	return MessageHE{
		Header:     hEnc,
		Ciphertext: s.Crypto.Encrypt(mk, plaintext, append(ad, hEnc...)),
	}
}

func (s *sessionHE) RatchetDecryptHE(m MessageHE, ad []byte) ([]byte, error) {
	// Is the message one of the skipped?
	for hk, keys := range s.MkSkipped.All() {
		for n, mk := range keys {
			hEnc, err := s.Crypto.Decrypt(hk, m.Header, nil)
			if err != nil {
				continue
			}
			h, err := MessageEncHeader(hEnc).Decode()
			if err != nil {
				// FIXME: Log fail here instead of return.
				return nil, fmt.Errorf("can't decode header %s for skipped message key under (%s, %d)", hEnc, hk, n)
			}
			if uint(h.N) != n {
				continue
			}

			plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m.Header...))
			if err != nil {
				return nil, fmt.Errorf("can't decrypt skipped message: %s", err)
			}
			s.MkSkipped.DeleteMk(hk, n)
			return plaintext, nil
		}
	}

	h, step, err := s.DecryptHeader(m.Header)
	if err != nil {
		return nil, fmt.Errorf("can't decrypt header: %s", err)
	}

	var (
		// All changes must be applied on a different session object, so that this session won't be modified nor left in a dirty session.
		sc state = s.state

		skippedKeys1 []skippedKey
		skippedKeys2 []skippedKey
	)
	if step {
		if skippedKeys1, err = sc.skipMessageKeys(s.HKr, uint(h.PN)); err != nil {
			return nil, fmt.Errorf("can't skip previous chain message keys: %s", err)
		}
		if err = sc.dhRatchet(h); err != nil {
			return nil, fmt.Errorf("can't perform ratchet step: %s", err)
		}
	}

	// After all, update the current chain.
	if skippedKeys2, err = sc.skipMessageKeys(s.HKr, uint(h.N)); err != nil {
		return nil, fmt.Errorf("can't skip current chain message keys: %s", err)
	}
	mk := sc.RecvCh.Step()
	plaintext, err := s.Crypto.Decrypt(mk, m.Ciphertext, append(ad, m.Header...))
	if err != nil {
		return nil, fmt.Errorf("can't decrypt: %s", err)
	}

	s.applyChanges(sc, append(skippedKeys1, skippedKeys2...))
	if step {
		s.deleteSkippedKeys(s.HKr)
	}

	return plaintext, nil
}

func (s *sessionHE) DecryptHeader(encHeader []byte) (MessageHeader, bool, error) {
	if encoded, err := s.Crypto.Decrypt(s.HKr, encHeader, nil); err == nil {
		h, err := MessageEncHeader(encoded).Decode()
		return h, false, err
	}
	if encoded, err := s.Crypto.Decrypt(s.HKr, encHeader, nil); err == nil {
		h, err := MessageEncHeader(encoded).Decode()
		return h, false, err
	}
	return MessageHeader{}, false, fmt.Errorf("invalid message header")
}
