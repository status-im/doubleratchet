package doubleratchet

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// CryptoRecommended is an implementation of Crypto with cryptographic primitives recommended
// by the Double Ratchet Algorithm specification.
type CryptoRecommended struct {
	Crypto
}

func (c CryptoRecommended) GenerateDH() (DHKeyPair, error) {
	var privkey [32]byte
	if _, err := rand.Read(privkey[:]); err != nil {
		return DHKeyPair{}, fmt.Errorf("couldn't generate privkey: %s", err)
	}
	privkey[0] &= 248
	privkey[31] &= 127
	privkey[31] |= 64

	var pubkey [32]byte
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return DHKeyPair{
		PrivateKey: privkey[:],
		PublicKey:  pubkey[:],
	}, nil
}
