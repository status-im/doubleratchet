package doubleratchet

import (
	"crypto/rand"
	"fmt"

	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
)

// CryptoRecommended is an implementation of Crypto with cryptographic primitives recommended
// by the Double Ratchet Algorithm specification.
// See Crypto interface.
type CryptoRecommended struct{}

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

func (c CryptoRecommended) DH(dhPair DHKeyPair, dhPub []byte) []byte {
	// TODO: Implement

	return nil
}

func (c CryptoRecommended) KdfRK(rk, dhOut []byte) (rootKey, chainKey []byte) {
	// TODO: Implement.

	return nil, nil
}

func (c CryptoRecommended) KdfCK(ck []byte) ([]byte, []byte) {
	const (
		ckInput = 15
		mkInput = 16
	)

	// TODO: Use sha512? Think about how to switch the implementation later if not.
	h := hmac.New(sha256.New, ck)

	h.Write([]byte(ckInput))
	chainKey := h.Sum(nil)
	h.Reset()

	h.Write([]byte(mkInput))
	msgKey := h.Sum(nil)

	return chainKey, msgKey
}

func (c CryptoRecommended) Encrypt(mk, plaintext, associatedData []byte) (ciphertext []byte) {
	// TODO: Implement.

	return nil
}

func (c CryptoRecommended) Decrypt(mk, ciphertext, associatedData []byte) (plaintext []byte) {
	// TODO: Implement.

	return nil
}
