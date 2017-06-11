package doubleratchet

import (
	"crypto/rand"
	"fmt"

	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// CryptoRecommended is an implementation of Crypto with cryptographic primitives recommended
// by the Double Ratchet Algorithm specification.
// See Crypto interface.
type CryptoRecommended struct{}

func (c CryptoRecommended) GenerateDH() (DHKeyPair, error) {
	var privKey [32]byte
	if l, err := rand.Read(privKey[:]); l != 32 || err != nil {
		return DHKeyPair{}, fmt.Errorf("couldn't generate privKey: %s, %d bytes read", err, l)
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return DHKeyPair{
		PrivateKey: privKey[:],
		PublicKey:  pubKey[:],
	}, nil
}

func (c CryptoRecommended) DH(dhPair DHKeyPair, dhPub []byte) []byte {
	var dhOut [32]byte
	curve25519.ScalarMult(&dhOut, &[32]byte(dhPair.PrivateKey), &[32]byte(dhPub))

	return dhOut[:]
}

func (c CryptoRecommended) KdfRK(rk, dhOut []byte) ([]byte, []byte, error) {
	// TODO: Use sha512? Think about how to switch the implementation later if not.
	var (
		// TODO: Check if HKDF is set up correctly.
		r        = hkdf.New(sha256.New, dhOut, rk, []byte("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"))
		chainKey = make([]byte, 32)
		rootKey  = make([]byte, 32)
	)

	if l, err := r.Read(chainKey); l != 32 || err != nil {
		return nil, nil, fmt.Errorf("failed to generate chain key: %s, %d bytes read", err, l)
	}
	if l, err := r.Read(rootKey); l != 32 || err != nil {
		return nil, nil, fmt.Errorf("failed to generate root key: %s, %d bytes read", err, l)
	}

	return chainKey, rootKey, nil
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
