package doubleratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DefaultCrypto is an implementation of Crypto with cryptographic primitives recommended
// by the Double Ratchet Algorithm specification. However, some details are different,
// see function comments for details.
type DefaultCrypto struct{}

func (c DefaultCrypto) GenerateDH() (DHKeyPair, error) {
	var privKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return DHKeyPair{}, fmt.Errorf("couldn't generate privKey: %s", err)
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

func (c DefaultCrypto) DH(dhPair DHKeyPair, dhPub []byte) []byte {
	var dhOut [32]byte
	curve25519.ScalarMult(&dhOut, &[32]byte(dhPair.PrivateKey), &[32]byte(dhPub))

	return dhOut[:]
}

func (c DefaultCrypto) KdfRK(rk, dhOut []byte) ([]byte, []byte, error) {
	// TODO: Use sha512? Think about how to switch the implementation later if not.
	var (
		// TODO: Check if HKDF is set up correctly.
		r        = hkdf.New(sha256.New, dhOut, rk, []byte("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"))
		chainKey = make([]byte, 32)
		rootKey  = make([]byte, 32)
	)

	if _, err := io.ReadFull(r, chainKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate chain key: %s", err)
	}
	if _, err := io.ReadFull(r, rootKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate root key: %s", err)
	}

	return chainKey, rootKey, nil
}

func (c DefaultCrypto) KdfCK(ck []byte) ([]byte, []byte) {
	const (
		ckInput = 15
		mkInput = 16
	)

	// TODO: Use sha512? Think about how to switch the implementation later if not.
	h := hmac.New(sha256.New, ck)

	// TODO: Handle error?
	h.Write([]byte(ckInput))
	chainKey := h.Sum(nil)
	h.Reset()

	// TODO: Handle error?
	h.Write([]byte(mkInput))
	msgKey := h.Sum(nil)

	return chainKey, msgKey
}

// Encrypt uses a slightly different approach over what is stated in the algorithm specification:
// it uses AES-256-CTR instead of AES-256-CBC for security, ciphertext length and implementation
// complexity considerations.
func (c DefaultCrypto) Encrypt(mk, plaintext, associatedData []byte) ([]byte, error) {
	// TODO: Think about switching to sha512
	// First, derive encryption and authentication key out of mk.
	salt := make([]byte, sha256.Size)
	for i := 0; i < sha256.Size; i++ {
		salt[i] = 0
	}
	var (
		// TODO: Check if HKDF is used correctly.
		r   = hkdf.New(sha256.New, mk, salt, []byte("pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh"))
		buf = make([]byte, 80)
	)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("failed to generate encryption keys: %s", err)
	}
	var (
		encKey  = buf[0:32]
		authKey = buf[32:64]
		iv      = buf[64:80]

		ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	)

	// Then, obtain the ciphertext.
	for i := 0; i < len(iv); i++ {
		ciphertext[i] = iv[i]
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes block cipher: %s", err)
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Now authenticate the ciphertext.
	h := hmac.New(sha256.New, authKey)
	// TODO: Handle error?
	h.Write(associatedData)
	// TODO: Handle error?
	h.Write(ciphertext)
	return h.Sum(ciphertext), nil
}

func (c DefaultCrypto) Decrypt(mk, ciphertext, associatedData []byte) (plaintext []byte) {
	// TODO: Implement.

	return nil
}
