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

func (c DefaultCrypto) GenerateDH() (DHPair, error) {
	var privKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return DHPair{}, fmt.Errorf("couldn't generate privKey: %s", err)
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return DHPair{
		PrivateKey: privKey[:],
		PublicKey:  pubKey[:],
	}, nil
}

func (c DefaultCrypto) DH(dhPair DHPair, dhPub []byte) []byte {
	var dhOut [32]byte
	curve25519.ScalarMult(&dhOut, &[32]byte(dhPair.PrivateKey), &[32]byte(dhPub))

	return dhOut[:]
}

func (c DefaultCrypto) KdfRK(rk, dhOut []byte) ([]byte, []byte, error) {
	// TODO: Use sha512? Think about how to switch the implementation later if not.
	var (
		// TODO: Check if HKDF is set up correctly.
		r   = hkdf.New(sha256.New, dhOut, rk, []byte("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"))
		buf = make([]byte, 64)
	)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, fmt.Errorf("failed to generate keys: %s", err)
	}
	return buf[:32], buf[32:], nil
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
	encKey, authKey, iv, err := c.deriveEncKeys(mk)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:len(iv)], iv)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes block cipher: %s", err)
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return c.authCiphertext(authKey, ciphertext, associatedData), nil
}

func (c DefaultCrypto) Decrypt(mk, authCiphertext, associatedData []byte) ([]byte, error) {
	var (
		l          = len(authCiphertext)
		iv         = authCiphertext[:aes.BlockSize]
		ciphertext = authCiphertext[aes.BlockSize : l-sha256.Size]
		signature  = authCiphertext[l-sha256.Size:]
	)

	// Check the signature.
	encKey, authKey, _, err := c.deriveEncKeys(mk)
	if err != nil {
		return nil, err
	}
	if s := c.authCiphertext(authKey, ciphertext, associatedData)[l-aes.BlockSize:]; string(s) != string(signature) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decrypt.
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes block cipher: %s", err)
	}
	var (
		stream    = cipher.NewCTR(block, iv)
		plaintext = make([]byte, len(ciphertext))
	)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// deriveEncKeys derive keys for message encryption and decryption. Returns (encKey, authKey, iv, err).
func (c DefaultCrypto) deriveEncKeys(mk []byte) ([]byte, []byte, []byte, error) {
	// TODO: Think about switching to sha512
	// First, derive encryption and authentication key out of mk.
	salt := make([]byte, sha256.Size)
	var (
		// TODO: Check if HKDF is used correctly.
		r   = hkdf.New(sha256.New, mk, salt, []byte("pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh"))
		buf = make([]byte, sha256.Size*2+aes.BlockSize)
	)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate encryption keys: %s", err)
	}
	return buf[0:sha256.Size], buf[sha256.Size : 2*sha256.Size], buf[2*sha256.Size : 80], nil
}

func (c DefaultCrypto) authCiphertext(authKey, ciphertext, associatedData []byte) []byte {
	h := hmac.New(sha256.New, authKey)
	// TODO: Handle error?
	h.Write(associatedData)
	// TODO: Handle error?
	h.Write(ciphertext)
	return h.Sum(ciphertext)
}
