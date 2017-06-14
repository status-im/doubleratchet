package doubleratchet

import "encoding/hex"

// Crypto is a cryptography supplement for the library.
type Crypto interface {
	// Generate returns a new Diffie-Hellman key pair.
	GenerateDH() (DHPair, error)

	// DH returns the output from the Diffie-Hellman calculation between
	// the private key from the DH key pair dhPair and the DH public key dbPub.
	DH(dhPair DHPair, dhPub Key) Key

	// KdfRK returns a pair (32-byte root key, 32-byte chain key) as the output of applying
	// a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dhOut.
	KdfRK(rk, dhOut Key) (rootKey, chainKey Key)

	// KdfCK returns a pair (32-byte chain key, 32-byte message key) as the output of applying
	// a KDF keyed by a 32-byte chain key ck to some constant.
	KdfCK(ck Key) (chainKey, msgKey Key)

	// Encrypt returns an AEAD encryption of plaintext with message key mk. The associated_data
	// is authenticated but is not included in the ciphertext. The AEAD nonce may be set to a constant.
	Encrypt(mk Key, plaintext, ad AssociatedData) (authCiphertext []byte)

	// Decrypt returns the AEAD decryption of ciphertext with message key mk.
	Decrypt(mk Key, ciphertext, ad AssociatedData) (plaintext []byte, err error)
}

// DHPair is a general interface for DH pairs representation.
type DHPair interface {
	PrivateKey() Key
	PublicKey() Key
}

type Key [32]byte

func (k Key) String() string {
	return hex.EncodeToString(k[:])
}
