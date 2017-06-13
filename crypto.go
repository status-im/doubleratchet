package doubleratchet

// Crypto is a cryptography supplement for the library.
type Crypto interface {
	// Generate returns a new Diffie-Hellman key pair.
	GenerateDH() (DHPair, error)

	// DH returns the output from the Diffie-Hellman calculation between
	// the private key from the DH key pair dhPair and the DH public key dbPub.
	DH(dhPair DHPair, dhPub [32]byte) [32]byte

	// KdfRK returns a pair (32-byte root key, 32-byte chain key) as the output of applying
	// a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dhOut.
	KdfRK(rk, dhOut [32]byte) (rootKey, chainKey [32]byte)

	// KdfCK returns a pair (32-byte chain key, 32-byte message key) as the output of applying
	// a KDF keyed by a 32-byte chain key ck to some constant.
	KdfCK(ck [32]byte) (chainKey, msgKey [32]byte)

	// Encrypt returns an AEAD encryption of plaintext with message key mk. The associated_data
	// is authenticated but is not included in the ciphertext. The AEAD nonce may be set to a constant.
	Encrypt(mk [32]byte, plaintext, associatedData []byte) (authCiphertext []byte)

	// Decrypt returns the AEAD decryption of ciphertext with message key mk.
	Decrypt(mk [32]byte, ciphertext, associatedData []byte) (plaintext []byte, err error)
}

// DHPair is a general interface for DH pairs representation.
type DHPair interface {
	PrivateKey() [32]byte
	PublicKey() [32]byte
}

// TODO:
// type Key [32]byte
