package doubleratchet

// TODO: Replace []byte with meaningful types?
// TODO: Constant for nonces?

// Crypto is a cryptography supplement for the library.
type Crypto interface {
	// Generate returns a new Diffie-Hellman key pair.
	// TODO: (privKey, pubKey []byte)?
	GenerateDH() (DHPair, error)

	// DH returns the output from the Diffie-Hellman calculation between
	// the private key from the DH key pair dhPair and the DH public key dbPub.
	DH(dhPair DHPair, dhPub [32]byte) [32]byte

	// KdfRK returns a pair (32-byte root key, 32-byte chain key) as the output of applying
	// a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dhOut.
	KdfRK(rk, dhOut [32]byte) (rootKey, chainKey [32]byte, err error)

	// KdfCK returns a pair (32-byte chain key, 32-byte message key) as the output of applying
	// a KDF keyed by a 32-byte chain key ck to some constant.
	KdfCK(ck [32]byte) (chainKey, msgKey [32]byte)

	// Encrypt returns an AEAD encryption of plaintext with message key mk. The associated_data
	// is authenticated but is not included in the ciphertext. The AEAD nonce may be set to a constant.
	Encrypt(mk [32]byte, plaintext, associatedData []byte) (authCiphertext []byte, err error)

	// Decrypt returns the AEAD decryption of ciphertext with message key mk.
	Decrypt(mk [32]byte, ciphertext, associatedData []byte) (plaintext []byte, err error)
}

//HEADER(dh_pair, pn, n):
// Creates a new message header containing the DH ratchet public key from the key pair in dh_pair,
// the previous chain length pn, and the message number n. The returned header object contains
// ratchet public key dh and integers pn and n.

//CONCAT(ad, header): Encodes a message header into a parseable byte sequence, prepends the
// ad byte sequence, and returns the result. If ad is not guaranteed to be a parseable
// byte sequence, a length value should be prepended to the output to ensure that the output
// is parseable as a unique pair (ad, header).

// DHPair is Diffie-Hellman's key pair consisting of the private and public keys.
type DHPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}
