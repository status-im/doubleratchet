package doubleratchet

// KDFer performs key derivation functions for chains.
type KDFer interface {
	// KdfRK returns a pair (32-byte root key, 32-byte chain key) as the output of applying
	// a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dhOut.
	KdfRK(rk, dhOut Key) (rootKey, chainKey, newHeaderKey Key)

	// KdfCK returns a pair (32-byte chain key, 32-byte message key) as the output of applying
	// a KDF keyed by a 32-byte chain key ck to some constant.
	KdfCK(ck Key) (chainKey, msgKey Key)
}

type rootChain struct {
	Crypto KDFer

	// 32-byte chain key.
	CK Key
}

func (c rootChain) Step(kdfInput Key) (ch chain, nhk Key) {
	ch = chain{
		Crypto: c.Crypto,
	}
	c.CK, ch.CK, nhk = c.Crypto.KdfRK(c.CK, kdfInput)
	return ch, nhk
}

type chain struct {
	Crypto KDFer

	// 32-byte chain key.
	CK Key

	// Messages count in the chain.
	N uint32
}

// Step performs chain step and returns message key.
func (c chain) Step() Key {
	var mk Key
	c.CK, mk = c.Crypto.KdfCK(c.CK)
	c.N = 0
	return mk
}
