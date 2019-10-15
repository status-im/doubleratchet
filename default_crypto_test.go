package doubleratchet

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDhPair(t *testing.T) {
	// Arrange.
	p := dhPair{
		privateKey: []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		publicKey:  []byte{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6},
	}

	// Act.
	var (
		privKey = p.PrivateKey()
		pubKey  = p.PublicKey()
	)

	// Assert.
	require.Equal(t, p.privateKey, privKey)
	require.Equal(t, p.publicKey, pubKey)
	require.Equal(t, fmt.Sprintf(`{privateKey: %s publicKey: %s}`, p.PrivateKey(), p.PublicKey()), p.String())
}

func TestDefaultCrypto_GenerateDH_Basic(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	pair, err := c.GenerateDH()

	// Assert.
	require.Nil(t, err)

	require.EqualValues(t, 0, pair.PrivateKey()[0]&7)
	require.EqualValues(t, 0, pair.PrivateKey()[31]&128)
	require.EqualValues(t, 64, pair.PrivateKey()[31]&64)

	require.NotEqual(t, nil, pair.PrivateKey())
	require.NotEqual(t, nil, pair.PublicKey())
	require.Len(t, pair.PrivateKey(), 32)
	require.Len(t, pair.PublicKey(), 32)
	require.NotEqual(t, pair.PublicKey(), pair.PrivateKey())
}

func TestDefaultCrypto_GenerateDH_DifferentKeysEveryTime(t *testing.T) {
	// Arrange.
	var (
		c    = DefaultCrypto{}
		keys = make(map[string]bool)
	)

	for i := 0; i < 10; i++ {
		t.Run("", func(t *testing.T) {
			// Act.
			pair, err := c.GenerateDH()

			// Assert.
			require.Nil(t, err)
			privateKeyString := fmt.Sprintf("%x", pair.PrivateKey())
			publicKeyString := fmt.Sprintf("%x", pair.PublicKey())
			require.False(t, keys[privateKeyString])
			require.False(t, keys[publicKeyString])

			// Preserve.
			keys[privateKeyString] = true
			keys[publicKeyString] = true
		})
	}
}

func TestDefaultCrypto_DH(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	var (
		alicePair, err1 = c.GenerateDH()
		bobPair, err2   = c.GenerateDH()
		aliceSK, err3   = c.DH(alicePair, bobPair.PublicKey())
		bobSK, err4     = c.DH(bobPair, alicePair.PublicKey())
	)

	// Assert.
	require.Nil(t, err1)
	require.Nil(t, err2)
	require.Nil(t, err3)
	require.Nil(t, err4)
	require.NotEqual(t, nil, aliceSK)
	require.Equal(t, aliceSK, bobSK)
}

func TestDefaultCrypto_KdfRK(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	// TODO: Test hk.
	newRK, newCK, _ := c.KdfRK(
		[]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40},
		[]byte{0x9c, 0x1e, 0x68, 0xab, 0x9d, 0x45, 0xf5, 0x82, 0x35, 0xc4, 0x2, 0xa8, 0x82, 0xa1, 0x46, 0x55, 0x35, 0x41, 0xf1, 0x9d, 0x87, 0x2b, 0x59, 0x24, 0x39, 0x3b, 0x91, 0xf7, 0xda, 0x46, 0x56, 0xf},
	)

	// Assert.
	require.NotEqual(t, nil, newRK)
	require.NotEqual(t, nil, newCK)
	require.Len(t, newRK, 32)
	require.Len(t, newCK, 32)
	require.NotEqual(t, newRK, newCK)
}

func TestDefaultCrypto_KdfCK(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	newCK, mk := c.KdfCK([]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40})

	// Assert.
	require.NotEqual(t, nil, newCK)
	require.NotEqual(t, nil, mk)
	require.Len(t, newCK, 32)
	require.Len(t, mk, 32)
	require.NotEqual(t, mk, newCK)
}

func TestDefaultCrypto_deriveEncKeys(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	encKey, authKey, iv := c.deriveEncKeys([]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40})

	// Assert.
	require.Len(t, encKey, 32)
	require.Len(t, authKey, 32)
	require.Len(t, iv, 16)
	require.NotEqual(t, nil, encKey)
	require.NotEqual(t, nil, authKey)
	require.NotContains(t, encKey, iv)
	require.NotContains(t, authKey, iv)
	require.NotEqual(t, encKey, authKey)
}

func TestDefaultCrypto_computeSignature(t *testing.T) {
	// Arrange.
	var (
		c          = DefaultCrypto{}
		ciphertext = []byte{13, 250, 114, 78}
	)

	// Act.
	signature := c.computeSignature(
		[]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40},
		ciphertext,
		nil,
	)

	// Assert.
	require.Len(t, signature, 32)
	require.NotEqual(t, nil, signature)
}

func TestDefaultCrypto_EncryptDecrypt(t *testing.T) {
	// Arrange.
	var (
		c   = DefaultCrypto{}
		msg = []byte("1337")
		mk  = []byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}
	)

	t.Run("no associated data", func(t *testing.T) {
		// Act.
		ciphertext, err := c.Encrypt(mk, msg, nil)
		require.Nil(t, err)

		plaintext, err := c.Decrypt(mk, ciphertext, nil)
		require.Nil(t, err)

		// Assert.
		require.Len(t, ciphertext, 16+len(msg)+32) // iv + plaintext length + signature
		require.Equal(t, msg, plaintext)
	})

	t.Run("same associated data", func(t *testing.T) {
		// Act.
		ciphertext, err := c.Encrypt(mk, msg, []byte("any secret"))
		require.Nil(t, err)

		plaintext, err := c.Decrypt(mk, ciphertext, []byte("any secret"))
		require.Nil(t, err)

		// Assert.
		require.Len(t, ciphertext, 32+16+len(msg)) // signature + iv + plaintext length
		require.Equal(t, msg, plaintext)
	})

	t.Run("different associated data", func(t *testing.T) {
		// Act.
		ciphertext, err := c.Encrypt(mk, msg, []byte("not secret at all"))
		require.Nil(t, err)

		_, err = c.Decrypt(mk, ciphertext, []byte("any secret"))
		require.EqualError(t, err, "invalid signature")
	})

	t.Run("malformed signature", func(t *testing.T) {
		// Act.
		ciphertext, err := c.Encrypt(mk, msg, nil)
		require.Nil(t, err)

		ciphertext[len(ciphertext)-1] ^= 57 // Inverse the last byte in the signature.
		_, err = c.Decrypt(mk, ciphertext, nil)

		// Assert.
		require.EqualError(t, err, "invalid signature")
	})
}
