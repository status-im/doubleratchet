package doubleratchet

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDefaultCrypto_GenerateDH(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	pair, err := c.GenerateDH()
	require.Nil(t, err)

	// Assert.
	require.EqualValues(t, 0, pair.PrivateKey[0]&7)
	require.EqualValues(t, 0, pair.PrivateKey[31]&128)
	require.EqualValues(t, 64, pair.PrivateKey[31]&64)

	require.Len(t, pair.PrivateKey, 32)
	require.Len(t, pair.PublicKey, 32)
}

func TestDefaultCrypto_DH(t *testing.T) {
	// Arrange.
	c := DefaultCrypto{}

	// Act.
	var (
		alicePair, err1 = c.GenerateDH()
		bobPair, err2   = c.GenerateDH()
		aliceSK         = c.DH(alicePair, bobPair.PublicKey)
		bobSK           = c.DH(bobPair, alicePair.PublicKey)
	)

	// Assert.
	require.Nil(t, err1)
	require.Nil(t, err2)
	require.NotEqual(t, [32]byte{}, aliceSK)
	require.Equal(t, aliceSK, bobSK)
}
