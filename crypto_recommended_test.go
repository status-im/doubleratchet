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

	// Assert.
	require.Nil(t, err)

	require.Equal(t, byte(0), pair.PrivateKey[0]&7)
	require.Equal(t, byte(0), pair.PrivateKey[31]&128)
	require.Equal(t, byte(64), pair.PrivateKey[31]&64)

	require.Len(t, pair.PrivateKey, 32)
	require.Len(t, pair.PublicKey, 32)
}
