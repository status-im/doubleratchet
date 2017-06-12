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
	require.Len(t, pair.PrivateKey, 32)
	require.Len(t, pair.PublicKey, 32)
}
