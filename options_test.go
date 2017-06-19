package doubleratchet

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWithMaxSkip_OK(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithMaxSkip(150)(&s)

	// Assert.
	require.Nil(t, err)
	require.EqualValues(t, 150, s.MaxSkip)
}

func TestWithMaxSkip_Negative(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithMaxSkip(-150)(&s)

	// Assert.
	require.NotNil(t, err)
}
func TestWithMaxKeep_OK(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithMaxKeep(150)(&s)

	// Assert.
	require.Nil(t, err)
	require.EqualValues(t, 150, s.MaxKeep)
}

func TestWithMaxKeep_Negative(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithMaxKeep(-150)(&s)

	// Assert.
	require.NotNil(t, err)
}

func TestWithKeysStorage_OK(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithKeysStorage(&KeysStorageInMemory{})(&s)

	// Assert.
	require.Nil(t, err)
	require.NotNil(t, s.MkSkipped)
}

func TestWithKeysStorage_Nil(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithKeysStorage(nil)(&s)

	// Assert.
	require.NotNil(t, err)
}

func TestWithCrypto_OK(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithCrypto(DefaultCrypto{})(&s)

	// Assert.
	require.Nil(t, err)
	require.NotNil(t, s.Crypto)
}

func TestWithCrypto_Nil(t *testing.T) {
	// Arrange.
	s := state{}

	// Act.
	err := WithCrypto(nil)(&s)

	// Assert.
	require.NotNil(t, err)
}
