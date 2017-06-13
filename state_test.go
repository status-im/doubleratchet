package doubleratchet

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var sk = [32]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}

func TestNew_Basic(t *testing.T) {
	// Act.
	var (
		si, err = New(sk)
		s       = si.(*state)
	)

	// Assert.
	require.Nil(t, err)
	require.Equal(t, sk, s.RK)
	require.Equal(t, [32]byte{}, s.DHr)
	require.NotEqual(t, [32]byte{}, s.DHs.PrivateKey())
	require.NotEqual(t, [32]byte{}, s.DHs.PublicKey())
	require.Equal(t, [32]byte{}, s.CKs)
	require.Equal(t, [32]byte{}, s.CKr)
	require.EqualValues(t, 0, s.Ns)
	require.EqualValues(t, 0, s.Nr)
	require.EqualValues(t, 0, s.PN)
	require.NotNil(t, s.MkSkipped)
	require.NotEqual(t, 0, s.MaxSkip)
	require.NotNil(t, s.Crypto)
}

func TestNew_WithMaxSkip_OK(t *testing.T) {
	// Act.
	var (
		si, err = New(sk, WithMaxSkip(100))
		s       = si.(*state)
	)

	// Assert.
	require.Nil(t, err)
	require.EqualValues(t, 100, s.MaxSkip)
}

func TestNew_WithMaxSkip_Negative(t *testing.T) {
	// Act.
	var (
		_, err = New(sk, WithMaxSkip(-10))
	)

	// Assert.
	require.NotNil(t, err)
}

//func TestNew_WithRemoteKey(t *testing.T) {
//	// Act.
//	var (
//		si, err = New(sk, WithRemoteKey(100))
//		s       = si.(*state)
//	)
//
//	// Assert.
//
//}
