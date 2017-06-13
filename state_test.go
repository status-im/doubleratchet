package doubleratchet

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	sk        = [32]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}
	alicePair = dhPair{
		privateKey: [32]byte{0x88, 0x6a, 0x50, 0xbf, 0x65, 0x63, 0x4b, 0xfb, 0xf5, 0xcf, 0x7d, 0xe0, 0x79, 0xec, 0x3c, 0x70, 0x56, 0x96, 0xa5, 0x4a, 0x8a, 0xfb, 0xfa, 0x97, 0xde, 0x4a, 0x2f, 0xdd, 0xdd, 0x22, 0x40, 0x51},
		publicKey:  [32]byte{0x6, 0x45, 0x36, 0xa5, 0xed, 0xa0, 0xae, 0xaf, 0x62, 0x4f, 0x20, 0x63, 0x3b, 0x8e, 0xc1, 0x7, 0xe8, 0xe7, 0x45, 0x1, 0x8d, 0x14, 0xdb, 0xf8, 0x9, 0x51, 0x3c, 0x5f, 0xbd, 0x33, 0x7, 0x44},
	}
	bobPair = dhPair{
		privateKey: [32]byte{0xf0, 0x22, 0x54, 0xf4, 0xcb, 0xa2, 0x60, 0xc8, 0xeb, 0xe, 0x83, 0xb, 0xc8, 0xb2, 0xfb, 0x18, 0x6f, 0x1b, 0xa4, 0xa2, 0x6e, 0x45, 0xc, 0xeb, 0xff, 0x74, 0xce, 0x65, 0x8b, 0x6e, 0x4c, 0x5d},
		publicKey:  [32]byte{0xe3, 0xbe, 0xb9, 0x4e, 0x70, 0x17, 0x37, 0xc, 0x1, 0x8f, 0xa9, 0x7e, 0xef, 0x4, 0xfb, 0x23, 0xac, 0xea, 0x28, 0xf7, 0xa9, 0x56, 0xcc, 0x1d, 0x46, 0xf3, 0xb5, 0x1d, 0x7d, 0x7d, 0x5e, 0x2c},
	}
)

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

func TestNew_WithRemoteKey(t *testing.T) {
	// Act.
	var (
		si, err = New(sk, WithRemoteKey(bobPair.PublicKey()))
		s       = si.(*state)
	)

	// Assert.
	require.Nil(t, err)

	require.Equal(t, bobPair.PublicKey(), s.DHr)
	require.NotEqual(t, [32]byte{}, s.RK)
	require.NotEqual(t, sk, s.RK)
	require.NotEqual(t, [32]byte{}, s.CKs)
}

func TestState_RatchetEncryptDecrypt_Basic(t *testing.T) {
	// Arrange.
	var (
		si, err = New(sk, WithRemoteKey(bobPair.PublicKey()))
		s       = si.(*state)
		oldCKs  = s.CKs
	)

	// Act.
	m := si.RatchetEncrypt([]byte("1337"), nil)

	// Assert.
	require.Nil(t, err)

	require.NotEqual(t, oldCKs, s.CKs)
	require.EqualValues(t, 1, s.Ns)

	require.Equal(t, MessageHeader{
		DH: s.DHs.PublicKey(),
		N:  0,
		PN: 0,
	}, m.Header)
	require.NotEmpty(t, m.Ciphertext)
}

func TestState_RatchetDecrypt_BasicCommunicationAliceSends(t *testing.T) {
	// Arrange.
	var (
		bobI, _ = New(sk)
		bob     = bobI.(*state)

		aliceI, _ = New(sk, WithRemoteKey(bob.DHs.PublicKey()))
		alice     = aliceI.(*state)
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			// Act.
			var (
				m              = alice.RatchetEncrypt([]byte(pt), nil)
				decrypted, err = bob.RatchetDecrypt(m, nil)
			)

			// Assert.
			require.Nil(t, err)
			require.Equal(t, []byte(pt), decrypted)
		})
	}
}

func TestState_RatchetDecrypt_BasicCommunicationBobSends(t *testing.T) {
	// Arrange.
	var (
		bobI, _ = New(sk)
		bob     = bobI.(*state)

		aliceI, _ = New(sk, WithRemoteKey(bob.DHs.PublicKey()))
		alice     = aliceI.(*state)
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			// Act.
			var (
				m              = bob.RatchetEncrypt([]byte(pt), nil)
				decrypted, err = alice.RatchetDecrypt(m, nil)
			)

			// Assert.
			require.Nil(t, err)
			require.Equal(t, []byte(pt), decrypted)
		})
	}
}
