package doubleratchet

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	sk      = [32]byte{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}
	bobPair = dhPair{
		//privateKey: [32]byte{0xf0, 0x22, 0x54, 0xf4, 0xcb, 0xa2, 0x60, 0xc8, 0xeb, 0xe, 0x83, 0xb, 0xc8, 0xb2, 0xfb, 0x18, 0x6f, 0x1b, 0xa4, 0xa2, 0x6e, 0x45, 0xc, 0xeb, 0xff, 0x74, 0xce, 0x65, 0x8b, 0x6e, 0x4c, 0x5d},
		publicKey: [32]byte{0xe3, 0xbe, 0xb9, 0x4e, 0x70, 0x17, 0x37, 0xc, 0x1, 0x8f, 0xa9, 0x7e, 0xef, 0x4, 0xfb, 0x23, 0xac, 0xea, 0x28, 0xf7, 0xa9, 0x56, 0xcc, 0x1d, 0x46, 0xf3, 0xb5, 0x1d, 0x7d, 0x7d, 0x5e, 0x2c},
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
	require.Equal(t, sk, s.CKs)
	require.Equal(t, sk, s.CKr)
	require.Equal(t, [32]byte{}, s.DHr)
	require.NotEqual(t, [32]byte{}, s.DHs.PrivateKey())
	require.NotEqual(t, [32]byte{}, s.DHs.PublicKey())
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

func TestState_RatchetDecrypt_CommunicationAliceSends(t *testing.T) {
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
				m              = alice.RatchetEncrypt([]byte(pt), []byte("alice associated data"))
				decrypted, err = bob.RatchetDecrypt(m, []byte("alice associated data"))
			)

			// Assert.
			require.Nil(t, err)
			require.Equal(t, []byte(pt), decrypted)
		})
	}
}

func TestState_RatchetDecrypt_CommunicationBobSends(t *testing.T) {
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
				m              = bob.RatchetEncrypt([]byte(pt), []byte("bob associated data"))
				decrypted, err = alice.RatchetDecrypt(m, []byte("bob associated data"))
			)

			// Assert.
			require.Nil(t, err)
			require.Equal(t, []byte(pt), decrypted)
		})
	}
}

func TestState_RatchetDecrypt_CommunicationPingPong(t *testing.T) {
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
				mAlice   = alice.RatchetEncrypt([]byte(pt+"alice"), []byte("alice associated data"))
				d1, err1 = bob.RatchetDecrypt(mAlice, []byte("alice associated data"))

				mBob     = alice.RatchetEncrypt([]byte(pt+"bob"), []byte("bob associated data"))
				d2, err2 = bob.RatchetDecrypt(mBob, []byte("bob associated data"))
			)

			// Assert.
			require.Nil(t, err1)
			require.Nil(t, err2)
			require.Equal(t, []byte(pt+"alice"), d1)
			require.Equal(t, []byte(pt+"bob"), d2)
		})
	}
}

func TestState_RatchetDecrypt_CommunicationSkippedMessages(t *testing.T) {
	// Arrange.
	var (
		bobI, _ = New(sk, WithMaxSkip(1))
		bob     = bobI.(*state)

		aliceI, _ = New(sk, WithMaxSkip(1), WithRemoteKey(bob.DHs.PublicKey()))
		alice     = aliceI.(*state)
	)

	t.Run("skipped messages from alice", func(t *testing.T) {
		// Arrange.
		var (
			m0 = alice.RatchetEncrypt([]byte("hi"), nil)
			m1 = alice.RatchetEncrypt([]byte("bob"), nil)
			m2 = alice.RatchetEncrypt([]byte("how are you?"), nil)
			m3 = alice.RatchetEncrypt([]byte("still do cryptography?"), nil)
		)

		// Act and assert.
		d, err := bob.RatchetDecrypt(m1, nil) // Decrypted and skipped.
		require.Nil(t, err)
		require.Equal(t, []byte("bob"), d)

		_, err = bob.RatchetDecrypt(m3, nil) // Error: too many to skip.
		require.NotNil(t, err)

		d, err = bob.RatchetDecrypt(m2, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("how are you?"), d)

		// TODO: Invalid signature to test state atomicity.

		d, err = bob.RatchetDecrypt(m3, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("still do cryptography?"), d)

		d, err = bob.RatchetDecrypt(m0, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("hi"), d)
	})
}
