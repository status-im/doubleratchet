package doubleratchet

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	sk      = Key{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}
	bobPair = dhPair{
		//privateKey: Key{0xf0, 0x22, 0x54, 0xf4, 0xcb, 0xa2, 0x60, 0xc8, 0xeb, 0xe, 0x83, 0xb, 0xc8, 0xb2, 0xfb, 0x18, 0x6f, 0x1b, 0xa4, 0xa2, 0x6e, 0x45, 0xc, 0xeb, 0xff, 0x74, 0xce, 0x65, 0x8b, 0x6e, 0x4c, 0x5d},
		publicKey: Key{0xe3, 0xbe, 0xb9, 0x4e, 0x70, 0x17, 0x37, 0xc, 0x1, 0x8f, 0xa9, 0x7e, 0xef, 0x4, 0xfb, 0x23, 0xac, 0xea, 0x28, 0xf7, 0xa9, 0x56, 0xcc, 0x1d, 0x46, 0xf3, 0xb5, 0x1d, 0x7d, 0x7d, 0x5e, 0x2c},
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
	require.Equal(t, Key{}, s.DHr)
	require.NotEqual(t, Key{}, s.DHs.PrivateKey())
	require.NotEqual(t, Key{}, s.DHs.PublicKey())
	require.Empty(t, s.Ns)
	require.Empty(t, s.Nr)
	require.Empty(t, s.PN)
	require.NotNil(t, s.MkSkipped)
	require.NotEmpty(t, s.MaxSkip)
	require.NotEmpty(t, s.MaxKeep)
	require.NotNil(t, s.Crypto)
	require.NotNil(t, s.PubKeys)
}

func TestNew_BadSharedKey(t *testing.T) {
	// Act.
	_, err := New([32]byte{})

	// Assert.
	require.NotNil(t, err)
}

func TestNew_WithMaxSkip_OK(t *testing.T) {
	// Act.
	var (
		si, err = New(sk, MaxSkip(100))
		s       = si.(*state)
	)

	// Assert.
	require.Nil(t, err)
	require.EqualValues(t, 100, s.MaxSkip)
}

func TestNew_WithMaxSkip_Negative(t *testing.T) {
	// Act.
	_, err := New(sk, MaxSkip(-10))

	// Assert.
	require.NotNil(t, err)
}

func TestNew_WithRemoteKey(t *testing.T) {
	// Act.
	var (
		si, err = New(sk, RemoteKey(bobPair.PublicKey()))
		s       = si.(*state)
	)

	// Assert.
	require.Nil(t, err)
	require.Equal(t, bobPair.PublicKey(), s.DHr)
	require.NotEqual(t, Key{}, s.RK)
	require.NotEqual(t, sk, s.RK)
	require.NotEqual(t, Key{}, s.CKs)
}

func TestState_RatchetEncryptDecrypt_Basic(t *testing.T) {
	// Arrange.
	var (
		si, err = New(sk, RemoteKey(bobPair.PublicKey()))
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
		bob, _   = New(sk)
		alice, _ = New(sk, RemoteKey(bob.PublicKey()))
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelper{t, alice, bob}
			h.AliceToBob(pt, []byte("alice associated data"))
		})
	}
}

func TestState_RatchetDecrypt_CommunicationBobSends(t *testing.T) {
	var (
		bob, _   = New(sk)
		alice, _ = New(sk, RemoteKey(bob.PublicKey()))
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelper{t, alice, bob}
			h.BobToAlice(pt, []byte("bob associated data"))
		})
	}
}

func TestState_RatchetDecrypt_CommunicationPingPong(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New(sk)
		alice, _ = New(sk, RemoteKey(bob.PublicKey()))
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelper{t, alice, bob}

			h.AliceToBob(pt+"alice", []byte("alice associated data"))
			h.BobToAlice(pt+"bob", []byte("bob associated data"))
		})
	}
}

func TestState_RatchetDecrypt_CommunicationSkippedMessages(t *testing.T) {
	// Arrange.
	var (
		bobI, _ = New(sk, MaxSkip(1))
		bob     = bobI.(*state)

		aliceI, _ = New(sk, MaxSkip(1), RemoteKey(bob.DHs.PublicKey()))
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
		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
		_, err := bob.RatchetDecrypt(m1, nil) // Error: invalid signature.
		require.NotNil(t, err)
		require.EqualValues(t, 0, bob.MkSkipped.Count(bob.DHr))
		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10

		d, err := bob.RatchetDecrypt(m1, nil) // Decrypted and skipped.
		require.Nil(t, err)
		require.Equal(t, []byte("bob"), d)
		require.EqualValues(t, 1, bob.MkSkipped.Count(bob.DHr))

		_, err = bob.RatchetDecrypt(m3, nil) // Error: too many to skip.
		require.NotNil(t, err)

		d, err = bob.RatchetDecrypt(m2, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("how are you?"), d)

		m3.Ciphertext[len(m3.Ciphertext)-1] ^= 10
		_, err = bob.RatchetDecrypt(m3, nil) // Error: invalid signature.
		require.NotNil(t, err)
		m3.Ciphertext[len(m3.Ciphertext)-1] ^= 10

		d, err = bob.RatchetDecrypt(m3, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("still do cryptography?"), d)

		d, err = bob.RatchetDecrypt(m0, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("hi"), d)
	})
}

func TestState_SkippedKeysDeletion(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New(sk, MaxKeep(2))
		alice, _ = New(sk, RemoteKey(bob.PublicKey()), MaxKeep(2))
		h        = SessionTestHelper{t, alice, bob}
	)

	// Act.
	m0 := alice.RatchetEncrypt([]byte("Hi"), nil)

	h.AliceToBob("Bob!", nil)         // Bob ratchet step 1.
	h.BobToAlice("Alice?", nil)       // Alice ratchet step 1.
	h.AliceToBob("How are you?", nil) // Bob ratchet step 2.

	// Assert.
	_, err := bob.RatchetDecrypt(m0, nil)
	require.NotNil(t, err)
}

type SessionTestHelper struct {
	t *testing.T

	alice State
	bob   State
}

func (h SessionTestHelper) AliceToBob(msg string, ad AssociatedData) {
	var (
		msgByte = []byte(msg)
		m       = h.alice.RatchetEncrypt(msgByte, ad)
		d, err  = h.bob.RatchetDecrypt(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}

func (h SessionTestHelper) BobToAlice(msg string, ad AssociatedData) {
	var (
		msgByte = []byte(msg)
		m       = h.bob.RatchetEncrypt(msgByte, ad)
		d, err  = h.alice.RatchetDecrypt(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}

func (h SessionTestHelper) MustDecrypt(party State, m Message, ad AssociatedData) []byte {
	pt, err := party.RatchetDecrypt(m, ad)
	require.Nil(h.t, err)
	return pt
}
