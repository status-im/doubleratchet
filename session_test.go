package doubleratchet

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	// Act.
	var (
		si, err = New([]byte("id"), sk, bobPair, nil)
		s       = si.(*sessionState)
	)

	// Assert.
	require.Nil(t, err)
	require.NotEqual(t, Key{}, s.DHs.PrivateKey())
	require.NotEqual(t, Key{}, s.DHs.PublicKey())
}

func TestNew_BadOption(t *testing.T) {
	// Act.
	_, err := New([]byte("id"), sk, bobPair, nil, WithMaxSkip(-10))

	// Assert.
	require.NotNil(t, err)
}

func TestNewWithRemoteKey(t *testing.T) {
	// Act.
	si, err := NewWithRemoteKey([]byte("id"), sk, bobPair.PublicKey(), nil)
	require.NoError(t, err)

	s := si.(*sessionState)

	// Assert.
	require.Nil(t, err)
	require.Equal(t, bobPair.PublicKey(), s.DHr)
	require.NotEqual(t, dhPair{}, s.DHs)
	require.NotEqual(t, Key{}, s.RootCh.CK)
	require.NotEqual(t, sk, s.RootCh.CK)
	require.NotEqual(t, Key{}, s.SendCh.CK)
	require.NotEqual(t, sk, s.SendCh.CK)
}

func TestNewWithRemoteKey_BadOption(t *testing.T) {
	// Act.
	_, err := NewWithRemoteKey([]byte("id"), sk, bobPair.PublicKey(), nil, WithMaxSkip(-10))

	// Assert.
	require.NotNil(t, err)
}

func TestSession_RatchetEncrypt_Basic(t *testing.T) {
	// Arrange.
	si, err := NewWithRemoteKey([]byte("id"), sk, bobPair.PublicKey(), nil)
	require.NoError(t, err)

	s := si.(*sessionState)
	oldCKs := s.SendCh.CK

	// Act.
	m, err := si.RatchetEncrypt([]byte("1337"), nil)

	// Assert.
	require.NoError(t, err)
	require.NotEqual(t, oldCKs, s.SendCh.CK)
	require.EqualValues(t, 1, s.SendCh.N)
	require.Equal(t, MessageHeader{
		DH: s.DHs.PublicKey(),
		N:  0,
		PN: 0,
	}, m.Header)
	require.NotEmpty(t, m.Ciphertext)
}

func TestSession_RatchetDecrypt_CommunicationFailedWithNoPublicKey(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New([]byte("bob"), sk, bobPair, nil)
		alice, _ = New([]byte("alice"), sk, alicePair, nil)
	)

	// Act.
	m, err := alice.RatchetEncrypt([]byte("something important"), nil)
	require.NoError(t, err)

	_, err = bob.RatchetDecrypt(m, nil)

	// Assert.
	require.NotNil(t, err) // Invalid signature.
}

func TestSession_RatchetDecrypt_CommunicationAliceSends(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New([]byte("bob"), sk, bobPair, nil)
		alice, _ = NewWithRemoteKey([]byte("alice"), sk, bobPair.PublicKey(), nil)
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelper{t, alice, bob}
			h.AliceToBob(pt, []byte("alice associated data"))
		})
	}
}

func TestSession_RatchetDecrypt_CommunicationBobSends(t *testing.T) {
	var (
		bob, _   = New([]byte("bob"), sk, bobPair, nil)
		alice, _ = NewWithRemoteKey([]byte("alice"), sk, bobPair.PublicKey(), nil)
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelper{t, alice, bob}
			h.BobToAlice(pt, []byte("bob associated data"))
		})
	}
}

func TestSession_RatchetDecrypt_CommunicationPingPong(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New([]byte("bob"), sk, bobPair, nil)
		alice, _ = NewWithRemoteKey([]byte("alice"), sk, bobPair.PublicKey(), nil)
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

func TestSession_RatchetDecrypt_CommunicationSkippedMessages(t *testing.T) {
	// Arrange.
	var (
		bobI, _ = New([]byte("bob"), sk, bobPair, nil, WithMaxSkip(1))
		bob     = bobI.(*sessionState)

		aliceI, _ = NewWithRemoteKey([]byte("alice"), sk, bob.DHs.PublicKey(), nil, WithMaxSkip(1))
		alice     = aliceI.(*sessionState)
	)

	t.Run("skipped messages from alice", func(t *testing.T) {
		// Arrange.
		m0, err := alice.RatchetEncrypt([]byte("hi"), nil)
		require.NoError(t, err)

		m1, err := alice.RatchetEncrypt([]byte("bob"), nil)
		require.NoError(t, err)

		m2, err := alice.RatchetEncrypt([]byte("how are you?"), nil)
		require.NoError(t, err)

		m3, err := alice.RatchetEncrypt([]byte("still do cryptography?"), nil)
		require.NoError(t, err)

		m4, err := alice.RatchetEncrypt([]byte("you there?"), nil)
		require.NoError(t, err)

		m5, err := alice.RatchetEncrypt([]byte("bob? bob? BOB? BOB?"), nil)
		require.NoError(t, err)

		// Act and assert.
		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
		_, err = bob.RatchetDecrypt(m1, nil) // Error: invalid signature.
		require.NotNil(t, err)

		bobSkippedCount, err := bob.MkSkipped.Count(bob.DHr)
		require.NoError(t, err)
		require.EqualValues(t, 0, bobSkippedCount)

		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
		d, err := bob.RatchetDecrypt(m1, nil) // Decrypted and skipped.
		require.Nil(t, err)
		require.Equal(t, []byte("bob"), d)

		bobSkippedCount, err = bob.MkSkipped.Count(bob.DHr)
		require.NoError(t, err)
		require.EqualValues(t, 2, bobSkippedCount)

		_, err = bob.RatchetDecrypt(m5, nil) // Too many messages
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

		d, err = bob.RatchetDecrypt(m4, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("you there?"), d)

		d, err = bob.RatchetDecrypt(m5, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("bob? bob? BOB? BOB?"), d)
	})
}

func TestSession_SkippedKeysDeletion(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New([]byte("bob"), sk, bobPair, nil, WithMaxKeep(2))
		alice, _ = NewWithRemoteKey([]byte("alice"), sk, bobPair.PublicKey(), nil, WithMaxKeep(2))
		h        = SessionTestHelper{t, alice, bob}
	)

	// Act.
	m0, err := alice.RatchetEncrypt([]byte("Hi"), nil)
	require.NoError(t, err)

	h.AliceToBob("Bob!", nil)         // Bob ratchet step 1.
	h.BobToAlice("Alice?", nil)       // Alice ratchet step 1.
	h.AliceToBob("How are you?", nil) // Bob ratchet step 2.

	// Assert.
	_, err = bob.RatchetDecrypt(m0, nil)
	require.NotNil(t, err)
}

type SessionTestHelper struct {
	t *testing.T

	alice Session
	bob   Session
}

func (h SessionTestHelper) AliceToBob(msg string, ad []byte) {
	msgByte := []byte(msg)

	m, err := h.alice.RatchetEncrypt(msgByte, ad)
	require.NoError(h.t, err)

	d, err := h.bob.RatchetDecrypt(m, ad)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}

func (h SessionTestHelper) BobToAlice(msg string, ad []byte) {
	msgByte := []byte(msg)

	m, err := h.bob.RatchetEncrypt(msgByte, ad)
	require.NoError(h.t, err)

	d, err := h.alice.RatchetDecrypt(m, ad)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}
