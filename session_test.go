package doubleratchet

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNew(t *testing.T) {
	// Act.
	var (
		si, err = New(sk, bobPair)
		s       = si.(*session)
	)

	// Assert.
	require.Nil(t, err)
	require.NotEqual(t, Key{}, s.DHs.PrivateKey())
	require.NotEqual(t, Key{}, s.DHs.PublicKey())
}

func TestNewWithRemoteKey(t *testing.T) {
	// Act.
	var (
		si, err = NewWithRemoteKey(sk, bobPair.PublicKey())
		s       = si.(*session)
	)

	// Assert.
	require.Nil(t, err)
	require.Equal(t, bobPair.PublicKey(), s.DHr)
	require.NotEqual(t, dhPair{}, s.DHs)
	require.NotEqual(t, Key{}, s.RootCh.CK)
	require.NotEqual(t, sk, s.RootCh.CK)
	require.NotEqual(t, Key{}, s.SendCh.CK)
	require.NotEqual(t, sk, s.SendCh.CK)
}

func TestState_RatchetEncryptDecrypt_Basic(t *testing.T) {
	// Arrange.
	var (
		si, err = NewWithRemoteKey(sk, bobPair.PublicKey())
		s       = si.(*session)
		oldCKs  = s.SendCh.CK
	)

	// Act.
	m := si.RatchetEncrypt([]byte("1337"), nil)

	// Assert.
	require.Nil(t, err)
	require.NotEqual(t, oldCKs, s.SendCh.CK)
	require.EqualValues(t, 1, s.SendCh.N)
	require.Equal(t, MessageHeader{
		DH: s.DHs.PublicKey(),
		N:  0,
		PN: 0,
	}, m.Header)
	require.NotEmpty(t, m.Ciphertext)
}

func TestState_RatchetDecrypt_CommunicationFailedWithNoPublicKey(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New(sk, bobPair)
		alice, _ = New(sk, alicePair)
	)

	// Act.
	var (
		m      = alice.RatchetEncrypt([]byte("something important"), nil)
		_, err = bob.RatchetDecrypt(m, nil)
	)

	// Assert.
	require.NotNil(t, err) // Invalid signature.
}

func TestState_RatchetDecrypt_CommunicationAliceSends(t *testing.T) {
	// Arrange.
	var (
		bob, _   = New(sk, bobPair)
		alice, _ = NewWithRemoteKey(sk, bobPair.PublicKey())
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
		bob, _   = New(sk, bobPair)
		alice, _ = NewWithRemoteKey(sk, bobPair.PublicKey())
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
		bob, _   = New(sk, bobPair)
		alice, _ = NewWithRemoteKey(sk, bobPair.PublicKey())
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
		bobI, _ = New(sk, bobPair, WithMaxSkip(1))
		bob     = bobI.(*session)

		aliceI, _ = NewWithRemoteKey(sk, bob.DHs.PublicKey(), WithMaxSkip(1))
		alice     = aliceI.(*session)
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
		bob, _   = New(sk, bobPair, WithMaxKeep(2))
		alice, _ = NewWithRemoteKey(sk, bobPair.PublicKey(), WithMaxKeep(2))
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

	alice Session
	bob   Session
}

func (h SessionTestHelper) AliceToBob(msg string, ad []byte) {
	var (
		msgByte = []byte(msg)
		m       = h.alice.RatchetEncrypt(msgByte, ad)
		d, err  = h.bob.RatchetDecrypt(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}

func (h SessionTestHelper) BobToAlice(msg string, ad []byte) {
	var (
		msgByte = []byte(msg)
		m       = h.bob.RatchetEncrypt(msgByte, ad)
		d, err  = h.alice.RatchetDecrypt(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}
