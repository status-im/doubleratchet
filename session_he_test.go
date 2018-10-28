package doubleratchet

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	sharedHka  = Key{0xbd, 0x29, 0x18, 0xcb, 0x18, 0x6c, 0x26, 0x32, 0xd5, 0x82, 0x41, 0x2d, 0x11, 0xa4, 0x55, 0x87, 0x1e, 0x5b, 0xa3, 0xb5, 0x5a, 0x6d, 0xe1, 0x97, 0xde, 0xf7, 0x5e, 0xc3, 0xf2, 0xec, 0x1d, 0xd}
	sharedNhkb = Key{0x32, 0x89, 0x3a, 0xed, 0x4b, 0xf0, 0xbf, 0xc1, 0xa5, 0xa9, 0x53, 0x73, 0x5b, 0xf9, 0x76, 0xce, 0x70, 0x8e, 0xe1, 0xa, 0xed, 0x98, 0x1d, 0xe3, 0xb4, 0xe9, 0xa9, 0x88, 0x54, 0x94, 0xaf, 0x23}
)

func TestNewHE(t *testing.T) {
	// Act.
	var (
		si, err = NewHE(sk, sharedHka, sharedNhkb, bobPair)
		s       = si.(*sessionHE)
	)

	// Assert.
	require.Nil(t, err)
	require.Equal(t, dhPair{bobPair.PrivateKey(), bobPair.PublicKey()}, s.DHs)
	require.Equal(t, sharedNhkb, s.NHKs)
	require.Equal(t, sharedHka, s.HKs)
	require.Equal(t, sharedHka, s.NHKr)
}

func TestNewHEWithRemoteKey(t *testing.T) {
	// Act.
	var (
		si, err = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey())
		s       = si.(*sessionHE)
	)

	// Assert.
	require.Nil(t, err)
	require.NotEqual(t, dhPair{}, s.DHs)
	require.Equal(t, bobPair.PublicKey(), s.DHr)
	require.NotEqual(t, Key{}, s.NHKs)
	require.Equal(t, sharedHka, s.HKs)
	require.Equal(t, sharedNhkb, s.NHKr)
	require.Equal(t, sharedHka, s.HKs)
	require.NotEqual(t, Key{}, s.RootCh.CK)
	require.NotEqual(t, sk, s.RootCh.CK)
	require.NotEqual(t, Key{}, s.SendCh.CK)
	require.NotEqual(t, sk, s.SendCh.CK)
}

func TestSessionHE_RatchetEncrypt_Basic(t *testing.T) {
	// Arrange.
	var (
		si, err = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey())
		s       = si.(*sessionHE)
		oldCKs  = s.SendCh.CK
	)

	// Act.
	m := si.RatchetEncrypt([]byte("1337"), nil)

	// Assert.
	require.Nil(t, err)
	require.NotEqual(t, oldCKs, s.SendCh.CK)
	require.EqualValues(t, 1, s.SendCh.N)
	require.NotEmpty(t, m.Header)
	require.NotEmpty(t, m.Ciphertext)
}

func TestSessionHE_RatchetDecrypt_CommunicationAliceSends(t *testing.T) {
	// Arrange.
	var (
		bob, _   = NewHE(sk, sharedHka, sharedNhkb, bobPair)
		alice, _ = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey())
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelperHE{t, alice, bob}
			h.AliceToBob(pt, []byte("alice associated data"))
		})
	}
}

func TestSessionHE_RatchetDecrypt_CommunicationBobSends(t *testing.T) {
	// Arrange.
	var (
		bob, _   = NewHE(sk, sharedHka, sharedNhkb, bobPair)
		alice, _ = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey())
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelperHE{t, alice, bob}
			h.BobToAlice(pt, []byte("bob associated data"))
		})
	}
}

func TestSessionHE_RatchetDecrypt_CommunicationPingPong(t *testing.T) {
	// Arrange.
	var (
		bob, _   = NewHE(sk, sharedHka, sharedNhkb, bobPair)
		alice, _ = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey())
	)

	for i := 0; i < 10; i++ {
		pt := fmt.Sprintf("msg%d", i)
		t.Run(pt, func(t *testing.T) {
			h := SessionTestHelperHE{t, alice, bob}

			h.AliceToBob(pt+"alice", []byte("alice associated data"))
			h.BobToAlice(pt+"bob", []byte("bob associated data"))
		})
	}
}

func TestSessionHE_RatchetDecrypt_CommunicationSkippedMessages(t *testing.T) {
	// Arrange.
	var (
		bobI, _ = NewHE(sk, sharedHka, sharedNhkb, bobPair, WithMaxSkip(1))
		bob     = bobI.(*sessionHE)

		aliceI, _ = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey(), WithMaxSkip(1))
		alice     = aliceI.(*sessionHE)
	)

	t.Run("skipped messages from alice", func(t *testing.T) {
		// Arrange.
		var (
			m0 = alice.RatchetEncrypt([]byte("hi"), nil)
			m1 = alice.RatchetEncrypt([]byte("bob"), nil)
			m2 = alice.RatchetEncrypt([]byte("how are you?"), nil)
			m3 = alice.RatchetEncrypt([]byte("still do cryptography?"), nil)
			m4 = alice.RatchetEncrypt([]byte("what up bob?"), nil)
			m5 = alice.RatchetEncrypt([]byte("bob?"), nil)
		)

		// Act and assert.
		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
		_, err := bob.RatchetDecrypt(m1, nil) // Error: invalid signature.
		require.NotNil(t, err)

		bobSkippedCount, err := bob.MkSkipped.Count(bob.HKr)
		require.NoError(t, err)
		require.EqualValues(t, 0, bobSkippedCount)

		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
		d, err := bob.RatchetDecrypt(m1, nil) // Decrypted and skipped.
		require.Nil(t, err)
		require.Equal(t, []byte("bob"), d)

		bobSkippedCount, err = bob.MkSkipped.Count(bob.HKr)
		require.NoError(t, err)
		require.EqualValues(t, 1, bobSkippedCount)

		_, err = bob.RatchetDecrypt(m5, nil) // Error: too many to skip.
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
		require.Equal(t, []byte("what up bob?"), d)

		d, err = bob.RatchetDecrypt(m5, nil) // Decrypted.
		require.Nil(t, err)
		require.Equal(t, []byte("bob?"), d)

	})
}

func TestSessionHE_OldKeysDeletion(t *testing.T) {
	// Arrange.
	var (
		bob, _   = NewHE(sk, sharedHka, sharedNhkb, bobPair, WithMaxKeep(2))
		alice, _ = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey(), WithMaxKeep(2))
	)

	// Act.
	m0 := alice.RatchetEncrypt([]byte("Hi 1"), nil)
	m1 := alice.RatchetEncrypt([]byte("Hi 2"), nil)
	m2 := alice.RatchetEncrypt([]byte("Hi 3"), nil)
	m3 := alice.RatchetEncrypt([]byte("Hi 4"), nil)

	// Assert.

	// This one should be in the db
	_, err := bob.RatchetDecrypt(m1, nil)
	require.Nil(t, err)

	// This one should be in the db
	_, err = bob.RatchetDecrypt(m3, nil)
	require.Nil(t, err)

	// This key should be discarded
	_, err = bob.RatchetDecrypt(m0, nil)
	require.NotNil(t, err)

	// This one should be in the db
	_, err = bob.RatchetDecrypt(m2, nil)
	require.Nil(t, err)
}

func TestSessionHE_ExtraKeysDeletion(t *testing.T) {
	// Arrange.
	var (
		bob, _   = NewHE(sk, sharedHka, sharedNhkb, bobPair, WithMaxMessageKeysPerSession(2))
		alice, _ = NewHEWithRemoteKey(sk, sharedHka, sharedNhkb, bobPair.PublicKey(), WithMaxMessageKeysPerSession(2))
	)

	// Act.
	m0 := alice.RatchetEncrypt([]byte("Hi 1"), nil)
	m1 := alice.RatchetEncrypt([]byte("Hi 2"), nil)
	m2 := alice.RatchetEncrypt([]byte("Hi 3"), nil)
	m3 := alice.RatchetEncrypt([]byte("Hi 4"), nil)

	// Assert.
	_, err := bob.RatchetDecrypt(m3, nil)
	require.Nil(t, err)

	// This key should be discarded
	_, err = bob.RatchetDecrypt(m0, nil)
	require.NotNil(t, err)

	// This one should be in the db
	_, err = bob.RatchetDecrypt(m1, nil)
	require.Nil(t, err)

	// This one should be in the db
	_, err = bob.RatchetDecrypt(m2, nil)
	require.Nil(t, err)
}

type SessionTestHelperHE struct {
	t *testing.T

	alice SessionHE
	bob   SessionHE
}

func (h SessionTestHelperHE) AliceToBob(msg string, ad []byte) {
	var (
		msgByte = []byte(msg)
		m       = h.alice.RatchetEncrypt(msgByte, ad)
		d, err  = h.bob.RatchetDecrypt(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}

func (h SessionTestHelperHE) BobToAlice(msg string, ad []byte) {
	var (
		msgByte = []byte(msg)
		m       = h.bob.RatchetEncrypt(msgByte, ad)
		d, err  = h.alice.RatchetDecrypt(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}
