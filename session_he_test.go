package doubleratchet

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	sharedHka  = Key{0xbd, 0x29, 0x18, 0xcb, 0x18, 0x6c, 0x26, 0x32, 0xd5, 0x82, 0x41, 0x2d, 0x11, 0xa4, 0x55, 0x87, 0x1e, 0x5b, 0xa3, 0xb5, 0x5a, 0x6d, 0xe1, 0x97, 0xde, 0xf7, 0x5e, 0xc3, 0xf2, 0xec, 0x1d, 0xd}
	sharedNhkb = Key{0x32, 0x89, 0x3a, 0xed, 0x4b, 0xf0, 0xbf, 0xc1, 0xa5, 0xa9, 0x53, 0x73, 0x5b, 0xf9, 0x76, 0xce, 0x70, 0x8e, 0xe1, 0xa, 0xed, 0x98, 0x1d, 0xe3, 0xb4, 0xe9, 0xa9, 0x88, 0x54, 0x94, 0xaf, 0x23}
	k          = Key{0x4b, 0x22, 0x7f, 0x60, 0x7b, 0x1e, 0x76, 0xb6, 0xf5, 0xf2, 0x72, 0x22, 0xf3, 0x14, 0xaf, 0x69, 0x60, 0xca, 0xd4, 0x26, 0x51, 0x88, 0xc9, 0xd, 0xbf, 0x23, 0x42, 0xfd, 0x1a, 0x30, 0xad, 0x4b}
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
	m := si.RatchetEncryptHE([]byte("1337"), nil)

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

//func TestSessionHE_RatchetDecrypt_CommunicationPingPong(t *testing.T) {
//	// Arrange.
//	var (
//		bob, _   = New(sk, bobPair)
//		alice, _ = NewWithRemoteKey(sk, bobPair.PublicKey())
//	)
//
//	for i := 0; i < 10; i++ {
//		pt := fmt.Sprintf("msg%d", i)
//		t.Run(pt, func(t *testing.T) {
//			h := SessionTestHelper{t, alice, bob}
//
//			h.AliceToBob(pt+"alice", []byte("alice associated data"))
//			h.BobToAlice(pt+"bob", []byte("bob associated data"))
//		})
//	}
//}
//
//func TestSessionHE_RatchetDecrypt_CommunicationSkippedMessages(t *testing.T) {
//	// Arrange.
//	var (
//		bobI, _ = New(sk, bobPair, WithMaxSkip(1))
//		bob     = bobI.(*session)
//
//		aliceI, _ = NewWithRemoteKey(sk, bob.DHs.PublicKey(), WithMaxSkip(1))
//		alice     = aliceI.(*session)
//	)
//
//	t.Run("skipped messages from alice", func(t *testing.T) {
//		// Arrange.
//		var (
//			m0 = alice.RatchetEncrypt([]byte("hi"), nil)
//			m1 = alice.RatchetEncrypt([]byte("bob"), nil)
//			m2 = alice.RatchetEncrypt([]byte("how are you?"), nil)
//			m3 = alice.RatchetEncrypt([]byte("still do cryptography?"), nil)
//		)
//
//		// Act and assert.
//		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
//		_, err := bob.RatchetDecrypt(m1, nil) // Error: invalid signature.
//		require.NotNil(t, err)
//		require.EqualValues(t, 0, bob.MkSkipped.Count(bob.DHr))
//		m1.Ciphertext[len(m1.Ciphertext)-1] ^= 10
//
//		d, err := bob.RatchetDecrypt(m1, nil) // Decrypted and skipped.
//		require.Nil(t, err)
//		require.Equal(t, []byte("bob"), d)
//		require.EqualValues(t, 1, bob.MkSkipped.Count(bob.DHr))
//
//		_, err = bob.RatchetDecrypt(m3, nil) // Error: too many to skip.
//		require.NotNil(t, err)
//
//		d, err = bob.RatchetDecrypt(m2, nil) // Decrypted.
//		require.Nil(t, err)
//		require.Equal(t, []byte("how are you?"), d)
//
//		m3.Ciphertext[len(m3.Ciphertext)-1] ^= 10
//		_, err = bob.RatchetDecrypt(m3, nil) // Error: invalid signature.
//		require.NotNil(t, err)
//		m3.Ciphertext[len(m3.Ciphertext)-1] ^= 10
//
//		d, err = bob.RatchetDecrypt(m3, nil) // Decrypted.
//		require.Nil(t, err)
//		require.Equal(t, []byte("still do cryptography?"), d)
//
//		d, err = bob.RatchetDecrypt(m0, nil) // Decrypted.
//		require.Nil(t, err)
//		require.Equal(t, []byte("hi"), d)
//	})
//}
//
//func TestSessionHE_SkippedKeysDeletion(t *testing.T) {
//	// Arrange.
//	var (
//		bob, _   = New(sk, bobPair, WithMaxKeep(2))
//		alice, _ = NewWithRemoteKey(sk, bobPair.PublicKey(), WithMaxKeep(2))
//		h        = SessionTestHelper{t, alice, bob}
//	)
//
//	// Act.
//	m0 := alice.RatchetEncrypt([]byte("Hi"), nil)
//
//	h.AliceToBob("Bob!", nil)         // Bob ratchet step 1.
//	h.BobToAlice("Alice?", nil)       // Alice ratchet step 1.
//	h.AliceToBob("How are you?", nil) // Bob ratchet step 2.
//
//	// Assert.
//	_, err := bob.RatchetDecrypt(m0, nil)
//	require.NotNil(t, err)
//}

type SessionTestHelperHE struct {
	t *testing.T

	alice SessionHE
	bob   SessionHE
}

func (h SessionTestHelperHE) AliceToBob(msg string, ad []byte) {
	var (
		msgByte = []byte(msg)
		m       = h.alice.RatchetEncryptHE(msgByte, ad)
		d, err  = h.bob.RatchetDecryptHE(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}

func (h SessionTestHelperHE) BobToAlice(msg string, ad []byte) {
	var (
		msgByte = []byte(msg)
		m       = h.bob.RatchetEncryptHE(msgByte, ad)
		d, err  = h.alice.RatchetDecryptHE(m, ad)
	)
	require.Nil(h.t, err)
	require.EqualValues(h.t, msgByte, d)
}
