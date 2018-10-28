package doubleratchet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	pubKey1 = Key{0xe3, 0xbe, 0xb9, 0x4e, 0x70, 0x17, 0x37, 0xc, 0x1, 0x8f, 0xa9, 0x7e, 0xef, 0x4, 0xfb, 0x23, 0xac, 0xea, 0x28, 0xf7, 0xa9, 0x56, 0xcc, 0x1d, 0x46, 0xf3, 0xb5, 0x1d, 0x7d, 0x7d, 0x5e, 0x2c}
	pubKey2 = Key{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}
	mk      = Key{0xeb, 0x8, 0x10, 0x7c, 0x33, 0x54, 0x0, 0x20, 0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a, 0x2f, 0x60, 0xbe, 0x81, 0xa, 0x78, 0x8b, 0xeb, 0x1e, 0x2c, 0x9, 0x8d, 0x4b, 0x4d, 0xc1, 0x40}
)

func TestKeysStorageInMemory_Get(t *testing.T) {
	// Arrange.
	ks := &KeysStorageInMemory{}

	// Act.
	_, ok, err := ks.Get(pubKey1, 0)

	// Assert.
	require.NoError(t, err)
	require.False(t, ok)
}

func TestKeysStorageInMemory_Put(t *testing.T) {
	// Arrange.
	ks := &KeysStorageInMemory{}

	// Act and assert.
	err := ks.Put([]byte("session-id"), pubKey1, 0, mk, 1)
	require.NoError(t, err)
}

func TestKeysStorageInMemory_Count(t *testing.T) {
	// Arrange.
	ks := &KeysStorageInMemory{}

	// Act.
	cnt, err := ks.Count(pubKey1)

	// Assert.
	require.NoError(t, err)
	require.EqualValues(t, 0, cnt)
}

func TestKeysStorageInMemory_Delete(t *testing.T) {
	// Arrange.
	ks := &KeysStorageInMemory{}

	// Act and assert.
	err := ks.DeleteMk(pubKey1, 0)
	require.NoError(t, err)
}

func TestKeysStorageInMemory_Flow(t *testing.T) {
	// Arrange.
	ks := &KeysStorageInMemory{}

	t.Run("put and get existing", func(t *testing.T) {
		// Act.
		err := ks.Put([]byte("session-id"), pubKey1, 0, mk, 1)
		require.NoError(t, err)

		k, ok, err := ks.Get(pubKey1, 0)

		// Assert.
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, mk, k)
	})

	t.Run("get all", func(t *testing.T) {
		// Act.
		all, err := ks.All()

		// Assert.
		require.NoError(t, err)
		require.Len(t, all, 1)
		require.Len(t, all[pubKey1], 1)
		require.Equal(t, mk, all[pubKey1][0])
	})

	t.Run("get non-existent pub key", func(t *testing.T) {
		// Act.
		_, ok, err := ks.Get(pubKey2, 0)

		// Assert.
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("get non-existent message key of existing pubkey", func(t *testing.T) {
		// Act.
		_, ok, err := ks.Get(pubKey1, 1)

		// Assert.
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("count", func(t *testing.T) {
		// Act.
		cnt, err := ks.Count(pubKey1)

		// Assert.
		require.NoError(t, err)
		require.EqualValues(t, 1, cnt)
	})

	t.Run("delete non-existent message key of existing pubkey", func(t *testing.T) {
		// Act and assert.
		err := ks.DeleteMk(pubKey1, 1)
		require.NoError(t, err)
	})

	t.Run("delete non-existent message key of non-existent pubkey", func(t *testing.T) {
		// Act and assert.
		err := ks.DeleteMk(pubKey2, 0)
		require.NoError(t, err)
	})

	t.Run("delete existing message key", func(t *testing.T) {
		// Act.
		err := ks.DeleteMk(pubKey1, 0)
		require.NoError(t, err)

		cnt, err := ks.Count(pubKey1)

		// Assert.
		require.NoError(t, err)
		require.EqualValues(t, 0, cnt)
	})
}
