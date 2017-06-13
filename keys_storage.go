package doubleratchet

// KeysStorage is an interface of an abstract in-memory or persistent keys storage.
type KeysStorage interface {
	// Get returns a message key by the given public key and message number.
	Get(pubKey [32]byte, msgNum uint) (mk [32]byte, ok bool)

	// Put saves the given mk under the specified pubKey and msgNum.
	Put(pubKey [32]byte, msgNum uint, mk [32]byte)

	// Delete ensures there's no message key under the specified pubKey and msgNum.
	Delete(pubKey [32]byte, msgNum uint)

	// Count returns number of message keys stored under pubKey.
	Count(pubKey [32]byte) uint
}

// KeysStorageInMemory is an in-memory message keys storage.
type KeysStorageInMemory struct {
	keys map[[32]byte]map[uint][32]byte
}

func (s *KeysStorageInMemory) Get(pubKey [32]byte, msgNum uint) ([32]byte, bool) {
	if s.keys == nil {
		s.keys = make(map[[32]byte]map[uint][32]byte)
	}
	msgs, ok := s.keys[pubKey]
	if !ok {
		return [32]byte{}, false
	}
	mk, ok := msgs[msgNum]
	if !ok {
		return [32]byte{}, false
	}
	return mk, true
}

func (s *KeysStorageInMemory) Put(pubKey [32]byte, msgNum uint, mk [32]byte) {
	if s.keys == nil {
		s.keys = make(map[[32]byte]map[uint][32]byte)
	}
	if _, ok := s.keys[pubKey]; !ok {
		s.keys[pubKey] = make(map[uint][32]byte)
	}
	s.keys[pubKey][msgNum] = mk
}

func (s *KeysStorageInMemory) Delete(pubKey [32]byte, msgNum uint) {
	if s.keys == nil {
		return
	}
	if _, ok := s.keys[pubKey]; !ok {
		return
	}
	if _, ok := s.keys[pubKey][msgNum]; !ok {
		return
	}
	delete(s.keys[pubKey], msgNum)
	if len(s.keys[pubKey]) == 0 {
		delete(s.keys, pubKey)
	}
}

func (s *KeysStorageInMemory) Count(pubKey [32]byte) uint {
	if s.keys == nil {
		return 0
	}
	return uint(len(s.keys[pubKey]))
}
