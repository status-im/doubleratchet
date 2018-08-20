package doubleratchet

type SessionStorage interface {
	// Get returns a message key by the given key and message number.
	Save(id []byte, state *State) error

	// Put saves the given mk under the specified key and msgNum.
	Load(id []byte) (*State, error)
}
