package doubleratchet

type AssociatedData []byte

// MarshalBinary implements BinaryMarshaler interface.
func (ad AssociatedData) MarshalBinary() ([]byte, error) {
	// TODO: Are lengths more than 255 needed?
	return append([]byte{byte(len(ad))}, ad...), nil
}
