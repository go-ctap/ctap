package webauthn

type CreateMinPinLengthInputs struct {
	MinPinLength bool `cbor:"minPinLength" json:"minPinLength,omitzero"`
}
