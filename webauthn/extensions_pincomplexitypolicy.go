package webauthn

type CreatePinComplexityPolicyInputs struct {
	PinComplexityPolicy bool `cbor:"pinComplexityPolicy" json:"pinComplexityPolicy,omitzero"`
}
