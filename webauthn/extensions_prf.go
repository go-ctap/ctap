package webauthn

type AuthenticationExtensionsPRFValues struct {
	First  []byte `cbor:"first" json:"first"`
	Second []byte `cbor:"second,omitzero" json:"second,omitzero"`
}

func (v AuthenticationExtensionsPRFValues) IsZero() bool {
	return v.First == nil && v.Second == nil
}

type AuthenticationExtensionsPRFInputs struct {
	Eval             AuthenticationExtensionsPRFValues            `cbor:"eval,omitzero" json:"eval,omitzero"`
	EvalByCredential map[string]AuthenticationExtensionsPRFValues `cbor:"evalByCredential,omitzero" json:"evalByCredential,omitzero"`
}

type PRFInputs struct {
	PRF AuthenticationExtensionsPRFInputs `cbor:"prf" json:"prf,omitempty"`
}

type CreateAuthenticationExtensionsPRFOutputs struct {
	Enabled bool                              `cbor:"enabled" json:"enabled"`
	Results AuthenticationExtensionsPRFValues `cbor:"results,omitzero" json:"results,omitzero"`
}

type CreatePRFOutputs struct {
	PRF CreateAuthenticationExtensionsPRFOutputs `cbor:"prf" json:"prf"`
}

type GetAuthenticationExtensionsPRFOutputs struct {
	Results AuthenticationExtensionsPRFValues `cbor:"results,omitzero" json:"results,omitzero"`
}

type GetPRFOutputs struct {
	PRF GetAuthenticationExtensionsPRFOutputs `cbor:"prf" json:"prf"`
}
