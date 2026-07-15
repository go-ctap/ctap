package webauthn

type CreateCredentialPropertiesInputs struct {
	CredentialProperties bool `cbor:"credProps" json:"credProps,omitzero"`
}

type CredentialPropertiesOutput struct {
	ResidentKey *bool `cbor:"rk,omitempty" json:"rk,omitempty"`
}

type CreateCredentialPropertiesOutputs struct {
	CredentialProperties CredentialPropertiesOutput `cbor:"credProps" json:"credProps"`
}
