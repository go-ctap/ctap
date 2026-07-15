package webauthn

type CreateHMACSecretInputs struct {
	HMACCreateSecret bool `cbor:"hmacCreateSecret" json:"hmacCreateSecret,omitzero"`
}

type CreateHMACSecretOutputs struct {
	HMACCreateSecret bool `cbor:"hmacCreateSecret" json:"hmacCreateSecret"`
}

type HMACGetSecretInput struct {
	Salt1 []byte `cbor:"salt1" json:"salt1"`
	Salt2 []byte `cbor:"salt2,omitempty" json:"salt2,omitempty"`
}

type GetHMACSecretInputs struct {
	HMACGetSecret HMACGetSecretInput `cbor:"hmacGetSecret" json:"hmacGetSecret,omitempty"`
}

type HMACGetSecretOutput struct {
	Output1 []byte `cbor:"output1" json:"output1"`
	Output2 []byte `cbor:"output2,omitempty" json:"output2,omitempty"`
}

type GetHMACSecretOutputs struct {
	HMACGetSecret HMACGetSecretOutput `cbor:"hmacGetSecret" json:"hmacGetSecret"`
}

type CreateHMACSecretMCInputs struct {
	HMACGetSecret HMACGetSecretInput `cbor:"hmacGetSecret" json:"hmacGetSecret,omitempty"`
}

type CreateHMACSecretMCOutputs struct {
	HMACGetSecret HMACGetSecretOutput `cbor:"hmacGetSecret" json:"hmacGetSecret"`
}
