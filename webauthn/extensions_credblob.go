package webauthn

type CreateCredentialBlobInputs struct {
	CredBlob []byte `cbor:"credBlob" json:"credBlob,omitzero"`
}

type CreateCredentialBlobOutputs struct {
	CredBlob bool `cbor:"credBlob" json:"credBlob"`
}

type GetCredentialBlobInputs struct {
	GetCredBlob bool `cbor:"getCredBlob" json:"getCredBlob,omitzero"`
}

type GetCredentialBlobOutputs struct {
	GetCredBlob []byte `cbor:"getCredBlob" json:"getCredBlob"`
}
