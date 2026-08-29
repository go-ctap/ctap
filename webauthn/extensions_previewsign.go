package webauthn

import "github.com/telesma-app/ctap/cose"

type PreviewSignGenerateKeyInputs struct {
	Algorithms []cose.Algorithm `cbor:"algorithms" json:"algorithms"`
}

type PreviewSignSignInputs struct {
	KeyHandle           []byte `cbor:"keyHandle" json:"keyHandle"`
	ToBeSigned          []byte `cbor:"tbs" json:"tbs"`
	AdditionalArguments []byte `cbor:"additionalArgs,omitzero" json:"additionalArgs,omitzero"`
}

type AuthenticationExtensionsPreviewSignInputs struct {
	GenerateKey      *PreviewSignGenerateKeyInputs    `cbor:"generateKey,omitempty" json:"generateKey,omitempty"`
	SignByCredential map[string]PreviewSignSignInputs `cbor:"signByCredential,omitzero" json:"signByCredential,omitzero"`
}

type PreviewSignInputs struct {
	PreviewSign AuthenticationExtensionsPreviewSignInputs `cbor:"previewSign" json:"previewSign"`
}

type PreviewSignGeneratedKey struct {
	KeyHandle         []byte         `cbor:"keyHandle" json:"keyHandle"`
	PublicKey         []byte         `cbor:"publicKey" json:"publicKey"`
	Algorithm         cose.Algorithm `cbor:"algorithm" json:"algorithm"`
	AttestationObject []byte         `cbor:"attestationObject" json:"attestationObject"`
}

type AuthenticationExtensionsPreviewSignOutputs struct {
	GeneratedKey *PreviewSignGeneratedKey `cbor:"generatedKey,omitempty" json:"generatedKey,omitempty"`
	Signature    []byte                   `cbor:"signature,omitzero" json:"signature,omitzero"`
}

type PreviewSignOutputs struct {
	PreviewSign AuthenticationExtensionsPreviewSignOutputs `cbor:"previewSign" json:"previewSign"`
}
