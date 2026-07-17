package webauthn

import "github.com/go-ctap/ctap/extension"

type AuthenticationExtensionsLargeBlobInputs struct {
	Support extension.LargeBlobSupport `cbor:"support,omitzero" json:"support,omitzero"`
	Read    *bool                      `cbor:"read,omitempty" json:"read,omitempty"`
	Write   []byte                     `cbor:"write,omitzero" json:"write,omitzero"`
}

type LargeBlobInputs struct {
	LargeBlob AuthenticationExtensionsLargeBlobInputs `cbor:"largeBlob" json:"largeBlob,omitempty"`
}

type AuthenticationExtensionsLargeBlobOutputs struct {
	Supported *bool  `cbor:"supported,omitempty" json:"supported,omitempty"`
	Blob      []byte `cbor:"blob,omitzero" json:"blob,omitzero"`
	Written   *bool  `cbor:"written,omitempty" json:"written,omitempty"`
}

type LargeBlobOutputs struct {
	LargeBlob AuthenticationExtensionsLargeBlobOutputs `cbor:"largeBlob" json:"largeBlob"`
}
