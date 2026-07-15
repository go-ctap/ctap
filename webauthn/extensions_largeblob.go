package webauthn

import "github.com/go-ctap/ctap/extension"

type AuthenticationExtensionsLargeBlobInputs struct {
	Support extension.LargeBlobSupport `cbor:"support,omitzero" json:"support,omitzero"`
	Read    bool                       `cbor:"read,omitzero" json:"read,omitzero"`
	Write   []byte                     `cbor:"write,omitzero" json:"write,omitzero"`
}

type LargeBlobInputs struct {
	LargeBlob AuthenticationExtensionsLargeBlobInputs `cbor:"largeBlob" json:"largeBlob,omitempty"`
}

type AuthenticationExtensionsLargeBlobOutputs struct {
	Supported bool   `cbor:"supported" json:"supported"`
	Blob      []byte `cbor:"blob,omitzero" json:"blob,omitzero"`
	Written   bool   `cbor:"written,omitzero" json:"written,omitzero"`
}

type LargeBlobOutputs struct {
	LargeBlob AuthenticationExtensionsLargeBlobOutputs `cbor:"largeBlob" json:"largeBlob"`
}
