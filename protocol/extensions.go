package protocol

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/extension"
)

type CreateCredProtectInput struct {
	CredProtect int `cbor:"credProtect,omitzero"`
}

type CreateCredProtectOutput struct {
	CredProtect int `cbor:"credProtect,omitzero"`
}

type CreateCredBlobInput struct {
	CredBlob []byte `cbor:"credBlob,omitzero"`
}

type CreateCredBlobOutput struct {
	CredBlob bool `cbor:"credBlob"`
}

type GetCredBlobInput struct {
	CredBlob bool `cbor:"credBlob,omitzero"`
}

type GetCredBlobOutput struct {
	CredBlob []byte `cbor:"credBlob,omitzero"`
}

type CreateLargeBlobKeyInput struct {
	LargeBlobKey bool `cbor:"largeBlobKey,omitzero"`
}

type GetLargeBlobKeyInput struct {
	LargeBlobKey bool `cbor:"largeBlobKey,omitzero"`
}

type CreateLargeBlobParams struct {
	Support extension.LargeBlobSupport `cbor:"support"`
}

type CreateLargeBlobInput struct {
	LargeBlob CreateLargeBlobParams `cbor:"largeBlob,omitzero"`
}

type CreateLargeBlobOutput struct {
	Supported bool `cbor:"supported"`
}

type GetLargeBlobParams struct {
	Read         bool   `cbor:"read,omitempty"`
	Write        []byte `cbor:"write,omitzero"`
	OriginalSize *uint  `cbor:"originalSize,omitempty"`
}

type GetLargeBlobInput struct {
	LargeBlob GetLargeBlobParams `cbor:"largeBlob,omitzero"`
}

type GetLargeBlobOutput struct {
	Written      *bool  `cbor:"written,omitempty"`
	Blob         []byte `cbor:"blob,omitzero"`
	OriginalSize *uint  `cbor:"originalSize,omitempty"`
}

type CreateMinPinLengthInput struct {
	MinPinLength bool `cbor:"minPinLength,omitzero"`
}

type CreateMinPinLengthOutput struct {
	MinPinLength uint `cbor:"minPinLength,omitzero"`
}

type CreatePinComplexityPolicyInput struct {
	PinComplexityPolicy bool `cbor:"pinComplexityPolicy,omitzero"`
}

type CreatePinComplexityPolicyOutput struct {
	PinComplexityPolicy bool `cbor:"pinComplexityPolicy"`
}

type HMACSecret struct {
	KeyAgreement      cose.Key          `cbor:"1,keyasint"`
	SaltEnc           []byte            `cbor:"2,keyasint"`
	SaltAuth          []byte            `cbor:"3,keyasint"`
	PinUvAuthProtocol PinUvAuthProtocol `cbor:"4,keyasint,omitempty"`
}

type CreateHMACSecretInput struct {
	HMACSecret bool `cbor:"hmac-secret,omitzero"`
}

type CreateHMACSecretOutput struct {
	HMACSecret bool `cbor:"hmac-secret"`
}

type GetHMACSecretInput struct {
	HMACSecret HMACSecret `cbor:"hmac-secret,omitzero"`
}

type GetHMACSecretOutput struct {
	HMACSecret []byte `cbor:"hmac-secret,omitzero"`
}

type CreateHMACSecretMCInput struct {
	HMACSecret HMACSecret `cbor:"hmac-secret-mc,omitzero"`
}

type CreateHMACSecretMCOutput struct {
	HMACSecret []byte `cbor:"hmac-secret-mc,omitzero"`
}

type CreateThirdPartyPaymentInput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment,omitzero"`
}

type GetThirdPartyPaymentInput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment,omitzero"`
}

type GetThirdPartyPaymentOutput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

// CreateExtensionInputs aggregates MakeCredential extension inputs in CTAP
// 2.3 PS § 12 order.
type CreateExtensionInputs struct {
	CreateCredProtectInput
	CreateCredBlobInput
	CreateLargeBlobKeyInput
	CreateLargeBlobInput
	CreateMinPinLengthInput
	CreatePinComplexityPolicyInput
	CreateHMACSecretInput
	CreateHMACSecretMCInput
	CreateThirdPartyPaymentInput
}

type CreateExtensionOutputs struct {
	CreateCredProtectOutput
	*CreateCredBlobOutput
	CreateMinPinLengthOutput
	*CreatePinComplexityPolicyOutput
	*CreateHMACSecretOutput
	CreateHMACSecretMCOutput
}

type GetExtensionInputs struct {
	GetCredBlobInput
	GetLargeBlobKeyInput
	GetLargeBlobInput
	GetHMACSecretInput
	GetThirdPartyPaymentInput
}

type GetExtensionOutputs struct {
	GetCredBlobOutput
	GetHMACSecretOutput
	*GetThirdPartyPaymentOutput
}

func decodeUnsignedExtensionOutput[T any](
	outputs map[extension.ExtensionIdentifier]any,
	identifier extension.ExtensionIdentifier,
) (*T, error) {
	value, ok := outputs[identifier]
	if !ok {
		return nil, nil
	}

	encoded, err := cbor.Marshal(value)
	if err != nil {
		return nil, err
	}

	var output T
	if err := cbor.Unmarshal(encoded, &output); err != nil {
		return nil, err
	}

	return &output, nil
}
