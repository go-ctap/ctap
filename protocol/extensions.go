package protocol

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/extension"
)

type CreateCredProtectInput struct {
	CredProtect int `cbor:"credProtect"`
}

type CreateCredProtectOutput struct {
	CredProtect int `cbor:"credProtect"`
}

type CreateCredBlobInput struct {
	CredBlob []byte `cbor:"credBlob"`
}

type CreateCredBlobOutput struct {
	CredBlob bool `cbor:"credBlob"`
}

type GetCredBlobInput struct {
	CredBlob bool `cbor:"credBlob"`
}

type GetCredBlobOutput struct {
	CredBlob []byte `cbor:"credBlob"`
}

type CreateLargeBlobKeyInput struct {
	LargeBlobKey bool `cbor:"largeBlobKey"`
}

type GetLargeBlobKeyInput struct {
	LargeBlobKey bool `cbor:"largeBlobKey"`
}

type CreateLargeBlobParams struct {
	Support extension.LargeBlobSupport `cbor:"support"`
}

type CreateLargeBlobInput struct {
	LargeBlob CreateLargeBlobParams `cbor:"largeBlob"`
}

type CreateLargeBlobOutput struct {
	Supported *bool `cbor:"supported,omitempty"`
}

type GetLargeBlobParams struct {
	Read         bool   `cbor:"read,omitempty"`
	Write        []byte `cbor:"write,omitzero"`
	OriginalSize *uint  `cbor:"originalSize,omitempty"`
}

type GetLargeBlobInput struct {
	LargeBlob GetLargeBlobParams `cbor:"largeBlob"`
}

type GetLargeBlobOutput struct {
	Written      *bool  `cbor:"written,omitempty"`
	Blob         []byte `cbor:"blob,omitzero"`
	OriginalSize *uint  `cbor:"originalSize,omitempty"`
}

type CreateMinPinLengthInput struct {
	MinPinLength bool `cbor:"minPinLength"`
}

type CreateMinPinLengthOutput struct {
	MinPinLength uint `cbor:"minPinLength"`
}

type CreatePinComplexityPolicyInput struct {
	PinComplexityPolicy bool `cbor:"pinComplexityPolicy"`
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
	HMACSecret bool `cbor:"hmac-secret"`
}

type CreateHMACSecretOutput struct {
	HMACSecret bool `cbor:"hmac-secret"`
}

type GetHMACSecretInput struct {
	HMACSecret HMACSecret `cbor:"hmac-secret"`
}

type GetHMACSecretOutput struct {
	HMACSecret []byte `cbor:"hmac-secret"`
}

type CreateHMACSecretMCInput struct {
	HMACSecret HMACSecret `cbor:"hmac-secret-mc"`
}

type CreateHMACSecretMCOutput struct {
	HMACSecret []byte `cbor:"hmac-secret-mc"`
}

type CreateThirdPartyPaymentInput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

type GetThirdPartyPaymentInput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

type GetThirdPartyPaymentOutput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

// CreateExtensionInputs aggregates MakeCredential extension inputs in CTAP
// 2.3 PS § 12 order.
type CreateExtensionInputs struct {
	*CreateCredProtectInput
	*CreateCredBlobInput
	*CreateLargeBlobKeyInput
	*CreateLargeBlobInput
	*CreateMinPinLengthInput
	*CreatePinComplexityPolicyInput
	*CreateHMACSecretInput
	*CreateHMACSecretMCInput
	*CreateThirdPartyPaymentInput
}

type CreateExtensionOutputs struct {
	*CreateCredProtectOutput
	*CreateCredBlobOutput
	*CreateMinPinLengthOutput
	*CreatePinComplexityPolicyOutput
	*CreateHMACSecretOutput
	*CreateHMACSecretMCOutput
}

type GetExtensionInputs struct {
	*GetCredBlobInput
	*GetLargeBlobKeyInput
	*GetLargeBlobInput
	*GetHMACSecretInput
	*GetThirdPartyPaymentInput
}

type GetExtensionOutputs struct {
	*GetCredBlobOutput
	*GetHMACSecretOutput
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
