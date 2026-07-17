package protocol

import (
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/google/uuid"
)

type (
	Version           string
	Versions          []Version
	PinUvAuthProtocol uint
	UserVerify        uint
)

const (
	FIDO_2_0     Version = "FIDO_2_0"
	FIDO_2_1_PRE Version = "FIDO_2_1_PRE"
	FIDO_2_1     Version = "FIDO_2_1"
	FIDO_2_3     Version = "FIDO_2_3"
	U2F_V2       Version = "U2F_V2"
)

const (
	PinUvAuthProtocolOne PinUvAuthProtocol = iota + 1
	PinUvAuthProtocolTwo
)

const (
	UserVerifyPresenceInternal UserVerify = 1 << iota
	UserVerifyFingerprintInternal
	UserVerifyPasscodeInternal
	UserVerifyVoiceprintInternal
	UserVerifyFaceprintInternal
	UserVerifyLocationInternal
	UserVerifyEyeprintInternal
	UserVerifyPatternInternal
	UserVerifyHandprintInternal
	UserVerifyPasscodeExternal
	UserVerifyPatternExternal
	UserVerifyNone
	UserVerifyAll
)

func (uv UserVerify) String() string {
	switch uv {
	case UserVerifyPresenceInternal:
		return "presence_internal"
	case UserVerifyFingerprintInternal:
		return "fingerprint_internal"
	case UserVerifyPasscodeInternal:
		return "passcode_internal"
	case UserVerifyVoiceprintInternal:
		return "voiceprint_internal"
	case UserVerifyFaceprintInternal:
		return "faceprint_internal"
	case UserVerifyLocationInternal:
		return "location_internal"
	case UserVerifyEyeprintInternal:
		return "eyeprint_internal"
	case UserVerifyPatternInternal:
		return "pattern_internal"
	case UserVerifyHandprintInternal:
		return "handprint_internal"
	case UserVerifyPasscodeExternal:
		return "passcode_external"
	case UserVerifyPatternExternal:
		return "pattern_external"
	case UserVerifyNone:
		return "none"
	case UserVerifyAll:
		return "all"
	default:
		return ""
	}
}

const (
	DefaultMaxMsgSize       uint = 1024
	DefaultMinPINCodePoints uint = 4
	DefaultMaxPINCodePoints uint = 63
)

// AuthenticatorGetInfoResponse is used in Metadata Statement specification as well, so json notation added.
type AuthenticatorGetInfoResponse struct {
	Versions                         Versions                                           `cbor:"1,keyasint" json:"versions"`
	Extensions                       []extension.ExtensionIdentifier                    `cbor:"2,keyasint" json:"extensions,omitempty"`
	AAGUID                           uuid.UUID                                          `cbor:"3,keyasint" json:"aaguid"`
	Options                          map[Option]bool                                    `cbor:"4,keyasint" json:"options,omitempty"`
	MaxMsgSize                       *uint                                              `cbor:"5,keyasint" json:"maxMsgSize,omitempty"`
	PinUvAuthProtocols               []PinUvAuthProtocol                                `cbor:"6,keyasint" json:"pinUvAuthProtocols,omitempty"`
	MaxCredentialCountInList         *uint                                              `cbor:"7,keyasint" json:"maxCredentialCountInList,omitempty"`
	MaxCredentialIdLength            *uint                                              `cbor:"8,keyasint" json:"maxCredentialIdLength,omitempty"`
	Transports                       []credential.AuthenticatorTransport                `cbor:"9,keyasint" json:"transports,omitempty"`
	Algorithms                       []credential.PublicKeyCredentialParameters         `cbor:"10,keyasint" json:"algorithms,omitempty"`
	MaxSerializedLargeBlobArray      *uint                                              `cbor:"11,keyasint" json:"maxSerializedLargeBlobArray,omitempty"`
	ForcePINChange                   *bool                                              `cbor:"12,keyasint" json:"forcePINChange,omitempty"`
	MinPINLength                     *uint                                              `cbor:"13,keyasint" json:"minPINLength,omitempty"`
	FirmwareVersion                  *uint                                              `cbor:"14,keyasint" json:"firmwareVersion,omitempty"`
	MaxCredBlobLength                *uint                                              `cbor:"15,keyasint" json:"maxCredBlobLength,omitempty"`
	MaxRPIDsForSetMinPINLength       *uint                                              `cbor:"16,keyasint" json:"maxRPIDsForSetMinPINLength,omitempty"`
	PreferredPlatformUvAttempts      *uint                                              `cbor:"17,keyasint" json:"preferredPlatformUvAttempts,omitempty"`
	UvModality                       *UserVerify                                        `cbor:"18,keyasint" json:"uvModality,omitempty"`
	Certifications                   map[string]uint64                                  `cbor:"19,keyasint" json:"certifications,omitempty"`
	RemainingDiscoverableCredentials *uint                                              `cbor:"20,keyasint" json:"remainingDiscoverableCredentials,omitempty"`
	VendorPrototypeConfigCommands    []VendorCommandID                                  `cbor:"21,keyasint" json:"vendorPrototypeConfigCommands,omitempty"`
	AttestationFormats               []attestation.AttestationStatementFormatIdentifier `cbor:"22,keyasint" json:"attestationFormats,omitempty"`
	UvCountSinceLastPinEntry         *uint                                              `cbor:"23,keyasint" json:"uvCountSinceLastPinEntry,omitempty"`
	LongTouchForReset                *bool                                              `cbor:"24,keyasint" json:"longTouchForReset,omitempty"`
	EncIdentifier                    []byte                                             `cbor:"25,keyasint" json:"encIdentifier,omitempty"`
	TransportsForReset               []credential.AuthenticatorTransport                `cbor:"26,keyasint" json:"transportsForReset,omitempty"`
	PinComplexityPolicy              *bool                                              `cbor:"27,keyasint" json:"pinComplexityPolicy,omitempty"`
	PinComplexityPolicyURL           []byte                                             `cbor:"28,keyasint" json:"pinComplexityPolicyURL,omitempty"`
	MaxPINLength                     *uint                                              `cbor:"29,keyasint" json:"maxPINLength,omitempty"`
	EncCredStoreState                []byte                                             `cbor:"30,keyasint" json:"encCredStoreState,omitempty"`
	AuthenticatorConfigCommands      []ConfigSubCommand                                 `cbor:"31,keyasint" json:"authenticatorConfigCommands,omitempty"`
}

func (r *AuthenticatorGetInfoResponse) EffectiveMaxMsgSize() uint {
	if r.MaxMsgSize != nil {
		return *r.MaxMsgSize
	}

	return DefaultMaxMsgSize
}

func (r *AuthenticatorGetInfoResponse) EffectiveMinPINLength() uint {
	if r.MinPINLength != nil && *r.MinPINLength > DefaultMinPINCodePoints {
		return *r.MinPINLength
	}

	return DefaultMinPINCodePoints
}

// EffectiveMaxPINLength returns the authenticator's maximum PIN length in
// Unicode code points. CTAP defines 63 code points as the effective value when
// maxPINLength is absent.
func (r *AuthenticatorGetInfoResponse) EffectiveMaxPINLength() uint {
	if r.MaxPINLength != nil {
		return *r.MaxPINLength
	}

	return DefaultMaxPINCodePoints
}

// PinComplexityPolicyURLString returns pinComplexityPolicyURL as a string.
// The field is a CBOR byte string on the wire.
func (r *AuthenticatorGetInfoResponse) PinComplexityPolicyURLString() string {
	return string(r.PinComplexityPolicyURL)
}

func (r *AuthenticatorGetInfoResponse) MaxCredBlobLengthValue() (uint, bool) {
	if r.MaxCredBlobLength == nil {
		return 0, false
	}

	return *r.MaxCredBlobLength, true
}

func (r *AuthenticatorGetInfoResponse) MaxSerializedLargeBlobArrayValue() (uint, bool) {
	if r.MaxSerializedLargeBlobArray == nil {
		return 0, false
	}

	return *r.MaxSerializedLargeBlobArray, true
}
