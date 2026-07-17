package credential

import "github.com/go-ctap/ctap/cose"

type (
	// PublicKeyCredentialType defines the valid credential types.
	// https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialtype
	PublicKeyCredentialType string
	// AuthenticatorTransport defines hints as to how clients might communicate
	// with a particular authenticator in order to obtain an assertion for a specific credential.
	// https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport
	AuthenticatorTransport string
	// PublicKeyCredentialHint is used by WebAuthn Relying Parties to communicate hints to the user-agent about
	// how a request may be best completed.
	// https://www.w3.org/TR/webauthn-3/#enum-hints
	PublicKeyCredentialHint string
)

const (
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

const (
	AuthenticatorTransportUSB       AuthenticatorTransport = "usb"
	AuthenticatorTransportNFC       AuthenticatorTransport = "nfc"
	AuthenticatorTransportBLE       AuthenticatorTransport = "ble"
	AuthenticatorTransportSmartCard AuthenticatorTransport = "smart-card"
	AuthenticatorTransportHybrid    AuthenticatorTransport = "hybrid"
	AuthenticatorTransportInternal  AuthenticatorTransport = "internal"
)

const (
	PublicKeyCredentialHintSecurityKey  PublicKeyCredentialHint = "security-key"
	PublicKeyCredentialHintClientDevice PublicKeyCredentialHint = "client-device"
	PublicKeyCredentialHintHybrid       PublicKeyCredentialHint = "hybrid"
)

// PublicKeyCredentialRpEntity is used to supply additional Relying Party attributes when creating a new credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity
type PublicKeyCredentialRpEntity struct {
	ID   string `cbor:"id" json:"id"`
	Name string `cbor:"name,omitempty" json:"name"`
}

// PublicKeyCredentialUserEntity is used to supply additional user account attributes when creating a new credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity
type PublicKeyCredentialUserEntity struct {
	ID          []byte `cbor:"id" json:"id"`
	DisplayName string `cbor:"displayName" json:"displayName"`
	Name        string `cbor:"name" json:"name"`
	Icon        string `cbor:"icon,omitempty" json:"icon,omitempty"` // deprecated
}

// PublicKeyCredentialDescriptor identifies a specific public key credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor
type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType  `cbor:"type" json:"type"`
	ID         []byte                   `cbor:"id" json:"id"`
	Transports []AuthenticatorTransport `cbor:"transports,omitempty" json:"transports,omitempty"`
}

// PublicKeyCredentialParameters is used to supply additional parameters when creating a new credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
type PublicKeyCredentialParameters struct {
	Type      PublicKeyCredentialType `cbor:"type" json:"type"`
	Algorithm cose.Algorithm          `cbor:"alg" json:"alg"`
}
