package attestation

import "github.com/telesma-app/ctap/cose"

// AttestationStatementFormatIdentifier is an enum consisting of IANA registered Attestation Statement Format Identifiers.
// https://www.iana.org/assignments/webauthn/webauthn.xhtml
type AttestationStatementFormatIdentifier string

const (
	AttestationStatementFormatIdentifierPacked           AttestationStatementFormatIdentifier = "packed"
	AttestationStatementFormatIdentifierTPM              AttestationStatementFormatIdentifier = "tpm"
	AttestationStatementFormatIdentifierAndroidKey       AttestationStatementFormatIdentifier = "android-key"
	AttestationStatementFormatIdentifierAndroidSafetyNet AttestationStatementFormatIdentifier = "android-safetynet"
	AttestationStatementFormatIdentifierFIDOU2F          AttestationStatementFormatIdentifier = "fido-u2f"
	AttestationStatementFormatIdentifierApple            AttestationStatementFormatIdentifier = "apple"
	AttestationStatementFormatIdentifierNone             AttestationStatementFormatIdentifier = "none"
)

// PackedAttestationStatementFormat is a WebAuthn optimized attestation statement format.
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type PackedAttestationStatementFormat struct {
	Algorithm cose.Algorithm `cbor:"alg" json:"alg"`
	Signature []byte         `cbor:"sig" json:"sig"`
	X509Chain [][]byte       `cbor:"x5c,omitempty" json:"x5c,omitempty"`
}

// FIDOU2FAttestationStatementFormat is attestation statement format is used with FIDO U2F authenticators.
// https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation
type FIDOU2FAttestationStatementFormat struct {
	X509Chain [][]byte `cbor:"x5c" json:"x5c"`
	Signature []byte   `cbor:"sig" json:"sig"`
}

// TPMAttestationStatementFormat is generally used by authenticators that use a Trusted Platform Module
// as their cryptographic engine.
// https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
type TPMAttestationStatementFormat struct {
	Version   string         `cbor:"ver" json:"ver"`
	Algorithm cose.Algorithm `cbor:"alg" json:"alg"`
	X509Chain [][]byte       `cbor:"x5c" json:"x5c"`
	Signature []byte         `cbor:"sig" json:"sig"`
	CertInfo  []byte         `cbor:"certInfo" json:"certInfo"` // TPMS_ATTEST structure
	PubArea   []byte         `cbor:"pubArea" json:"pubArea"`   // TPMT_PUBLIC structure
}
