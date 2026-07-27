// Package cose contains COSE types and signature primitives used by CTAP.
package cose

// Algorithm identifies an entry in the IANA COSE Algorithms registry.
type Algorithm int

const (
	// AlgorithmES256 is ECDSA with SHA-256 on the P-256 curve.
	AlgorithmES256 Algorithm = -7
	// AlgorithmESP256 is deterministic ECDSA with SHA-256 on the P-256 curve.
	AlgorithmESP256 Algorithm = -9
	// AlgorithmES384 is ECDSA with SHA-384 on the P-384 curve.
	AlgorithmES384 Algorithm = -35
	// AlgorithmESP384 is deterministic ECDSA with SHA-384 on the P-384 curve.
	AlgorithmESP384 Algorithm = -51
	// AlgorithmES512 is ECDSA with SHA-512 on the P-521 curve.
	AlgorithmES512 Algorithm = -36
	// AlgorithmESP512 is deterministic ECDSA with SHA-512 on the P-521 curve.
	AlgorithmESP512 Algorithm = -52
	// AlgorithmEdDSA is EdDSA using a key-selected Edwards curve.
	AlgorithmEdDSA Algorithm = -8
	// AlgorithmEd25519 is EdDSA using Ed25519.
	AlgorithmEd25519 Algorithm = -19
	// AlgorithmRS256 is RSASSA-PKCS1-v1_5 with SHA-256.
	AlgorithmRS256 Algorithm = -257
	// AlgorithmRS384 is RSASSA-PKCS1-v1_5 with SHA-384.
	AlgorithmRS384 Algorithm = -258
	// AlgorithmRS512 is RSASSA-PKCS1-v1_5 with SHA-512.
	AlgorithmRS512 Algorithm = -259
	// AlgorithmPS256 is RSASSA-PSS with SHA-256.
	AlgorithmPS256 Algorithm = -37
	// AlgorithmPS384 is RSASSA-PSS with SHA-384.
	AlgorithmPS384 Algorithm = -38
	// AlgorithmPS512 is RSASSA-PSS with SHA-512.
	AlgorithmPS512 Algorithm = -39
	// AlgorithmECDHESHKDF256 is ECDH ES with HKDF-SHA-256.
	AlgorithmECDHESHKDF256 Algorithm = -25
)

// COSE common key parameter labels.
const (
	KeyParameterKty = 1
	KeyParameterAlg = 3
)

// COSE key types used by CTAP.
const (
	KeyTypeOKP = 1
	KeyTypeEC2 = 2
	KeyTypeRSA = 3
)

// COSE OKP key parameter labels.
const (
	OKPKeyParameterCrv = -1
	OKPKeyParameterX   = -2
)

// COSE EC2 key parameter labels.
const (
	EC2KeyParameterCrv = -1
	EC2KeyParameterX   = -2
	EC2KeyParameterY   = -3
)

// COSE RSA key parameter labels.
const (
	RSAKeyParameterN = -1
	RSAKeyParameterE = -2
)

// COSE elliptic curve identifiers used by CTAP key agreement.
const (
	EllipticCurveP256    = 1
	EllipticCurveP384    = 2
	EllipticCurveP521    = 3
	EllipticCurveEd25519 = 6
)
