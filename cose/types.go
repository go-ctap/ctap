// Package cose contains the small subset of COSE types used by CTAP.
package cose

// Algorithm identifies an entry in the IANA COSE Algorithms registry.
type Algorithm int

const (
	// AlgorithmES256 is ECDSA with SHA-256 on the P-256 curve.
	AlgorithmES256 Algorithm = -7
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
	KeyTypeEC2 = 2
)

// COSE EC2 key parameter labels.
const (
	EC2KeyParameterCrv = -1
	EC2KeyParameterX   = -2
	EC2KeyParameterY   = -3
)

// COSE elliptic curve identifiers used by CTAP key agreement.
const (
	EllipticCurveP256 = 1
)
