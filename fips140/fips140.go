// Package fips140 exposes the CTAP policy integration with Go's FIPS 140-3
// mode.
package fips140

import (
	cryptofips140 "crypto/fips140"
	"errors"
)

// ErrNotAllowed identifies an operation rejected by the CTAP FIPS 140-3
// policy.
var ErrNotAllowed = errors.New("fips140: operation is not allowed in FIPS 140-3 mode")

// Required reports whether CTAP must apply its FIPS 140-3 policy.
//
// It follows the process-wide mode reported by [crypto/fips140.Enabled].
func Required() bool {
	return cryptofips140.Enabled()
}

// NotAllowedError reports a CTAP operation rejected by the FIPS 140-3 policy.
type NotAllowedError struct {
	Operation string
}

// Error implements error.
func (e *NotAllowedError) Error() string {
	if e == nil || e.Operation == "" {
		return ErrNotAllowed.Error()
	}
	return "fips140: " + e.Operation + " is not allowed in FIPS 140-3 mode"
}

// Unwrap makes ErrNotAllowed available through errors.Is.
func (e *NotAllowedError) Unwrap() error {
	return ErrNotAllowed
}
