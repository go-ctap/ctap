// Package transport defines the transport-independent CTAP message boundary.
package transport

import (
	"errors"
	"io"

	"github.com/go-ctap/ctap/protocol"
)

// CBORResponse is a transport-independent CTAP response.
type CBORResponse struct {
	StatusCode StatusCode
	Data       []byte
}

// ValidateCBORResponse returns a typed CTAP error for a non-success response.
func ValidateCBORResponse(command protocol.Command, response CBORResponse) (CBORResponse, error) {
	if response.StatusCode != CTAP2_OK {
		return CBORResponse{}, &CTAPError{Command: command, StatusCode: response.StatusCode}
	}

	return response, nil
}

// CTAPError reports a non-success status returned by an authenticator command.
type CTAPError struct {
	Command    protocol.Command
	StatusCode StatusCode
}

func (e *CTAPError) Error() string {
	return e.Command.String() + " failed (" + e.StatusCode.String() + ")"
}

func (e *CTAPError) Unwrap() error {
	return errors.New(e.StatusCode.String())
}

// CBOR exchanges one CTAP command byte followed by its CBOR payload.
// Implementations return a CTAPError when the authenticator status is not OK.
type CBOR interface {
	CBOR(data []byte) (CBORResponse, error)
}

// Device is an owned CTAP transport connection.
type Device interface {
	CBOR
	io.Closer
}
