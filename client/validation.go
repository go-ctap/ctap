package client

import (
	"fmt"

	pinvalidation "github.com/telesma-app/ctap/internal/pin"
	"github.com/telesma-app/ctap/protocol"
)

const clientDataHashSize = 32

func validateClientDataHash(clientDataHash []byte) error {
	if len(clientDataHash) != clientDataHashSize {
		return fmt.Errorf("clientDataHash must be exactly %d bytes", clientDataHashSize)
	}

	return nil
}

// validateFIPS140HMACSecret applies the PIN/UV auth protocol policy to an
// hmac-secret input. Callers must have established that the policy is active.
func validateFIPS140HMACSecret(hmacSecret protocol.HMACSecret) error {
	if hmacSecret.IsZero() {
		return nil
	}

	// CTAP defaults the omitted member to protocol 1.
	pinUvAuthProtocol := hmacSecret.PinUvAuthProtocol
	if pinUvAuthProtocol == 0 {
		pinUvAuthProtocol = protocol.PinUvAuthProtocolOne
	}

	return pinvalidation.ValidateFIPS140UvAuthProtocol(pinUvAuthProtocol)
}
