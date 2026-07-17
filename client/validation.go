package client

import (
	"fmt"
	"unicode/utf8"

	"github.com/go-ctap/ctap/protocol"
	"golang.org/x/text/unicode/norm"
)

const (
	defaultMinPINCodePoints uint = 4
	maxPINUTF8Bytes         int  = 63
	clientDataHashSize      int  = 32
)

func ValidateClientDataHash(clientDataHash []byte) error {
	if len(clientDataHash) != clientDataHashSize {
		return fmt.Errorf("clientDataHash must be exactly %d bytes", clientDataHashSize)
	}

	return nil
}

// ValidatePinUvAuthToken validates the token length accepted by the selected
// PIN/UV auth protocol across CTAP versions before it is used as a
// cryptographic key. Callers with authenticator version information may apply
// stricter version-specific requirements.
func ValidatePinUvAuthToken(pinUvAuthProtocol protocol.PinUvAuthProtocol, pinUvAuthToken []byte) error {
	switch pinUvAuthProtocol {
	case protocol.PinUvAuthProtocolOne:
		// CTAP 2.0 allowed any positive multiple of the AES block size. CTAP
		// 2.1 narrowed this to 16 or 32 bytes; that requirement is enforced by
		// the high-level authenticator client, which has version information.
		if len(pinUvAuthToken) == 0 || len(pinUvAuthToken)%16 != 0 {
			return fmt.Errorf("pinUvAuthToken must be a positive multiple of 16 bytes for PIN/UV auth protocol 1")
		}
	case protocol.PinUvAuthProtocolTwo:
		if len(pinUvAuthToken) != 32 {
			return fmt.Errorf("pinUvAuthToken must be 32 bytes for PIN/UV auth protocol 2")
		}
	default:
		return fmt.Errorf("unsupported PIN/UV auth protocol %d", pinUvAuthProtocol)
	}

	return nil
}

func NormalizeAndValidatePIN(pin string, minCodePoints uint) (string, error) {
	if minCodePoints < defaultMinPINCodePoints {
		minCodePoints = defaultMinPINCodePoints
	}

	pin = norm.NFC.String(pin)
	if uint(utf8.RuneCountInString(pin)) < minCodePoints {
		return "", fmt.Errorf("pin must contain at least %d Unicode code points", minCodePoints)
	}
	if len([]byte(pin)) > maxPINUTF8Bytes {
		return "", fmt.Errorf("pin must be at most %d UTF-8 bytes", maxPINUTF8Bytes)
	}
	if pin[len(pin)-1] == 0x00 {
		return "", fmt.Errorf("pin must not end in a 0x00 byte")
	}

	return pin, nil
}

func normalizeAndValidatePIN(pin string) (string, error) {
	return NormalizeAndValidatePIN(pin, defaultMinPINCodePoints)
}
