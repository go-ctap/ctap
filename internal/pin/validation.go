package pin

import (
	"fmt"
	"unicode/utf8"

	"github.com/telesma-app/ctap/protocol"
	"golang.org/x/text/unicode/norm"
)

const maxUTF8Bytes = 63

// ValidateUvAuthToken validates the token length accepted by the selected
// PIN/UV auth protocol. Callers with authenticator version information may
// apply stricter version-specific requirements.
func ValidateUvAuthToken(pinUvAuthProtocol protocol.PinUvAuthProtocol, pinUvAuthToken []byte) error {
	switch pinUvAuthProtocol {
	case protocol.PinUvAuthProtocolOne:
		// CTAP 2.0 allowed any positive multiple of the AES block size. CTAP
		// 2.1 narrowed this to 16 or 32 bytes; callers with authenticator
		// version information enforce that stricter requirement.
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

// NormalizeAndValidate normalizes a PIN to NFC and validates the minimum code
// point count and CTAP UTF-8 representation limit.
func NormalizeAndValidate(value string, minCodePoints uint) (string, error) {
	if minCodePoints < protocol.DefaultMinPINCodePoints {
		minCodePoints = protocol.DefaultMinPINCodePoints
	}

	value = norm.NFC.String(value)
	if uint(utf8.RuneCountInString(value)) < minCodePoints {
		return "", fmt.Errorf("pin must contain at least %d Unicode code points", minCodePoints)
	}
	if len([]byte(value)) > maxUTF8Bytes {
		return "", fmt.Errorf("pin must be at most %d UTF-8 bytes", maxUTF8Bytes)
	}
	if value[len(value)-1] == 0x00 {
		return "", fmt.Errorf("pin must not end in a 0x00 byte")
	}

	return value, nil
}
