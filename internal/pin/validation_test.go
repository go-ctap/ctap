package pin

import (
	"strings"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUvAuthToken(t *testing.T) {
	tests := []struct {
		name     string
		protocol protocol.PinUvAuthProtocol
		length   int
		wantErr  bool
	}{
		{name: "protocol 1 16 bytes", protocol: protocol.PinUvAuthProtocolOne, length: 16},
		{name: "protocol 1 32 bytes", protocol: protocol.PinUvAuthProtocolOne, length: 32},
		{name: "protocol 1 CTAP 2.0 compatible length", protocol: protocol.PinUvAuthProtocolOne, length: 48},
		{name: "protocol 1 empty", protocol: protocol.PinUvAuthProtocolOne, wantErr: true},
		{name: "protocol 1 wrong length", protocol: protocol.PinUvAuthProtocolOne, length: 31, wantErr: true},
		{name: "protocol 2 32 bytes", protocol: protocol.PinUvAuthProtocolTwo, length: 32},
		{name: "protocol 2 16 bytes", protocol: protocol.PinUvAuthProtocolTwo, length: 16, wantErr: true},
		{name: "unknown protocol", protocol: 99, length: 32, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUvAuthToken(tt.protocol, make([]byte, tt.length))
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNormalizeAndValidate(t *testing.T) {
	t.Run("rejects PIN below explicit minimum", func(t *testing.T) {
		_, err := NormalizeAndValidate("12345", 6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 6")
	})

	t.Run("rejects PIN over UTF-8 limit", func(t *testing.T) {
		_, err := NormalizeAndValidate(strings.Repeat("a", 64), protocol.DefaultMinPINCodePoints)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "63 UTF-8 bytes")
	})

	t.Run("normalizes PIN to NFC", func(t *testing.T) {
		value, err := NormalizeAndValidate("Cafe\u0301123", protocol.DefaultMinPINCodePoints)
		require.NoError(t, err)
		assert.Equal(t, "Caf\u00e9123", value)
	})

	t.Run("rejects PIN ending in NUL byte", func(t *testing.T) {
		_, err := NormalizeAndValidate("1234\x00", protocol.DefaultMinPINCodePoints)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0x00")
	})
}
