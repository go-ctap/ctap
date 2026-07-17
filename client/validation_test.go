package client

import (
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/stretchr/testify/require"
)

func TestValidatePinUvAuthToken(t *testing.T) {
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
			err := ValidatePinUvAuthToken(tt.protocol, make([]byte, tt.length))
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
