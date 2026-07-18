package client

import (
	"context"
	"encoding/hex"
	"reflect"
	"testing"

	ctapdiag "github.com/go-ctap/ctap/diagnostic"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderDiagnosticRedactsTaggedFieldsAndShowsOtherFields(t *testing.T) {
	secret := []byte("pin-hash-canary")
	request := protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.PinUvAuthProtocolOne,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		PinHashEnc:        secret,
		RPID:              "engineers.example",
	}
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(request)
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		reflect.TypeFor[protocol.AuthenticatorClientPINRequest](),
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, diagnosticRedacted)
	assert.Contains(t, diagnostic.Notation, "engineers.example")
	assert.NotContains(t, diagnostic.Notation, hex.EncodeToString(secret))
	assert.Equal(t, []string{"PinHashEnc"}, diagnostic.RedactedFields)
}

func TestRenderDiagnosticRedactsNestedExtensionFields(t *testing.T) {
	salt := []byte("salt-canary")
	request := protocol.AuthenticatorGetAssertionRequest{
		RPID:           "engineers.example",
		ClientDataHash: make([]byte, 32),
		Extensions: protocol.GetExtensionInputs{
			GetHMACSecretInput: protocol.GetHMACSecretInput{
				HMACSecret: protocol.HMACSecret{
					SaltEnc: salt,
				},
			},
		},
	}
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(request)
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest](),
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, diagnosticRedacted)
	assert.NotContains(t, diagnostic.Notation, hex.EncodeToString(salt))
	assert.Equal(t, []string{
		"Extensions.HMACSecret.SaltAuth",
		"Extensions.HMACSecret.SaltEnc",
	}, diagnostic.RedactedFields)
}

func TestRenderDiagnosticDropsUnknownFields(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		2:  uint64(protocol.ClientPINSubCommandGetPINRetries),
		10: "engineers.example",
		99: "unknown-field-canary",
	})
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		reflect.TypeFor[protocol.AuthenticatorClientPINRequest](),
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, "engineers.example")
	assert.NotContains(t, diagnostic.Notation, "unknown-field-canary")
}

func TestExchangeLogsStructuredRedactedDiagnostic(t *testing.T) {
	requestSecret := []byte("request-secret")
	responseSecret := []byte("response-secret")
	request := protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.PinUvAuthProtocolOne,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		PinHashEnc:        requestSecret,
		RPID:              "engineers.example",
	}
	response := protocol.AuthenticatorClientPINResponse{
		PinUvAuthToken: responseSecret,
	}
	configured := options.NewOptions()
	requestBody, err := configured.EncMode.Marshal(request)
	require.NoError(t, err)
	responseBody, err := configured.EncMode.Marshal(response)
	require.NoError(t, err)

	var events []ctapdiag.Exchange
	transport := &fakeCBORTransport{
		t:        t,
		request:  append([]byte{byte(protocol.AuthenticatorClientPIN)}, requestBody...),
		response: responseBody,
	}
	client, err := NewClient(
		options.WithDiagnosticSink(func(_ context.Context, event ctapdiag.Exchange) {
			events = append(events, event)
		}),
		options.WithTransport(transport),
	)
	require.NoError(t, err)

	_, err = client.cbor(context.Background(), transport.request)
	require.NoError(t, err)
	require.Len(t, events, 1)

	event := events[0]
	assert.Equal(t, protocol.AuthenticatorClientPIN, event.Command)
	assert.Equal(t, uint64(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions), event.SubCommand)
	assert.Equal(t, len(requestBody), event.Request.Bytes)
	assert.Equal(t, len(responseBody), event.Response.Bytes)
	require.NotNil(t, event.Status)
	assert.Equal(t, ctaptransport.CTAP2_OK, *event.Status)

	assert.Contains(t, event.Request.Notation, "engineers.example")
	assert.Contains(t, event.Request.Notation, "REDACTED")
	assert.NotContains(t, event.Request.Notation, hex.EncodeToString(requestSecret))
	assert.Equal(t, []string{"PinHashEnc"}, event.Request.RedactedFields)

	assert.Contains(t, event.Response.Notation, "REDACTED")
	assert.NotContains(t, event.Response.Notation, hex.EncodeToString(responseSecret))
	assert.Equal(t, []string{"PinUvAuthToken"}, event.Response.RedactedFields)
}
