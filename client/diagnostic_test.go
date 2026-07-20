package client

import (
	"context"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
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
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, diagnosticRedacted)
	assert.Contains(t, diagnostic.Notation, "h'/[REDACTED]/'")
	assert.Contains(t, diagnostic.Notation, "engineers.example")
	assert.NotContains(t, diagnostic.Notation, hex.EncodeToString(secret))
	assert.Equal(t, []string{"PinHashEnc"}, diagnostic.RedactedFields)
}

func TestDiagnosticRedactionPreservesCBORMajorType(t *testing.T) {
	configured := options.NewOptions()
	formatter := diagnosticFormatter{decoder: configured.DecMode}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"unsigned integer", uint64(42), `/[REDACTED]/ 0`},
		{"negative integer", int64(-42), `/[REDACTED]/ -1`},
		{"byte string", []byte("secret-canary"), `h'/[REDACTED]/'`},
		{"text string", "secret-canary", `/[REDACTED]/ ""`},
		{"array", []any{"secret-canary"}, "[\n  /[REDACTED]/\n]"},
		{"map", map[string]any{"secret": "secret-canary"}, "{\n  /[REDACTED]/\n}"},
		{"tag", cbor.Tag{Number: 24, Content: []byte("secret-canary")}, `24(h'/[REDACTED]/')`},
		{"boolean", true, `/[REDACTED]/ false`},
		{"null", nil, `/[REDACTED]/ null`},
		{"undefined", cbor.SimpleValue(23), `/[REDACTED]/ undefined`},
		{"float", 1.5, `/[REDACTED]/ 0.0`},
		{"simple value", cbor.SimpleValue(16), `/[REDACTED]/ simple(0)`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoder := configured.EncMode
			if _, ok := test.value.(cbor.Tag); ok {
				encoder, _ = cbor.EncOptions{}.EncMode()
			}

			raw, err := encoder.Marshal(test.value)
			require.NoError(t, err)

			notation, err := formatter.redactedNotation(raw, 0)
			require.NoError(t, err)
			assert.Equal(t, test.want, notation)
			assert.NotContains(t, notation, "secret-canary")
		})
	}
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
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest]()},
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, diagnosticRedacted)
	assert.NotContains(t, diagnostic.Notation, hex.EncodeToString(salt))
	assert.Equal(t, []string{
		"Extensions.HMACSecret.SaltAuth",
		"Extensions.HMACSecret.SaltEnc",
	}, diagnostic.RedactedFields)
}

func TestRenderDiagnosticPreservesUnknownFields(t *testing.T) {
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
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, "engineers.example")
	assert.Contains(t, diagnostic.Notation, "unknown-field-canary")
	assert.Contains(t, diagnostic.Notation, "/subCommand/ 2:")
	assert.Contains(t, diagnostic.Notation, "/rpId/ 10:")
}

func TestRenderDiagnosticPreservesNestedUnknownFieldsAndRedactsKnownWrongType(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		2: uint64(protocol.ClientPINSubCommandGetPINRetries),
		6: map[string]any{"unexpected": "secret-canary"},
		99: map[uint64]any{
			1: "nested-unknown-canary",
		},
	})
	require.NoError(t, err)

	diagnostic, subCommand := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	require.Empty(t, diagnostic.Error)
	assert.Equal(t, uint64(protocol.ClientPINSubCommandGetPINRetries), subCommand)
	assert.Contains(t, diagnostic.Notation, "nested-unknown-canary")
	assert.Contains(t, diagnostic.Notation, diagnosticRedacted)
	assert.NotContains(t, diagnostic.Notation, "secret-canary")
	assert.Equal(t, []string{"PinHashEnc"}, diagnostic.RedactedFields)
}

func TestRenderDiagnosticUsesExplicitAndDerivedFieldNames(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		1: "none",
		2: []byte("auth-data-canary"),
		3: map[string]any{"alg": -7},
		4: true,
	})
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorMakeCredentialResponse]()},
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, "/fmt/ 1:")
	assert.Contains(t, diagnostic.Notation, "/authData/ 2:")
	assert.Contains(t, diagnostic.Notation, "/attStmt/ 3:")
	assert.Contains(t, diagnostic.Notation, "/epAtt/ 4:")
	assert.NotContains(t, diagnostic.Notation, "auth-data-canary")
	assert.Equal(t, []string{"AuthDataRaw"}, diagnostic.RedactedFields)
}

func TestRenderDiagnosticUsesProtocolSpellingOverrides(t *testing.T) {
	tests := []struct {
		name   string
		key    uint64
		schema reflect.Type
		want   string
	}{
		{"rpId", 1, reflect.TypeFor[protocol.AuthenticatorGetAssertionRequest](), "/rpId/ 1:"},
		{"rpIDHash", 4, reflect.TypeFor[protocol.AuthenticatorCredentialManagementResponse](), "/rpIDHash/ 4:"},
		{"templateId", 4, reflect.TypeFor[protocol.AuthenticatorBioEnrollmentResponse](), "/templateId/ 4:"},
	}
	configured := options.NewOptions()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := configured.EncMode.Marshal(map[uint64]any{test.key: "value"})
			require.NoError(t, err)
			diagnostic, _ := renderDiagnostic(
				configured.DecMode,
				configured.EncMode,
				raw,
				diagnosticMessageSchema{typeInfo: test.schema},
			)
			require.Empty(t, diagnostic.Error)
			assert.Contains(t, diagnostic.Notation, test.want)
		})
	}
}

func TestRenderDiagnosticUsesConfigSubCommandParamsSchema(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		1: uint64(protocol.ConfigSubCommandSetMinPINLength),
		2: map[uint64]any{
			1:  8,
			4:  true,
			99: "vendor-param-canary",
		},
	})
	require.NoError(t, err)
	requestSchema, _ := exchangeSchemas(protocol.AuthenticatorConfig)

	diagnostic, subCommand := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		requestSchema,
	)

	require.Empty(t, diagnostic.Error)
	assert.Equal(t, uint64(protocol.ConfigSubCommandSetMinPINLength), subCommand)
	assert.Contains(t, diagnostic.Notation, "/subCommandParams/ 2:")
	assert.Contains(t, diagnostic.Notation, "/newMinPINLength/ 1:")
	assert.Contains(t, diagnostic.Notation, "/pinComplexityPolicy/ 4:")
	assert.Contains(t, diagnostic.Notation, "vendor-param-canary")
}

func TestRenderDiagnosticRedactsKnownUnsignedExtensionOutputFields(t *testing.T) {
	secret := []byte("large-blob-canary")
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		8: map[string]any{
			"largeBlob": map[string]any{
				"written":      true,
				"blob":         secret,
				"originalSize": 42,
			},
			"vendor.example": map[string]any{
				"debug": "vendor-canary",
			},
		},
	})
	require.NoError(t, err)
	_, responseSchema := exchangeSchemas(protocol.AuthenticatorGetAssertion)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		responseSchema,
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, "/unsignedExtensionOutputs/ 8:")
	assert.Contains(t, diagnostic.Notation, `"written": true`)
	assert.Contains(t, diagnostic.Notation, `"blob": h'/[REDACTED]/'`)
	assert.Contains(t, diagnostic.Notation, `"originalSize": 42`)
	assert.Contains(t, diagnostic.Notation, "vendor-canary")
	assert.NotContains(t, diagnostic.Notation, hex.EncodeToString(secret))
	assert.Equal(t, []string{"UnsignedExtensionOutputs.Blob"}, diagnostic.RedactedFields)
}

func TestRenderDiagnosticShowsSafeMakeCredentialUnsignedExtensionOutputs(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		6: map[string]any{
			"largeBlob": map[string]any{
				"supported": true,
			},
		},
	})
	require.NoError(t, err)
	_, responseSchema := exchangeSchemas(protocol.AuthenticatorMakeCredential)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		responseSchema,
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, "/unsignedExtensionOutputs/ 6:")
	assert.Contains(t, diagnostic.Notation, `"supported": true`)
	assert.NotContains(t, diagnostic.Notation, diagnosticRedacted)
	assert.Empty(t, diagnostic.RedactedFields)
}

func TestRenderDiagnosticWithoutSchemaShowsRawCBOR(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		99: []any{"vendor", map[string]any{"future": true}},
	})
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{},
	)

	require.Empty(t, diagnostic.Error)
	assert.Contains(t, diagnostic.Notation, "vendor")
	assert.Contains(t, diagnostic.Notation, "future")
}

func TestRenderDiagnosticHasDeterministicMapOrder(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		10: "example.com",
		2:  uint64(protocol.ClientPINSubCommandGetPINRetries),
		1:  uint64(protocol.PinUvAuthProtocolOne),
	})
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	require.Empty(t, diagnostic.Error)
	assert.Equal(t,
		`{
  /pinUvAuthProtocol/ 1: 1,
  /subCommand/ 2: 1,
  /rpId/ 10: "example.com"
}`,
		diagnostic.Notation,
	)
}

func TestRenderDiagnosticPrettyPrintsNestedCollections(t *testing.T) {
	configured := options.NewOptions()
	raw, err := configured.EncMode.Marshal(map[uint64]any{
		99: []any{
			map[string]any{
				"empty": []any{},
				"value": true,
			},
		},
	})
	require.NoError(t, err)

	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		raw,
		diagnosticMessageSchema{},
	)

	require.Empty(t, diagnostic.Error)
	assert.Equal(t,
		`{
  99: [
    {
      "empty": [],
      "value": true
    }
  ]
}`,
		diagnostic.Notation,
	)
}

func TestRenderDiagnosticRejectsMalformedCBORWithoutNotation(t *testing.T) {
	configured := options.NewOptions()
	diagnostic, _ := renderDiagnostic(
		configured.DecMode,
		configured.EncMode,
		[]byte{0xa1, 0x06},
		diagnosticMessageSchema{typeInfo: reflect.TypeFor[protocol.AuthenticatorClientPINRequest]()},
	)

	assert.NotEmpty(t, diagnostic.Error)
	assert.Empty(t, diagnostic.Notation)
}

func TestLowerCamel(t *testing.T) {
	assert.Equal(t, "clientDataHash", lowerCamel("ClientDataHash"))
	assert.Equal(t, "pinComplexityPolicy", lowerCamel("PINComplexityPolicy"))
	assert.Equal(t, "aaguid", lowerCamel("AAGUID"))
	assert.Equal(t, "maxRPIDsForSetMinPINLength", lowerCamel("MaxRPIDsForSetMinPINLength"))
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
	configured := options.NewOptions()
	requestBody, err := configured.EncMode.Marshal(request)
	require.NoError(t, err)
	responseBody, err := configured.EncMode.Marshal(map[uint64]any{
		2:  responseSecret,
		99: "response-unknown-canary",
	})
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
	assert.Contains(t, event.Response.Notation, "response-unknown-canary")
	assert.NotContains(t, event.Response.Notation, hex.EncodeToString(responseSecret))
	assert.Equal(t, []string{"PinUvAuthToken"}, event.Response.RedactedFields)
}
