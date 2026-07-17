package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/client"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/credential"
	ctapcrypto "github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/crypto/protocolone"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type prfRoundTripTransport struct {
	t          *testing.T
	privateKey *ecdh.PrivateKey
	result     []byte
	salts      []byte
	requests   [][]byte
}

func newPRFRoundTripTransport(t *testing.T, result []byte) *prfRoundTripTransport {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &prfRoundTripTransport{t: t, privateKey: privateKey, result: result}
}

func (t *prfRoundTripTransport) Close() error { return nil }

func (t *prfRoundTripTransport) CBOR(
	_ context.Context,
	data []byte,
) (ctaptransport.CBORResponse, error) {
	t.t.Helper()
	require.NotEmpty(t.t, data)
	t.requests = append(t.requests, bytes.Clone(data))

	switch protocol.Command(data[0]) {
	case protocol.AuthenticatorClientPIN:
		keyAgreement, err := cose.KeyFromP256PublicKey(t.privateKey.PublicKey())
		require.NoError(t.t, err)
		return ctaptransport.CBORResponse{Data: encodeCBOR(t.t, &protocol.AuthenticatorClientPINResponse{
			KeyAgreement: keyAgreement,
		})}, nil

	case protocol.AuthenticatorMakeCredential:
		var request protocol.AuthenticatorMakeCredentialRequest
		require.NoError(t.t, cbor.Unmarshal(data[1:], &request))
		require.NotNil(t.t, request.Extensions.CreateHMACSecretMCInput)
		encryptedResult := t.encryptResult(request.Extensions.CreateHMACSecretMCInput.HMACSecret)

		authData := minimalAuthData()
		authData[32] = byte(protocol.AuthDataFlagUserPresent |
			protocol.AuthDataFlagUserVerified |
			protocol.AuthDataFlagExtensionDataIncluded)
		authData = append(authData, encodeCBOR(t.t, protocol.CreateExtensionOutputs{
			CreateHMACSecretOutput:   &protocol.CreateHMACSecretOutput{HMACSecret: true},
			CreateHMACSecretMCOutput: &protocol.CreateHMACSecretMCOutput{HMACSecret: encryptedResult},
		})...)

		return ctaptransport.CBORResponse{Data: encodeCBOR(t.t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: authData,
		})}, nil

	case protocol.AuthenticatorGetAssertion:
		var request protocol.AuthenticatorGetAssertionRequest
		require.NoError(t.t, cbor.Unmarshal(data[1:], &request))
		require.NotNil(t.t, request.Extensions.GetHMACSecretInput)
		encryptedResult := t.encryptResult(request.Extensions.GetHMACSecretInput.HMACSecret)

		authData := minimalAuthData()
		authData[32] = byte(protocol.AuthDataFlagUserPresent |
			protocol.AuthDataFlagUserVerified |
			protocol.AuthDataFlagExtensionDataIncluded)
		authData = append(authData, encodeCBOR(t.t, protocol.GetExtensionOutputs{
			GetHMACSecretOutput: &protocol.GetHMACSecretOutput{HMACSecret: encryptedResult},
		})...)

		return ctaptransport.CBORResponse{Data: encodeCBOR(t.t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: authData,
			Signature:   []byte("signature"),
		})}, nil
	default:
		require.FailNow(t.t, "unexpected CTAP command", "command: %v", data[0])
		return ctaptransport.CBORResponse{}, nil
	}
}

func (t *prfRoundTripTransport) encryptResult(input protocol.HMACSecret) []byte {
	t.t.Helper()

	platformPublicKey, err := input.KeyAgreement.P256PublicKey()
	require.NoError(t.t, err)
	z, err := t.privateKey.ECDH(platformPublicKey)
	require.NoError(t.t, err)
	sharedSecret := protocolone.KDF(z)
	t.salts, err = protocolone.Decrypt(sharedSecret, input.SaltEnc)
	require.NoError(t.t, err)
	require.Equal(t.t, ctapcrypto.Authenticate(
		protocol.PinUvAuthProtocolOne,
		sharedSecret,
		input.SaltEnc,
	), input.SaltAuth)

	encryptedResult, err := protocolone.Encrypt(sharedSecret, t.result)
	require.NoError(t.t, err)
	return encryptedResult
}

func newPRFRoundTripDevice(
	t *testing.T,
	transport *prfRoundTripTransport,
	info protocol.AuthenticatorGetInfoResponse,
) *Device {
	t.Helper()

	ctapClient, err := client.NewClient(options.WithTransport(transport))
	require.NoError(t, err)
	d := &Device{transport: transport, ctapClient: ctapClient}
	d.cacheInfo(info)
	return d
}

func TestMakeCredentialPRFReportsCapabilityWithoutRequiringEvaluation(t *testing.T) {
	tests := []struct {
		name string
		eval webauthn.AuthenticationExtensionsPRFValues
	}{
		{name: "without eval"},
		{name: "eval without hmac-secret-mc", eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
				Format: attestation.AttestationStatementFormatIdentifierPacked,
				AuthDataRaw: authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
					CreateHMACSecretOutput: &protocol.CreateHMACSecretOutput{HMACSecret: true},
				}),
			})
			fake := testhid.NewCBORDevice(t, testCID, response)
			d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
				Options: map[protocol.Option]bool{
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			})

			resp, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
				PRFInputs: &webauthn.PRFInputs{
					PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: tt.eval},
				},
			})
			require.NoError(t, err)
			require.NotNil(t, resp.ExtensionOutputs.CreatePRFOutputs)
			assert.True(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Enabled)
			assert.True(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Results.IsZero())
			assert.Nil(t, resp.ExtensionOutputs.CreateHMACSecretOutputs)

			require.Len(t, fake.Requests(t), 1)
			_, requestCBOR := fake.FirstCTAPPayload(t)
			var request protocol.AuthenticatorMakeCredentialRequest
			require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
			require.NotNil(t, request.Extensions.CreateHMACSecretInput)
			assert.True(t, request.Extensions.CreateHMACSecretInput.HMACSecret)
			assert.Nil(t, request.Extensions.CreateHMACSecretMCInput)
		})
	}
}

func TestMakeCredentialPRFWithoutHMACSecretReturnsDisabledOutput(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{protocol.OptionMakeCredentialUvNotRequired: true},
	})

	resp, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
		PRFInputs: &webauthn.PRFInputs{
			PRF: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreatePRFOutputs)
	assert.False(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Enabled)

	_, requestCBOR := fake.FirstCTAPPayload(t)
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	assert.Nil(t, request.Extensions.CreateHMACSecretInput)
	assert.Nil(t, request.Extensions.CreateHMACSecretMCInput)
}

func TestMakeCredentialPRFEvaluatesAtCreationTimeWithExplicitUserVerification(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{
		First:  []byte("first"),
		Second: []byte{},
	}
	result := bytes.Repeat([]byte{0xa5}, 64)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	resp, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreatePRFOutputs)
	assert.Nil(t, resp.ExtensionOutputs.CreateHMACSecretMCOutputs)
	assert.True(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Enabled)
	assert.Equal(t, result[:32], resp.ExtensionOutputs.CreatePRFOutputs.PRF.Results.First)
	assert.Equal(t, result[32:], resp.ExtensionOutputs.CreatePRFOutputs.PRF.Results.Second)
	assert.Equal(t, prfSalts(values), transport.salts)

	require.Len(t, transport.requests, 2)
	require.Equal(t, byte(protocol.AuthenticatorMakeCredential), transport.requests[1][0])
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(transport.requests[1][1:], &request))
	assert.True(t, request.Options[protocol.OptionUserVerification])
	require.NotNil(t, request.Extensions.CreateHMACSecretInput)
	assert.True(t, request.Extensions.CreateHMACSecretInput.HMACSecret)
	require.NotNil(t, request.Extensions.CreateHMACSecretMCInput)
}

func TestMakeCredentialRawHMACSecretMCReturnsRawOutput(t *testing.T) {
	salt1 := bytes.Repeat([]byte{0x11}, 32)
	salt2 := bytes.Repeat([]byte{0x22}, 32)
	result := bytes.Repeat([]byte{0x5a}, 64)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	resp, err := makeCredentialWithExtensions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{
					Salt1: salt1,
					Salt2: salt2,
				},
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreateHMACSecretMCOutputs)
	assert.Nil(t, resp.ExtensionOutputs.CreatePRFOutputs)
	assert.Equal(t, result[:32], resp.ExtensionOutputs.CreateHMACSecretMCOutputs.HMACGetSecret.Output1)
	assert.Equal(t, result[32:], resp.ExtensionOutputs.CreateHMACSecretMCOutputs.HMACGetSecret.Output2)
	assert.Equal(t, append(bytes.Clone(salt1), salt2...), transport.salts)
}

func TestMakeCredentialPRFEvaluatesAtCreationTimeWithAlwaysUV(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	result := bytes.Repeat([]byte{0xa5}, 32)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_1},
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
			protocol.OptionAlwaysUv:         true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	resp, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		callerOptions,
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreatePRFOutputs)
	assert.True(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Enabled)
	assert.Equal(t, result, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Results.First)
	assert.Equal(t, prfSalts(values), transport.salts)
	assert.False(t, callerOptions[protocol.OptionUserVerification])

	require.Len(t, transport.requests, 2)
	require.Equal(t, byte(protocol.AuthenticatorMakeCredential), transport.requests[1][0])
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(transport.requests[1][1:], &request))
	assert.False(t, request.Options[protocol.OptionUserVerification])
	require.NotNil(t, request.Extensions.CreateHMACSecretMCInput)
}

func TestMakeCredentialPRFSkipsCreationTimeEvaluationWithoutExplicitUserVerification(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format: attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
			CreateHMACSecretOutput: &protocol.CreateHMACSecretOutput{HMACSecret: true},
		}),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	resp, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		callerOptions,
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreatePRFOutputs)
	assert.True(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Enabled)
	assert.True(t, resp.ExtensionOutputs.CreatePRFOutputs.PRF.Results.IsZero())
	assert.False(t, callerOptions[protocol.OptionUserVerification])

	_, requestCBOR := fake.FirstCTAPPayload(t)
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	assert.False(t, request.Options[protocol.OptionUserVerification])
	assert.Nil(t, request.Extensions.CreateHMACSecretMCInput)
}

func TestMakeCredentialPRFRejectsResultsWhenHMACSecretWasNotEnabled(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	authData := authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
		CreateHMACSecretOutput:   &protocol.CreateHMACSecretOutput{HMACSecret: false},
		CreateHMACSecretMCOutput: &protocol.CreateHMACSecretMCOutput{HMACSecret: make([]byte, 32)},
	})
	authData[32] |= byte(protocol.AuthDataFlagUserVerified)
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: authData,
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := makeCredentialWithExtensionsAndOptions(
		d,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	)
	require.ErrorIs(t, err, ErrSpecViolation)
}

func TestGetAssertionPRFInitializesEmptyOutputWhenNoEvaluationIsSent(t *testing.T) {
	tests := []struct {
		name       string
		extensions []extension.ExtensionIdentifier
		prf        webauthn.AuthenticationExtensionsPRFInputs
	}{
		{name: "empty input"},
		{
			name: "unsupported authenticator",
			prf: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
				AuthDataRaw: minimalAuthData(),
				Signature:   []byte("signature"),
			})
			fake := testhid.NewCBORDevice(t, testCID, response)
			d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{Extensions: tt.extensions})

			var assertions []protocol.AuthenticatorGetAssertionResponse
			for assertion, err := range d.GetAssertion(
				testContext,
				nil,
				"example.com",
				[]byte("client-data"),
				nil,
				&webauthn.GetAuthenticationExtensionsClientInputs{
					PRFInputs: &webauthn.PRFInputs{PRF: tt.prf},
				},
				nil,
			) {
				require.NoError(t, err)
				assertions = append(assertions, assertion)
			}
			require.Len(t, assertions, 1)
			require.NotNil(t, assertions[0].ExtensionOutputs.GetPRFOutputs)
			assert.True(t, assertions[0].ExtensionOutputs.GetPRFOutputs.PRF.Results.IsZero())

			_, requestCBOR := fake.FirstCTAPPayload(t)
			var request protocol.AuthenticatorGetAssertionRequest
			require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
			assert.Nil(t, request.Extensions.GetHMACSecretInput)
		})
	}
}

func TestGetAssertionPRFEvaluatesAndReturnsDecryptedResult(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	result := bytes.Repeat([]byte{0x5a}, 32)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	var assertions []protocol.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	) {
		require.NoError(t, err)
		assertions = append(assertions, assertion)
	}

	require.Len(t, assertions, 1)
	require.NotNil(t, assertions[0].ExtensionOutputs.GetPRFOutputs)
	assert.Equal(t, result, assertions[0].ExtensionOutputs.GetPRFOutputs.PRF.Results.First)
	assert.Nil(t, assertions[0].ExtensionOutputs.GetPRFOutputs.PRF.Results.Second)
	assert.Equal(t, prfSalts(values), transport.salts)
}

func TestGetAssertionPRFEvaluatesWithAlwaysUV(t *testing.T) {
	values := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	result := bytes.Repeat([]byte{0x5a}, 32)
	transport := newPRFRoundTripTransport(t, result)
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
			protocol.OptionAlwaysUv:         true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	var assertions []protocol.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{Eval: values},
			},
		},
		callerOptions,
	) {
		require.NoError(t, err)
		assertions = append(assertions, assertion)
	}

	require.Len(t, assertions, 1)
	require.NotNil(t, assertions[0].ExtensionOutputs.GetPRFOutputs)
	assert.Equal(t, result, assertions[0].ExtensionOutputs.GetPRFOutputs.PRF.Results.First)
	assert.Equal(t, prfSalts(values), transport.salts)
	assert.False(t, callerOptions[protocol.OptionUserVerification])

	require.Len(t, transport.requests, 2)
	require.Equal(t, byte(protocol.AuthenticatorGetAssertion), transport.requests[1][0])
	var request protocol.AuthenticatorGetAssertionRequest
	require.NoError(t, cbor.Unmarshal(transport.requests[1][1:], &request))
	assert.False(t, request.Options[protocol.OptionUserVerification])
	require.NotNil(t, request.Extensions.GetHMACSecretInput)
}

func TestGetAssertionPRFRejectsResultCountMismatch(t *testing.T) {
	transport := newPRFRoundTripTransport(t, bytes.Repeat([]byte{0x5a}, 64))
	d := newPRFRoundTripDevice(t, transport, protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	) {
		gotErr = err
	}
	require.ErrorIs(t, gotErr, ErrSpecViolation)
}

func TestGetAssertionPRFRequiresExplicitUserVerification(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})
	callerOptions := map[protocol.Option]bool{protocol.OptionUserVerification: false}

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		callerOptions,
	) {
		gotErr = err
	}
	require.ErrorIs(t, gotErr, ErrBuiltInUVRequired)
	assert.False(t, callerOptions[protocol.OptionUserVerification])
	assert.Empty(t, fake.Writes())
}

func TestPRFResultsRequireUserVerification(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: authDataWithExtensionOutputs(t, protocol.GetExtensionOutputs{
			GetHMACSecretOutput: &protocol.GetHMACSecretOutput{HMACSecret: make([]byte, 32)},
		}),
		Signature: []byte("signature"),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, assertion)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
				},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
	) {
		gotErr = err
	}
	require.ErrorIs(t, gotErr, ErrSpecViolation)
}

func TestPRFPreflightFailuresPerformNoAuthenticatorIO(t *testing.T) {
	t.Run("registration rejects even an empty evalByCredential", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{
				PRF: webauthn.AuthenticationExtensionsPRFInputs{
					EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{},
				},
			},
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("authentication rejects user presence false", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		})

		var gotErr error
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				PRFInputs: &webauthn.PRFInputs{
					PRF: webauthn.AuthenticationExtensionsPRFInputs{
						Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
					},
				},
			},
			map[protocol.Option]bool{protocol.OptionUserPresence: false},
		) {
			gotErr = err
		}
		require.ErrorIs(t, gotErr, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("authentication requires a PIN UV auth token on a PIN-only device", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
			Options: map[protocol.Option]bool{
				protocol.OptionClientPIN: true,
			},
		})

		var gotErr error
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				PRFInputs: &webauthn.PRFInputs{
					PRF: webauthn.AuthenticationExtensionsPRFInputs{
						Eval: webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")},
					},
				},
			},
			nil,
		) {
			gotErr = err
		}
		require.ErrorIs(t, gotErr, ErrPinUvAuthTokenRequired)
		assert.Empty(t, fake.Writes())
	})

	t.Run("hmac-secret-mc without hmac-secret is an authenticator violation", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecretMC},
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthn.PRFInputs{},
		})
		require.ErrorIs(t, err, ErrSpecViolation)
		assert.Empty(t, fake.Writes())
	})
}

func TestValidateGetPRFInputs(t *testing.T) {
	credentialOne := credential.PublicKeyCredentialDescriptor{ID: []byte("one")}
	credentialTwo := credential.PublicKeyCredentialDescriptor{ID: []byte("two")}
	idOne := base64.RawURLEncoding.EncodeToString(credentialOne.ID)
	idTwo := base64.RawURLEncoding.EncodeToString(credentialTwo.ID)
	first := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	second := webauthn.AuthenticationExtensionsPRFValues{First: []byte("second")}

	t.Run("empty evalByCredential is allowed without allowList", func(t *testing.T) {
		err := validateGetPRFInputs(webauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{},
		}, nil)
		require.NoError(t, err)
	})

	t.Run("present empty first is valid", func(t *testing.T) {
		err := validateGetPRFInputs(webauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
				idOne: {First: []byte{}},
			},
		}, []credential.PublicKeyCredentialDescriptor{credentialOne})
		require.NoError(t, err)
	})

	for _, tt := range []struct {
		name   string
		inputs webauthn.AuthenticationExtensionsPRFInputs
		allow  []credential.PublicKeyCredentialDescriptor
		want   error
	}{
		{
			name: "eval second without first",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				Eval: webauthn.AuthenticationExtensionsPRFValues{Second: []byte("second")},
			},
			want: SyntaxError,
		},
		{
			name: "non-empty evalByCredential without allowList",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne: first},
			},
			want: ErrNotSupported,
		},
		{
			name: "empty credential ID",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{"": first},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
		{
			name: "padded credential ID",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne + "=": first},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
		{
			name: "credential ID outside allowList",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idTwo: second},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
		{
			name: "missing required first",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne: {}},
			},
			allow: []credential.PublicKeyCredentialDescriptor{credentialOne},
			want:  SyntaxError,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGetPRFInputs(tt.inputs, tt.allow)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestSelectCTAPGetPRFEvaluation(t *testing.T) {
	credentialOne := credential.PublicKeyCredentialDescriptor{ID: []byte("one")}
	credentialTwo := credential.PublicKeyCredentialDescriptor{ID: []byte("two")}
	idOne := base64.RawURLEncoding.EncodeToString(credentialOne.ID)
	idTwo := base64.RawURLEncoding.EncodeToString(credentialTwo.ID)
	first := webauthn.AuthenticationExtensionsPRFValues{First: []byte("first")}
	second := webauthn.AuthenticationExtensionsPRFValues{First: []byte("second")}

	t.Run("single credential override", func(t *testing.T) {
		got, err := selectCTAPGetPRFEvaluation(webauthn.AuthenticationExtensionsPRFInputs{
			Eval:             second,
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{idOne: first},
		}, []credential.PublicKeyCredentialDescriptor{credentialOne})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, first, *got)
	})

	t.Run("uniform multi-credential inputs are safe", func(t *testing.T) {
		got, err := selectCTAPGetPRFEvaluation(webauthn.AuthenticationExtensionsPRFInputs{
			EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
				idOne: first,
				idTwo: first,
			},
		}, []credential.PublicKeyCredentialDescriptor{credentialOne, credentialTwo})
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, first, *got)
	})

	for _, tt := range []struct {
		name   string
		inputs webauthn.AuthenticationExtensionsPRFInputs
	}{
		{
			name: "different credential inputs require separate CTAP requests",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
					idOne: first,
					idTwo: second,
				},
			},
		},
		{
			name: "absent and present empty second inputs differ",
			inputs: webauthn.AuthenticationExtensionsPRFInputs{
				EvalByCredential: map[string]webauthn.AuthenticationExtensionsPRFValues{
					idOne: first,
					idTwo: {First: []byte("first"), Second: []byte{}},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := selectCTAPGetPRFEvaluation(
				tt.inputs,
				[]credential.PublicKeyCredentialDescriptor{credentialOne, credentialTwo},
			)
			require.ErrorIs(t, err, ErrNotSupported)
		})
	}
}
