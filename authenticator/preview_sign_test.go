package authenticator

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
)

func previewSignCredentialKey(marker byte) cose.Key {
	return cose.Key{
		cose.KeyParameterKty:    cose.KeyTypeEC2,
		cose.KeyParameterAlg:    cose.AlgorithmES256,
		cose.EC2KeyParameterCrv: cose.EllipticCurveP256,
		cose.EC2KeyParameterX:   append([]byte{marker}, make([]byte, 31)...),
		cose.EC2KeyParameterY:   append([]byte{marker + 1}, make([]byte, 31)...),
	}
}

func previewSignAuthData(
	t *testing.T,
	flags protocol.AuthDataFlag,
	aaguid uuid.UUID,
	credentialID []byte,
	publicKey cose.Key,
	extensions protocol.CreateExtensionOutputs,
) []byte {
	return previewSignAuthDataWithSignCount(t, flags, 0, aaguid, credentialID, publicKey, extensions)
}

func previewSignAuthDataWithSignCount(
	t *testing.T,
	flags protocol.AuthDataFlag,
	signCount uint32,
	aaguid uuid.UUID,
	credentialID []byte,
	publicKey cose.Key,
	extensions protocol.CreateExtensionOutputs,
) []byte {
	t.Helper()

	data := make([]byte, 37)
	data[32] = byte(flags)
	binary.BigEndian.PutUint32(data[33:37], signCount)
	if flags.AttestedCredentialDataIncluded() {
		data = append(data, aaguid[:]...)
		credentialIDLength := make([]byte, 2)
		binary.BigEndian.PutUint16(credentialIDLength, uint16(len(credentialID)))
		data = append(data, credentialIDLength...)
		data = append(data, credentialID...)
		data = append(data, encodeCBOR(t, publicKey)...)
	}
	if flags.ExtensionDataIncluded() {
		data = append(data, encodeCBOR(t, extensions)...)
	}

	return data
}

func TestMakeCredentialPreviewSign(t *testing.T) {
	algorithm := cose.AlgorithmESP256SplitARKGPlaceholder
	flags := protocol.AuthDataFlagUserPresent
	aaguid := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	authDataFlags := protocol.AuthDataFlagUserPresent |
		protocol.AuthDataFlagAttestedCredentialDataIncluded |
		protocol.AuthDataFlagExtensionDataIncluded
	outerAuthData := previewSignAuthData(
		t,
		authDataFlags,
		aaguid,
		[]byte("credential-id"),
		previewSignCredentialKey(1),
		protocol.CreateExtensionOutputs{
			CreatePreviewSignOutput: protocol.CreatePreviewSignOutput{
				PreviewSign: &protocol.PreviewSignOutput{Algorithm: &algorithm},
			},
		},
	)
	signingKeyHandle := []byte("signing-key-handle")
	innerAuthData := previewSignAuthData(
		t,
		authDataFlags,
		aaguid,
		signingKeyHandle,
		previewSignCredentialKey(3),
		protocol.CreateExtensionOutputs{
			CreatePreviewSignOutput: protocol.CreatePreviewSignOutput{
				PreviewSign: &protocol.PreviewSignOutput{Flags: &flags},
			},
		},
	)
	statement := map[string]any{"alg": cose.AlgorithmES256, "sig": []byte{1}}
	innerAttestationObject := encodeCBOR(t, map[uint64]any{
		1: attestation.AttestationStatementFormatIdentifierNone,
		2: innerAuthData,
		3: map[string]any{},
	})
	response := encodeCBOR(t, protocol.AuthenticatorMakeCredentialResponse{
		Format:               attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw:          outerAuthData,
		AttestationStatement: statement,
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierPreviewSign: protocol.PreviewSignUnsignedOutput{
				AttestationObject: innerAttestationObject,
			},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierPreviewSign},
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	result, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
		PreviewSignInputs: &webauthn.PreviewSignInputs{
			PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
				GenerateKey: &webauthn.PreviewSignGenerateKeyInputs{
					Algorithms: []cose.Algorithm{algorithm},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result.ExtensionOutputs.PreviewSignOutputs)
	generatedKey := result.ExtensionOutputs.PreviewSign.GeneratedKey
	require.NotNil(t, generatedKey)
	assert.Equal(t, signingKeyHandle, generatedKey.KeyHandle)
	assert.Equal(t, algorithm, generatedKey.Algorithm)

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)
	wantPublicKey, err := encMode.Marshal(previewSignCredentialKey(3))
	require.NoError(t, err)
	assert.Equal(t, wantPublicKey, generatedKey.PublicKey)
	attestationObject, err := attestation.ParseObject(generatedKey.AttestationObject)
	require.NoError(t, err)
	assert.Equal(t, attestation.AttestationStatementFormatIdentifierNone, attestationObject.Format)
	assert.Equal(t, innerAuthData, attestationObject.AuthData)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	require.NotNil(t, request.Extensions.PreviewSign.Flags)
	assert.Equal(t, protocol.AuthDataFlagUserPresent, *request.Extensions.PreviewSign.Flags)
	assert.Equal(t, []cose.Algorithm{algorithm}, request.Extensions.PreviewSign.Algorithms)
}

func TestGetAssertionPreviewSign(t *testing.T) {
	signature := []byte("preview-signature")
	authData := minimalAuthData()
	authData[32] = byte(protocol.AuthDataFlagUserPresent | protocol.AuthDataFlagExtensionDataIncluded)
	authData = append(authData, encodeCBOR(t, protocol.GetExtensionOutputs{
		GetPreviewSignOutput: protocol.GetPreviewSignOutput{
			PreviewSign: &protocol.PreviewSignOutput{Signature: signature},
		},
	})...)
	response := encodeCBOR(t, protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: authData,
		Signature:   []byte("assertion-signature"),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierPreviewSign},
	})
	credentialID := []byte("credential-id")
	keyHandle := []byte{}
	toBeSigned := []byte{}
	additionalArguments := encodeCBOR(t, map[int]any{3: cose.AlgorithmESP256SplitARKGPlaceholder})
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   credentialID,
	}}
	extInputs := &webauthn.GetAuthenticationExtensionsClientInputs{
		PreviewSignInputs: &webauthn.PreviewSignInputs{
			PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
				SignByCredential: map[string]webauthn.PreviewSignSignInputs{
					base64.RawURLEncoding.EncodeToString(credentialID): {
						KeyHandle:           keyHandle,
						ToBeSigned:          toBeSigned,
						AdditionalArguments: additionalArguments,
					},
				},
			},
		},
	}

	var result protocol.AuthenticatorGetAssertionResponse
	var gotErr error
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		allowList,
		extInputs,
		nil,
	) {
		result, gotErr = assertion, err
	}
	require.NoError(t, gotErr)
	require.NotNil(t, result.ExtensionOutputs.PreviewSignOutputs)
	assert.Equal(t, signature, result.ExtensionOutputs.PreviewSign.Signature)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
	var request protocol.AuthenticatorGetAssertionRequest
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	assert.NotNil(t, request.Extensions.PreviewSign.KeyHandle)
	assert.NotNil(t, request.Extensions.PreviewSign.ToBeSigned)
	assert.Empty(t, request.Extensions.PreviewSign.KeyHandle)
	assert.Empty(t, request.Extensions.PreviewSign.ToBeSigned)
	assert.Equal(t, additionalArguments, request.Extensions.PreviewSign.AdditionalArguments)
}

func TestPreviewSignValidatesClientInputsBeforeAuthenticatorIO(t *testing.T) {
	t.Run("MakeCredential maps user verification to signing flags", func(t *testing.T) {
		input, err := validateCreatePreviewSign(
			protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierPreviewSign},
			},
			nil,
			&webauthn.PreviewSignInputs{
				PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
					GenerateKey: &webauthn.PreviewSignGenerateKeyInputs{
						Algorithms: []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder},
					},
				},
			},
			map[protocol.Option]bool{protocol.OptionUserVerification: true},
		)
		require.NoError(t, err)
		require.NotNil(t, input.Flags)
		assert.Equal(
			t,
			protocol.AuthDataFlagUserPresent|protocol.AuthDataFlagUserVerified,
			*input.Flags,
		)
	})

	t.Run("MakeCredential requires advertised support", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{protocol.OptionMakeCredentialUvNotRequired: true},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PreviewSignInputs: &webauthn.PreviewSignInputs{
				PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
					GenerateKey: &webauthn.PreviewSignGenerateKeyInputs{Algorithms: []cose.Algorithm{cose.AlgorithmES256}},
				},
			},
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("GetAssertion permits identical inputs for multiple allowed credentials", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierPreviewSign},
		}
		allowList := []credential.PublicKeyCredentialDescriptor{
			{Type: credential.PublicKeyCredentialTypePublicKey, ID: []byte{1}},
			{Type: credential.PublicKeyCredentialTypePublicKey, ID: []byte{2}},
		}
		inputs := make(map[string]webauthn.PreviewSignSignInputs, len(allowList))
		for _, descriptor := range allowList {
			inputs[base64.RawURLEncoding.EncodeToString(descriptor.ID)] = webauthn.PreviewSignSignInputs{
				KeyHandle:  []byte{},
				ToBeSigned: []byte{},
			}
		}

		input, err := validateGetPreviewSign(
			info,
			allowList,
			&webauthn.PreviewSignInputs{
				PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{SignByCredential: inputs},
			},
		)
		require.NoError(t, err)
		assert.NotNil(t, input)

		secondID := base64.RawURLEncoding.EncodeToString(allowList[1].ID)
		second := inputs[secondID]
		second.ToBeSigned = []byte{1}
		inputs[secondID] = second
		_, err = validateGetPreviewSign(
			info,
			allowList,
			&webauthn.PreviewSignInputs{
				PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{SignByCredential: inputs},
			},
		)
		require.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("GetAssertion validates COSE signing arguments", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierPreviewSign},
		}
		credentialID := []byte{1}
		allowList := []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   credentialID,
		}}
		validate := func(arguments []byte) error {
			_, err := validateGetPreviewSign(
				info,
				allowList,
				&webauthn.PreviewSignInputs{
					PreviewSign: webauthn.AuthenticationExtensionsPreviewSignInputs{
						SignByCredential: map[string]webauthn.PreviewSignSignInputs{
							base64.RawURLEncoding.EncodeToString(credentialID): {
								KeyHandle:           []byte{},
								ToBeSigned:          []byte{},
								AdditionalArguments: arguments,
							},
						},
					},
				},
			)
			return err
		}

		require.NoError(t, validate(encodeCBOR(t, map[any]any{
			3:     cose.AlgorithmESP256SplitARKGPlaceholder,
			"kid": []byte{1},
		})))
		require.ErrorIs(t, validate(encodeCBOR(t, map[string]any{"kid": []byte{1}})), SyntaxError)
		require.ErrorIs(t, validate(encodeCBOR(t, map[int]any{3: true})), SyntaxError)
		require.ErrorIs(t, validate(encodeCBOR(t, map[any]any{3: -1, true: 1})), SyntaxError)
		require.ErrorIs(t, validate([]byte{0xa2, 0x03, 0x26, 0x03, 0x27}), SyntaxError)
	})
}

func TestCreatePreviewSignOutputRejectsNonzeroSigningKeyCounter(t *testing.T) {
	algorithm := cose.AlgorithmESP256SplitARKGPlaceholder
	previewSignFlags := protocol.AuthDataFlagUserPresent
	aaguid := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	authDataFlags := protocol.AuthDataFlagUserPresent |
		protocol.AuthDataFlagAttestedCredentialDataIncluded |
		protocol.AuthDataFlagExtensionDataIncluded
	outerAuthData := &protocol.MakeCredentialAuthData{
		RPIDHash:  make([]byte, 32),
		Flags:     authDataFlags,
		SignCount: 1,
		AttestedCredentialData: &protocol.AttestedCredentialData{
			AAGUID: aaguid,
		},
		Extensions: &protocol.CreateExtensionOutputs{
			CreatePreviewSignOutput: protocol.CreatePreviewSignOutput{
				PreviewSign: &protocol.PreviewSignOutput{Algorithm: &algorithm},
			},
		},
	}
	innerAuthData := func(signCount uint32) []byte {
		return previewSignAuthDataWithSignCount(
			t,
			authDataFlags,
			signCount,
			aaguid,
			[]byte("signing-key-handle"),
			previewSignCredentialKey(3),
			protocol.CreateExtensionOutputs{
				CreatePreviewSignOutput: protocol.CreatePreviewSignOutput{
					PreviewSign: &protocol.PreviewSignOutput{Flags: &previewSignFlags},
				},
			},
		)
	}
	response := protocol.AuthenticatorMakeCredentialResponse{
		Format:               attestation.AttestationStatementFormatIdentifierPacked,
		AuthData:             outerAuthData,
		AttestationStatement: map[string]any{},
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierPreviewSign: protocol.PreviewSignUnsignedOutput{
				AttestationObject: encodeCBOR(t, map[uint64]any{
					1: attestation.AttestationStatementFormatIdentifierNone,
					2: innerAuthData(1),
					3: map[string]any{},
				}),
			},
		},
	}
	request := &protocol.PreviewSignGenerateKeyInput{
		Algorithms: []cose.Algorithm{algorithm},
		Flags:      &previewSignFlags,
	}

	_, err := createPreviewSignOutput(request, response)
	require.ErrorIs(t, err, ErrSpecViolation)
}

func TestGetPreviewSignOutputPreservesPresentEmptySignature(t *testing.T) {
	emptySignature := []byte{}
	output, err := getPreviewSignOutput(
		&protocol.PreviewSignSignInput{},
		protocol.AuthenticatorGetAssertionResponse{
			AuthData: &protocol.GetAssertionAuthData{
				Flags: protocol.AuthDataFlagExtensionDataIncluded,
				Extensions: &protocol.GetExtensionOutputs{
					GetPreviewSignOutput: protocol.GetPreviewSignOutput{
						PreviewSign: &protocol.PreviewSignOutput{Signature: emptySignature},
					},
				},
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, output)
	assert.NotNil(t, output.PreviewSign.Signature)
	assert.Empty(t, output.PreviewSign.Signature)
}
