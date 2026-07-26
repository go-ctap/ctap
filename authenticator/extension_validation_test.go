package authenticator

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeCredentialWithExtensions(
	d *Device,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return makeCredentialWithExtensionsAndOptions(d, extInputs, nil)
}

func makeCredentialWithExtensionsAndOptions(
	d *Device,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	requestOptions map[protocol.Option]bool,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	return d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		extInputs,
		requestOptions,
		0,
		nil,
	)
}

func authDataWithExtensionOutputs(t *testing.T, outputs any) []byte {
	t.Helper()

	authData := minimalAuthData()
	authData[32] = byte(protocol.AuthDataFlagExtensionDataIncluded)
	return append(authData, encodeCBOR(t, outputs)...)
}

func TestMakeCredentialVerifiesEnforcedCredentialProtectionOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  *int
		wantErr error
	}{
		{name: "missing output", wantErr: ErrSpecViolation},
		{name: "weaker output", output: new(1), wantErr: ErrSpecViolation},
		{name: "enforced output", output: new(3)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authData := minimalAuthData()
			if tt.output != nil {
				authData = authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
					CreateCredProtectOutput: protocol.CreateCredProtectOutput{CredProtect: *tt.output},
				})
			}
			response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
				Format:      attestation.AttestationStatementFormatIdentifierPacked,
				AuthDataRaw: authData,
			})
			fake := testhid.NewCBORDevice(t, testCID, response)
			d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierCredentialProtection},
				Options: map[protocol.Option]bool{
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			})

			_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialProtectionInputs: &webauthn.CreateCredentialProtectionInputs{
					CredentialProtectionPolicy:        extension.CredentialProtectionPolicyUserVerificationRequired,
					EnforceCredentialProtectionPolicy: true,
				},
			})
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.NotEmpty(t, fake.Writes())
		})
	}
}

func TestMakeCredentialIgnoresOversizedCredentialBlob(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierCredentialBlob,
			extension.ExtensionIdentifierCredentialProtection,
		},
		MaxCredBlobLength: 32,
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
		CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{
			CredBlob: bytes.Repeat([]byte{0xaa}, 33),
		},
	})
	require.NoError(t, err)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	require.Equal(t, protocol.AuthenticatorMakeCredential, command)
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	require.NotNil(t, request.Extensions)
	assert.Zero(t, request.Extensions.CreateCredBlobInput)
}

func TestFalseBooleanExtensionInputsAreNotProcessed(t *testing.T) {
	t.Run("MakeCredential", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalAuthData(),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretInputs:          &webauthn.CreateHMACSecretInputs{HMACCreateSecret: false},
			CreateMinPinLengthInputs:        &webauthn.CreateMinPinLengthInputs{MinPinLength: false},
			CreatePinComplexityPolicyInputs: &webauthn.CreatePinComplexityPolicyInputs{PinComplexityPolicy: false},
			PaymentInputs: &webauthn.PaymentInputs{
				Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: false},
			},
		})
		require.NoError(t, err)

		_, requestCBOR := fake.FirstCTAPPayload(t)
		var request protocol.AuthenticatorMakeCredentialRequest
		require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
		require.NotNil(t, request.Extensions)
		assert.Zero(t, request.Extensions.CreateHMACSecretInput)
		assert.Zero(t, request.Extensions.CreateMinPinLengthInput)
		assert.Zero(t, request.Extensions.CreatePinComplexityPolicyInput)
		assert.Zero(t, request.Extensions.CreateThirdPartyPaymentInput)
	})

	t.Run("GetAssertion", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: minimalAuthData(),
			Signature:   []byte("signature"),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

		var count int
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				GetCredentialBlobInputs: &webauthn.GetCredentialBlobInputs{GetCredBlob: false},
				PaymentInputs: &webauthn.PaymentInputs{
					Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: false},
				},
			},
			nil,
		) {
			count++
			require.NoError(t, err)
		}
		require.Equal(t, 1, count)

		_, requestCBOR := fake.FirstCTAPPayload(t)
		var request protocol.AuthenticatorGetAssertionRequest
		require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
		require.NotNil(t, request.Extensions)
		assert.Zero(t, request.Extensions.GetCredBlobInput)
		assert.Zero(t, request.Extensions.GetThirdPartyPaymentInput)
	})
}

func TestThirdPartyPaymentExtension(t *testing.T) {
	t.Run("MakeCredential", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalAuthData(),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierThirdPartyPayment},
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PaymentInputs: &webauthn.PaymentInputs{
				Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true},
			},
		})
		require.NoError(t, err)

		command, requestCBOR := fake.FirstCTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
		var request protocol.AuthenticatorMakeCredentialRequest
		require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
		assert.True(t, request.Extensions.CreateThirdPartyPaymentInput.ThirdPartyPayment)
	})

	t.Run("GetAssertion preserves false output", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: authDataWithExtensionOutputs(t, protocol.GetExtensionOutputs{
				GetThirdPartyPaymentOutput: &protocol.GetThirdPartyPaymentOutput{ThirdPartyPayment: false},
			}),
			Signature: []byte("signature"),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierThirdPartyPayment},
		})

		var assertions []protocol.AuthenticatorGetAssertionResponse
		for assertion, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			&webauthn.GetAuthenticationExtensionsClientInputs{
				PaymentInputs: &webauthn.PaymentInputs{
					Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true},
				},
			},
			nil,
		) {
			require.NoError(t, err)
			assertions = append(assertions, assertion)
		}
		require.Len(t, assertions, 1)
		require.NotNil(t, assertions[0].AuthData.Extensions.GetThirdPartyPaymentOutput)
		assert.False(t, assertions[0].AuthData.Extensions.GetThirdPartyPaymentOutput.ThirdPartyPayment)

		command, requestCBOR := fake.FirstCTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
		var request protocol.AuthenticatorGetAssertionRequest
		require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
		assert.True(t, request.Extensions.GetThirdPartyPaymentInput.ThirdPartyPayment)
	})

	t.Run("requires advertised support", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, &webauthn.CreateAuthenticationExtensionsClientInputs{
			PaymentInputs: &webauthn.PaymentInputs{
				Payment: webauthn.AuthenticationExtensionsPaymentInputs{IsPayment: true},
			},
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assertNoAuthenticatorIO(t, fake)
	})
}

func TestCompositeExtensionCapabilitiesAreValidatedBeforeCommand(t *testing.T) {
	tests := []struct {
		name      string
		info      protocol.AuthenticatorGetInfoResponse
		extInputs *webauthn.CreateAuthenticationExtensionsClientInputs
	}{
		{
			name: "credBlob requires credProtect",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions:        []extension.ExtensionIdentifier{extension.ExtensionIdentifierCredentialBlob},
				MaxCredBlobLength: 32,
			},
			extInputs: &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
			},
		},
		{
			name: "credBlob requires minimum maximum length",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{
					extension.ExtensionIdentifierCredentialBlob,
					extension.ExtensionIdentifierCredentialProtection,
				},
				MaxCredBlobLength: 31,
			},
			extInputs: &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
			},
		},
		{
			name: "hmac-secret-mc requires hmac-secret",
			info: protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecretMC},
			},
			extInputs: &webauthn.CreateAuthenticationExtensionsClientInputs{
				CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
					HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID)
			tt.info.Options = map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			}
			d := newTestDevice(t, fake, tt.info)

			_, err := makeCredentialWithExtensions(d, tt.extInputs)
			require.ErrorIs(t, err, ErrSpecViolation)
			assertNoAuthenticatorIO(t, fake)
		})
	}
}

func TestGetAssertionRejectsHMACSecretWhenUserPresenceIsDisabledBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
			},
		},
		map[protocol.Option]bool{protocol.OptionUserPresence: false},
	) {
		gotErr = err
	}

	require.ErrorIs(t, gotErr, ErrNotSupported)
	assertNoAuthenticatorIO(t, fake)
}

func TestUnsolicitedExtensionOutputsAreRejectedWithoutPanic(t *testing.T) {
	t.Run("MakeCredential hmac-secret-mc", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format: attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: authDataWithExtensionOutputs(t, protocol.CreateExtensionOutputs{
				CreateHMACSecretMCOutput: protocol.CreateHMACSecretMCOutput{HMACSecret: make([]byte, 32)},
			}),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := makeCredentialWithExtensions(d, nil)
		require.ErrorIs(t, err, ErrSpecViolation)
	})

	t.Run("GetAssertion hmac-secret", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: authDataWithExtensionOutputs(t, protocol.GetExtensionOutputs{
				GetHMACSecretOutput: protocol.GetHMACSecretOutput{HMACSecret: make([]byte, 32)},
			}),
			Signature: []byte("signature"),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

		var gotErr error
		for _, err := range d.GetAssertion(
			testContext,
			nil,
			"example.com",
			[]byte("client-data"),
			nil,
			nil,
			nil,
		) {
			gotErr = err
		}
		require.ErrorIs(t, gotErr, ErrSpecViolation)
	})
}

func TestSetLargeBlobsValidatesAndCanonicalizesArray(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		MaxSerializedLargeBlobArray: 1024,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	}

	t.Run("rejects invalid entries", func(t *testing.T) {
		tests := []protocol.LargeBlob{
			{Ciphertext: make([]byte, 15), Nonce: make([]byte, 12)},
			{Ciphertext: make([]byte, 16), Nonce: make([]byte, 11)},
		}
		for _, blob := range tests {
			fake := testhid.NewCBORDevice(t, testCID)
			d := newTestDevice(t, fake, info)

			err := d.SetLargeBlobs(testContext, nil, []protocol.LargeBlob{blob})
			require.ErrorIs(t, err, SyntaxError)
			assertNoAuthenticatorIO(t, fake)
		}
	})

	t.Run("nil input becomes an empty array", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, info)

		require.NoError(t, d.SetLargeBlobs(testContext, nil, nil))

		_, requestCBOR := fake.FirstCTAPPayload(t)
		var request protocol.AuthenticatorLargeBlobsRequest
		require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
		require.Len(t, request.Set, 17)
		assert.Equal(t, byte(0x80), request.Set[0])
		hash := sha256.Sum256(request.Set[:1])
		assert.Equal(t, hash[:16], request.Set[1:])
	})
}

func TestValidateMakeCredentialExtensionOutputsRejectsUnsolicitedValues(t *testing.T) {
	err := validateMakeCredentialExtensionOutputs(
		&protocol.CreateExtensionInputs{},
		&webauthn.CreateAuthenticationExtensionsClientInputs{},
		&protocol.CreateExtensionOutputs{
			CreateCredBlobOutput: &protocol.CreateCredBlobOutput{CredBlob: true},
		},
	)
	require.ErrorIs(t, err, ErrSpecViolation)
}

func TestGetAssertionValidatesHMACSecretSalts(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 31)},
			},
		},
		nil,
	) {
		count++
		assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSaltSize))
	}

	assert.Equal(t, 1, count)
	assertNoAuthenticatorIO(t, fake)
}

func TestMakeCredentialValidatesHMACSecretMCSalts(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32), Salt2: make([]byte, 31)},
			},
		},
		nil,
		0,
		nil,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSaltSize))
	assertNoAuthenticatorIO(t, fake)
}

func TestMakeCredentialAllowsFIDO20BuiltInUV(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
		},
	})

	_, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
		0,
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, fake.Writes())
}

func TestMakeCredentialCredPropsOutputDependsOnCredPropsInput(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	}
	fake := testhid.NewCBORDevice(t, testCID, response, encodeCBOR(t, info))
	d := newTestDevice(t, fake, info)

	resp, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthn.CreateCredentialPropertiesInputs{CredentialProperties: true},
		},
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs)
	require.NotNil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
	assert.True(t, *resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
}

func TestMakeCredentialRequiresMaxCredBlobLengthWhenCredBlobExtensionReported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierCredentialBlob,
			extension.ExtensionIdentifierCredentialProtection,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
		},
		nil,
		0,
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maxCredBlobLength")
	assertNoAuthenticatorIO(t, fake)
}

func TestHMACSecretPinUvAuthProtocolWirePresence(t *testing.T) {
	tests := []struct {
		name       string
		protocol   protocol.PinUvAuthProtocol
		wantMember bool
	}{
		{name: "protocol one is implicit", protocol: protocol.PinUvAuthProtocolOne},
		{name: "protocol two is explicit", protocol: protocol.PinUvAuthProtocolTwo, wantMember: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := newHMACSecretInput(cose.Key{1: 2}, []byte{3}, []byte{4}, tt.protocol)
			raw, err := cbor.Marshal(input)
			require.NoError(t, err)

			var fields map[uint64]cbor.RawMessage
			require.NoError(t, cbor.Unmarshal(raw, &fields))
			if tt.wantMember {
				require.Contains(t, fields, uint64(4))
			} else {
				require.NotContains(t, fields, uint64(4))
			}
		})
	}
}
