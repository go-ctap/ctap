package authenticator

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"uuid"

	"github.com/fxamacker/cbor/v2"
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := result.ExtensionOutputs.PreviewSignOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	generatedKey := result.ExtensionOutputs.PreviewSign.GeneratedKey
	if got := generatedKey; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	{
		want, got := signingKeyHandle, generatedKey.KeyHandle
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := algorithm, generatedKey.Algorithm
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantPublicKey, err := encMode.Marshal(previewSignCredentialKey(3))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := wantPublicKey, generatedKey.PublicKey
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	attestationObject, err := attestation.ParseObject(generatedKey.AttestationObject)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := attestation.AttestationStatementFormatIdentifierNone, attestationObject.Format
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := innerAuthData, attestationObject.AuthData
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	command, requestCBOR := fake.FirstCTAPPayload(t)
	{
		want, got := protocol.AuthenticatorMakeCredential, command
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	var request protocol.AuthenticatorMakeCredentialRequest
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := request.Extensions.PreviewSign.Flags; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	{
		want, got := protocol.AuthDataFlagUserPresent, *request.Extensions.PreviewSign.Flags
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []cose.Algorithm{algorithm}, request.Extensions.PreviewSign.Algorithms
		if (got == nil) != (want == nil) || !slices.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
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
	if err := gotErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := result.ExtensionOutputs.PreviewSignOutputs; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	{
		want, got := signature, result.ExtensionOutputs.PreviewSign.Signature
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	command, requestCBOR := fake.FirstCTAPPayload(t)
	{
		want, got := protocol.AuthenticatorGetAssertion, command
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	var request protocol.AuthenticatorGetAssertionRequest
	if err := cbor.Unmarshal(requestCBOR, &request); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := request.Extensions.PreviewSign.KeyHandle; got == nil {
		t.Errorf("got nil, want a non-nil value")
	}
	if got := request.Extensions.PreviewSign.ToBeSigned; got == nil {
		t.Errorf("got nil, want a non-nil value")
	}
	if got := request.Extensions.PreviewSign.KeyHandle; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
	if got := request.Extensions.PreviewSign.ToBeSigned; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
	{
		want, got := additionalArguments, request.Extensions.PreviewSign.AdditionalArguments
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := input.Flags; got == nil {
			t.Fatalf("got nil, want a non-nil value")
		}
		{
			want, got := protocol.AuthDataFlagUserPresent|protocol.AuthDataFlagUserVerified, *input.Flags
			if got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		}
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
		{
			err, target := err, ErrNotSupported
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := input; got == nil {
			t.Errorf("got nil, want a non-nil value")
		}

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
		{
			err, target := err, ErrNotSupported
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
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

		if err := validate(encodeCBOR(t, map[any]any{
			3:     cose.AlgorithmESP256SplitARKGPlaceholder,
			"kid": []byte{1},
		})); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		{
			err, target := validate(encodeCBOR(t, map[string]any{"kid": []byte{1}})), SyntaxError
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
		{
			err, target := validate(encodeCBOR(t, map[int]any{3: true})), SyntaxError
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
		{
			err, target := validate(encodeCBOR(t, map[any]any{3: -1, true: 1})), SyntaxError
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
		{
			err, target := validate([]byte{0xa2, 0x03, 0x26, 0x03, 0x27}), SyntaxError
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
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
	{
		err, target := err, ErrSpecViolation
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := output; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	if got := output.PreviewSign.Signature; got == nil {
		t.Errorf("got nil, want a non-nil value")
	}
	if got := output.PreviewSign.Signature; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
}
