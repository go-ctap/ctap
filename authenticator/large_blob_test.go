package authenticator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/credential"
	ctapcrypto "github.com/telesma-app/ctap/crypto"
	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectLargeBlobMakeCredential(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: protocol.CreateLargeBlobOutput{Supported: true},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
	})

	result, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
			Support: extension.LargeBlobSupportRequired,
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, result.ExtensionOutputs.LargeBlobOutputs)
	require.NotNil(t, result.ExtensionOutputs.LargeBlobOutputs.LargeBlob.Supported)
	assert.True(t, *result.ExtensionOutputs.LargeBlobOutputs.LargeBlob.Supported)

	command, payload := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	assert.Equal(t, extension.LargeBlobSupportRequired, request.Extensions.CreateLargeBlobInput.LargeBlob.Support)
	assert.Zero(t, request.Extensions.CreateLargeBlobKeyInput)
}

func TestLegacyLargeBlobMakeCredential(t *testing.T) {
	key := make([]byte, 32)
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:       attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw:  minimalAuthData(),
		LargeBlobKey: key,
	})
	info := legacyLargeBlobInfo()
	fake := testhid.NewCBORDevice(t, testCID, response, encodeCBOR(t, info))
	d := newTestDevice(t, fake, info)

	result, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
			Support: extension.LargeBlobSupportRequired,
		},
	}, map[protocol.Option]bool{protocol.OptionResidentKeys: true})
	require.NoError(t, err)
	require.NotNil(t, result.ExtensionOutputs.LargeBlobOutputs)
	require.NotNil(t, result.ExtensionOutputs.LargeBlobOutputs.LargeBlob.Supported)
	assert.True(t, *result.ExtensionOutputs.LargeBlobOutputs.LargeBlob.Supported)

	command, payload := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	var request protocol.AuthenticatorMakeCredentialRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	assert.True(t, request.Extensions.CreateLargeBlobKeyInput.LargeBlobKey)
	assert.Zero(t, request.Extensions.CreateLargeBlobInput)
}

func TestLegacyLargeBlobMakeCredentialValidatesKeyRequestCorrelation(t *testing.T) {
	t.Run("requested preferred key is required in response", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalAuthData(),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
				Support: extension.LargeBlobSupportPreferred,
			},
		}, map[protocol.Option]bool{protocol.OptionResidentKeys: true})
		require.ErrorIs(t, err, ErrSpecViolation)
		assert.Contains(t, err.Error(), "omitted")

		_, payload := fake.FirstCTAPPayload(t)
		var request protocol.AuthenticatorMakeCredentialRequest
		require.NoError(t, cbor.Unmarshal(payload, &request))
		assert.True(t, request.Extensions.CreateLargeBlobKeyInput.LargeBlobKey)
	})

	t.Run("key without CTAP extension input is unsolicited", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:       attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw:  minimalAuthData(),
			LargeBlobKey: make([]byte, 32),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
				Support: extension.LargeBlobSupportPreferred,
			},
		}, nil)
		require.ErrorIs(t, err, ErrSpecViolation)
		assert.Contains(t, err.Error(), "unsolicited")

		_, payload := fake.FirstCTAPPayload(t)
		var request protocol.AuthenticatorMakeCredentialRequest
		require.NoError(t, cbor.Unmarshal(payload, &request))
		assert.Zero(t, request.Extensions.CreateLargeBlobKeyInput)
	})
}

func TestMakeCredentialRejectsUnsolicitedLargeBlobResponseWithoutClientInput(t *testing.T) {
	t.Run("legacy key", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:       attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw:  minimalAuthData(),
			LargeBlobKey: make([]byte, 32),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, nil, nil)
		require.ErrorIs(t, err, ErrSpecViolation)
	})

	t.Run("direct output", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalAuthData(),
			UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
				extension.ExtensionIdentifierLargeBlob: protocol.CreateLargeBlobOutput{Supported: true},
			},
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:   protocol.Versions{protocol.FIDO_2_3},
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
		})

		_, err := makeCredentialWithLargeBlob(t, d, nil, nil)
		require.ErrorIs(t, err, ErrSpecViolation)
	})
}

func TestGetAssertionRejectsUnsolicitedLargeBlobResponseWithoutClientInput(t *testing.T) {
	t.Run("legacy key", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw:  minimalAuthData(),
			Signature:    []byte("signature"),
			LargeBlobKey: make([]byte, 32),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := getAssertionsWithLargeBlob(d, nil, nil)
		require.ErrorIs(t, err, ErrSpecViolation)
	})

	t.Run("direct output", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: minimalAuthData(),
			Signature:   []byte("signature"),
			UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
				extension.ExtensionIdentifierLargeBlob: protocol.GetLargeBlobOutput{Written: new(false)},
			},
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:   protocol.Versions{protocol.FIDO_2_3},
			Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
		})

		_, err := getAssertionsWithLargeBlob(d, nil, nil)
		require.ErrorIs(t, err, ErrSpecViolation)
	})
}

func TestDirectLargeBlobGetAssertionRead(t *testing.T) {
	want := []byte("direct large blob")
	compressed, err := ctapcrypto.CompressLargeBlobData(want)
	require.NoError(t, err)
	originalSize := uint(len(want))
	response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte("signature"),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: protocol.GetLargeBlobOutput{
				Blob:         compressed,
				OriginalSize: &originalSize,
			},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
	})

	assertions, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	require.NoError(t, gotErr)
	require.Len(t, assertions, 1)
	require.NotNil(t, assertions[0].ExtensionOutputs.LargeBlobOutputs)
	require.NotNil(t, assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Blob)
	assert.Equal(t, want, assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Blob)

	command, payload := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
	var request protocol.AuthenticatorGetAssertionRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	assert.True(t, request.Extensions.GetLargeBlobInput.LargeBlob.Read)
	assert.Zero(t, request.Extensions.GetLargeBlobKeyInput)
}

func TestDirectLargeBlobGetAssertionPreservesEmptyWrite(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte("signature"),
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierLargeBlob: protocol.GetLargeBlobOutput{Written: new(true)},
		},
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions:   protocol.Versions{protocol.FIDO_2_3},
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlob},
	})
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}}

	assertions, gotErr := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: []byte{}},
	})
	require.NoError(t, gotErr)
	require.Len(t, assertions, 1)
	require.NotNil(t, assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Written)
	assert.True(t, *assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Written)

	_, payload := fake.FirstCTAPPayload(t)
	var request protocol.AuthenticatorGetAssertionRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	params := request.Extensions.GetLargeBlobInput.LargeBlob
	require.NotNil(t, params.Write)
	require.NotNil(t, params.OriginalSize)
	assert.Zero(t, *params.OriginalSize)
	uncompressed, err := ctapcrypto.DecompressLargeBlobData(params.Write, *params.OriginalSize)
	require.NoError(t, err)
	assert.Empty(t, uncompressed)
}

func TestLegacyLargeBlobGetAssertionBuffersAllAssertionsBeforeRead(t *testing.T) {
	firstKey := make([]byte, 32)
	firstKey[0] = 1
	secondKey := make([]byte, 32)
	secondKey[0] = 2
	want := []byte("legacy large blob")
	encrypted, err := ctapcrypto.EncryptLargeBlob(firstKey, want)
	require.NoError(t, err)

	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 2,
		LargeBlobKey:        firstKey,
	})
	second := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte{2},
		LargeBlobKey: secondKey,
	})
	array := encodeLargeBlobConfig(t, []protocol.LargeBlob{encrypted})
	largeBlobs := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: array})
	fake := testhid.NewCBORDevice(t, testCID, first, second, largeBlobs)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())

	assertions, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	require.NoError(t, gotErr)
	require.Len(t, assertions, 2)
	require.NotNil(t, assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Blob)
	assert.Equal(t, want, assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Blob)
	assert.Nil(t, assertions[1].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Blob)

	requests := fake.Requests(t)
	require.Len(t, requests, 3)
	commands := make([]protocol.Command, 0, len(requests))
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		commands = append(commands, command)
	}
	assert.Equal(t, []protocol.Command{
		protocol.AuthenticatorGetAssertion,
		protocol.AuthenticatorGetNextAssertion,
		protocol.AuthenticatorLargeBlobs,
	}, commands)

	_, payload := requests[0].CTAPPayload(t)
	var request protocol.AuthenticatorGetAssertionRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	assert.True(t, request.Extensions.GetLargeBlobKeyInput.LargeBlobKey)
	assert.Zero(t, request.Extensions.GetLargeBlobInput)
}

func TestLegacyLargeBlobGetAssertionWrite(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	oldBlob, err := ctapcrypto.EncryptLargeBlob(key, []byte("old"))
	require.NoError(t, err)
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte("signature"),
		LargeBlobKey: key,
	})
	read := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: encodeLargeBlobConfig(t, []protocol.LargeBlob{oldBlob}),
	})
	write := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{})
	fake := testhid.NewCBORDevice(t, testCID, assertion, read, write)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}}
	want := []byte("updated")

	assertions, gotErr := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: want},
	})
	require.NoError(t, gotErr)
	require.Len(t, assertions, 1)
	require.NotNil(t, assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Written)
	assert.True(t, *assertions[0].ExtensionOutputs.LargeBlobOutputs.LargeBlob.Written)

	requests := fake.Requests(t)
	require.Len(t, requests, 3)
	command, payload := requests[2].CTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	var request protocol.AuthenticatorLargeBlobsRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	require.GreaterOrEqual(t, len(request.Set), 16)
	serialized := request.Set[:len(request.Set)-16]
	checksum := sha256.Sum256(serialized)
	assert.Equal(t, checksum[:16], request.Set[len(request.Set)-16:])
	var stored []protocol.LargeBlob
	require.NoError(t, cbor.Unmarshal(serialized, &stored))
	require.Len(t, stored, 1)
	got, err := ctapcrypto.DecryptLargeBlob(key, stored[0])
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestLegacyLargeBlobReadReturnsMatchedDecompressionError(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	malformed := encryptRawLargeBlob(t, key, []byte{0xff}, 8)
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte("signature"),
		LargeBlobKey: key,
	})
	largeBlobs := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: encodeLargeBlobConfig(t, []protocol.LargeBlob{malformed}),
	})
	fake := testhid.NewCBORDevice(t, testCID, assertion, largeBlobs)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())

	_, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	require.Error(t, gotErr)
}

func TestLegacyLargeBlobWriteReplacesAEADMatchWithoutDecompressing(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	malformed := encryptRawLargeBlob(t, key, []byte{0xff}, 8)
	assertion := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:  minimalAuthData(),
		Signature:    []byte("signature"),
		LargeBlobKey: key,
	})
	read := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: encodeLargeBlobConfig(t, []protocol.LargeBlob{malformed}),
	})
	write := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{})
	fake := testhid.NewCBORDevice(t, testCID, assertion, read, write)
	d := newTestDevice(t, fake, legacyLargeBlobInfo())
	allowList := []credential.PublicKeyCredentialDescriptor{{
		Type: credential.PublicKeyCredentialTypePublicKey,
		ID:   []byte("credential-id"),
	}}
	want := []byte("replacement")

	assertions, gotErr := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Write: want},
	})
	require.NoError(t, gotErr)
	require.Len(t, assertions, 1)

	requests := fake.Requests(t)
	require.Len(t, requests, 3)
	_, payload := requests[2].CTAPPayload(t)
	var request protocol.AuthenticatorLargeBlobsRequest
	require.NoError(t, cbor.Unmarshal(payload, &request))
	serialized := request.Set[:len(request.Set)-16]
	var stored []protocol.LargeBlob
	require.NoError(t, cbor.Unmarshal(serialized, &stored))
	require.Len(t, stored, 1)
	got, err := ctapcrypto.DecryptLargeBlob(key, stored[0])
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestLargeBlobInputValidationUsesReadPresence(t *testing.T) {
	presentFalse := new(false)

	t.Run("MakeCredential rejects present read", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())

		_, err := makeCredentialWithLargeBlob(t, d, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: presentFalse},
		}, nil)
		require.ErrorIs(t, err, SyntaxError)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("GetAssertion rejects present read with write", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, legacyLargeBlobInfo())
		allowList := []credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("credential-id"),
		}}

		_, err := getAssertionsWithLargeBlob(d, allowList, &webauthn.LargeBlobInputs{
			LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{
				Read:  presentFalse,
				Write: []byte("blob"),
			},
		})
		require.ErrorIs(t, err, SyntaxError)
		assertNoAuthenticatorIO(t, fake)
	})
}

func TestLargeBlobRejectsMutuallyExclusiveAuthenticatorCapabilities(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierLargeBlob,
			extension.ExtensionIdentifierLargeBlobKey,
		},
		Options: map[protocol.Option]bool{protocol.OptionLargeBlobs: true},
	})

	_, gotErr := getAssertionsWithLargeBlob(d, nil, &webauthn.LargeBlobInputs{
		LargeBlob: webauthn.AuthenticationExtensionsLargeBlobInputs{Read: new(true)},
	})
	require.ErrorIs(t, gotErr, ErrSpecViolation)
	assertNoAuthenticatorIO(t, fake)
}

func makeCredentialWithLargeBlob(
	t *testing.T,
	d *Device,
	inputs *webauthn.LargeBlobInputs,
	requestOptions map[protocol.Option]bool,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	t.Helper()
	return d.MakeCredential(
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
		&webauthn.CreateAuthenticationExtensionsClientInputs{LargeBlobInputs: inputs},
		requestOptions,
		0,
		nil,
	)
}

func getAssertionsWithLargeBlob(
	d *Device,
	allowList []credential.PublicKeyCredentialDescriptor,
	inputs *webauthn.LargeBlobInputs,
) ([]protocol.AuthenticatorGetAssertionResponse, error) {
	var assertions []protocol.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		allowList,
		&webauthn.GetAuthenticationExtensionsClientInputs{LargeBlobInputs: inputs},
		nil,
	) {
		if err != nil {
			return nil, err
		}
		assertions = append(assertions, assertion)
	}
	return assertions, nil
}

func legacyLargeBlobInfo() protocol.AuthenticatorGetInfoResponse {
	return protocol.AuthenticatorGetInfoResponse{
		Versions:                    protocol.Versions{protocol.FIDO_2_1},
		Extensions:                  []extension.ExtensionIdentifier{extension.ExtensionIdentifierLargeBlobKey},
		MaxSerializedLargeBlobArray: 2048,
		Options:                     map[protocol.Option]bool{protocol.OptionLargeBlobs: true},
	}
}

func encodeLargeBlobConfig(t *testing.T, blobs []protocol.LargeBlob) []byte {
	t.Helper()
	serialized, err := marshalLargeBlobArray(blobs)
	require.NoError(t, err)
	sum := sha256.Sum256(serialized)
	return append(serialized, sum[:16]...)
}

func encryptRawLargeBlob(t *testing.T, key, plaintext []byte, originalSize uint) protocol.LargeBlob {
	t.Helper()

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	nonce[0] = 1
	additionalData := make([]byte, 12)
	copy(additionalData, "blob")
	binary.LittleEndian.PutUint64(additionalData[4:], uint64(originalSize))

	return protocol.LargeBlob{
		Ciphertext: gcm.Seal(nil, nonce, plaintext, additionalData),
		Nonce:      nonce,
		OrigSize:   originalSize,
	}
}

func TestLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, sum[:16]...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Empty(t, blobs)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	require.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	assert.Equal(t, uint64(960), request[uint64(1)])
}

func TestGetLargeBlobsReadsAllFullFragments(t *testing.T) {
	want := []protocol.LargeBlob{{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 32),
		Nonce:      bytes.Repeat([]byte{0xbb}, 12),
		OrigSize:   16,
	}}
	encodedBlobs, err := marshalLargeBlobArray(want)
	require.NoError(t, err)
	sum := sha256.Sum256(encodedBlobs)
	config := slices.Concat(encodedBlobs, sum[:16])

	const maxFragmentLength = 16
	chunks := lo.Chunk(config, maxFragmentLength)
	require.Greater(t, len(chunks), 2)
	responses := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		responses[i] = encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: chunk})
	}

	fake := testhid.NewCBORDevice(t, testCID, responses...)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize: uint(maxFragmentLength + 64),
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	got, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Len(t, fake.Requests(t), len(chunks))
}

func TestGetLargeBlobsStopsAfterTrailingEmptyFragment(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	config := slices.Concat(encodedBlobs, sum[:16])
	maxMsgSize := uint(len(config) + 64)

	fake := testhid.NewCBORDevice(
		t,
		testCID,
		encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: config}),
		encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: []byte{}}),
	)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize: maxMsgSize,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Empty(t, blobs)

	requests := fake.Requests(t)
	require.Len(t, requests, 2)
	command, request := requests[1].CTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	assert.Equal(t, uint64(len(config)), request[uint64(3)])
}

func TestLargeBlobsReturnsIntegrityErrorForCorruptConfig(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{{Ciphertext: []byte{0xaa}}})
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, bytes.Repeat([]byte{0x00}, 16)...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	_, err := d.GetLargeBlobs(testContext)
	require.ErrorIs(t, err, ErrLargeBlobsIntegrityCheck)
}

func TestLargeBlobsReturnsInvalidArrayError(t *testing.T) {
	invalidArray := []byte{0xff}
	sum := sha256.Sum256(invalidArray)
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(invalidArray, sum[:16]...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	_, err := d.GetLargeBlobs(testContext)
	require.ErrorIs(t, err, SyntaxError)
}

func TestSetLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:          []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		MaxSerializedLargeBlobArray: 2048,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})
	blob := protocol.LargeBlob{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 1000),
		Nonce:      bytes.Repeat([]byte{0xbb}, 12),
	}

	err := d.SetLargeBlobs(testContext, make([]byte, 32), []protocol.LargeBlob{blob})
	require.NoError(t, err)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	require.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	set, ok := request[uint64(2)].([]byte)
	require.True(t, ok)
	assert.Len(t, set, 960)
	assert.Equal(t, uint64(0), request[uint64(3)])
}

func TestSetLargeBlobsRequiresReportedMaxSerializedLargeBlobArray(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	err := d.SetLargeBlobs(testContext, make([]byte, 32), []protocol.LargeBlob{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maxSerializedLargeBlobArray")
	assertNoAuthenticatorIO(t, fake)
}
