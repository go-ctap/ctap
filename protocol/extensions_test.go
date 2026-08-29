package protocol

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/extension"
)

func TestLargeBlobKeyExtensionInputs(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	tests := []struct {
		name  string
		input any
	}{
		{
			name: "MakeCredential",
			input: CreateExtensionInputs{
				CreateLargeBlobKeyInput: CreateLargeBlobKeyInput{LargeBlobKey: true},
			},
		},
		{
			name: "GetAssertion",
			input: GetExtensionInputs{
				GetLargeBlobKeyInput: GetLargeBlobKeyInput{LargeBlobKey: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := encMode.Marshal(tt.input)
			require.NoError(t, err)
			assert.Equal(t, []byte{
				0xa1,
				0x6c, 'l', 'a', 'r', 'g', 'e', 'B', 'l', 'o', 'b', 'K', 'e', 'y',
				0xf5,
			}, encoded)
		})
	}
}

func TestPreviewSignExtensionWireTypes(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	flags := AuthDataFlagUserPresent
	createEncoded, err := encMode.Marshal(CreateExtensionInputs{
		CreatePreviewSignInput: CreatePreviewSignInput{
			PreviewSign: PreviewSignGenerateKeyInput{
				Algorithms: []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder},
				Flags:      &flags,
			},
		},
	})
	require.NoError(t, err)
	var create map[string]map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(createEncoded, &create))
	require.Contains(t, create, "previewSign")
	var algorithms []cose.Algorithm
	require.NoError(t, cbor.Unmarshal(create["previewSign"][3], &algorithms))
	assert.Equal(t, []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder}, algorithms)
	var gotFlags AuthDataFlag
	require.NoError(t, cbor.Unmarshal(create["previewSign"][4], &gotFlags))
	assert.Equal(t, flags, gotFlags)

	unattended := AuthDataFlag(0)
	unattendedEncoded, err := encMode.Marshal(CreateExtensionInputs{
		CreatePreviewSignInput: CreatePreviewSignInput{
			PreviewSign: PreviewSignGenerateKeyInput{
				Algorithms: []cose.Algorithm{cose.AlgorithmESP256SplitARKGPlaceholder},
				Flags:      &unattended,
			},
		},
	})
	require.NoError(t, err)
	create = nil
	require.NoError(t, cbor.Unmarshal(unattendedEncoded, &create))
	assert.Contains(t, create["previewSign"], uint64(4), "explicit unattended flags must not be omitted")
	require.NoError(t, cbor.Unmarshal(create["previewSign"][4], &gotFlags))
	assert.Zero(t, gotFlags)

	outputEncoded, err := encMode.Marshal(CreateExtensionOutputs{
		CreatePreviewSignOutput: CreatePreviewSignOutput{
			PreviewSign: &PreviewSignOutput{Flags: &unattended},
		},
	})
	require.NoError(t, err)
	var output map[string]map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(outputEncoded, &output))
	require.Contains(t, output["previewSign"], uint64(4))
	require.NoError(t, cbor.Unmarshal(output["previewSign"][4], &gotFlags))
	assert.Zero(t, gotFlags)

	outputEncoded, err = encMode.Marshal(GetExtensionOutputs{
		GetPreviewSignOutput: GetPreviewSignOutput{
			PreviewSign: &PreviewSignOutput{Signature: []byte{}},
		},
	})
	require.NoError(t, err)
	output = nil
	require.NoError(t, cbor.Unmarshal(outputEncoded, &output))
	assert.Contains(t, output["previewSign"], uint64(6), "present empty signature must not be omitted")

	additionalArguments := []byte{0xa1, 0x03, 0x26}
	getEncoded, err := encMode.Marshal(GetExtensionInputs{
		GetPreviewSignInput: GetPreviewSignInput{
			PreviewSign: PreviewSignSignInput{
				KeyHandle:           []byte{},
				ToBeSigned:          []byte{},
				AdditionalArguments: additionalArguments,
			},
		},
	})
	require.NoError(t, err)
	var get map[string]map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(getEncoded, &get))
	require.Contains(t, get, "previewSign")
	for _, key := range []uint64{2, 6, 7} {
		assert.Contains(t, get["previewSign"], key)
	}
	var keyHandle, toBeSigned, gotAdditionalArguments []byte
	require.NoError(t, cbor.Unmarshal(get["previewSign"][2], &keyHandle))
	require.NoError(t, cbor.Unmarshal(get["previewSign"][6], &toBeSigned))
	require.NoError(t, cbor.Unmarshal(get["previewSign"][7], &gotAdditionalArguments))
	assert.Empty(t, keyHandle)
	assert.Empty(t, toBeSigned)
	assert.Equal(t, additionalArguments, gotAdditionalArguments)
}

func TestPreviewSignAttestationIsNestedInUnsignedExtensionOutputs(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	attestationObject := []byte{0xa0}
	encoded, err := encMode.Marshal(AuthenticatorMakeCredentialResponse{
		UnsignedExtensionOutputs: map[extension.ExtensionIdentifier]any{
			extension.ExtensionIdentifierPreviewSign: PreviewSignUnsignedOutput{
				AttestationObject: attestationObject,
			},
		},
	})
	require.NoError(t, err)

	var response map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(encoded, &response))
	require.Contains(t, response, uint64(6))
	assert.NotContains(t, response, uint64(7))

	var unsignedOutputs map[string]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(response[6], &unsignedOutputs))
	require.Contains(t, unsignedOutputs, "previewSign")

	var previewSign map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(unsignedOutputs["previewSign"], &previewSign))
	require.Contains(t, previewSign, uint64(7))

	var gotAttestationObject []byte
	require.NoError(t, cbor.Unmarshal(previewSign[7], &gotAttestationObject))
	assert.Equal(t, attestationObject, gotAttestationObject)
}

func TestPreviewSignOutputPreservesPresentEmptySignature(t *testing.T) {
	var output GetExtensionOutputs
	require.NoError(t, cbor.Unmarshal(
		[]byte{0xa1, 0x6b, 'p', 'r', 'e', 'v', 'i', 'e', 'w', 'S', 'i', 'g', 'n', 0xa1, 0x06, 0x40},
		&output,
	))
	require.NotNil(t, output.PreviewSign)
	assert.NotNil(t, output.PreviewSign.Signature)
	assert.Empty(t, output.PreviewSign.Signature)
}

func TestLargeBlobKeyExtensionInputIsOmittedWhenAbsent(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	createEncoded, err := encMode.Marshal(CreateExtensionInputs{})
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa0}, createEncoded)

	getEncoded, err := encMode.Marshal(GetExtensionInputs{})
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa0}, getEncoded)
}

func TestDirectLargeBlobExtensionWireTypes(t *testing.T) {
	encMode, err := cbor.CTAP2EncOptions().EncMode()
	require.NoError(t, err)

	createEncoded, err := encMode.Marshal(CreateExtensionInputs{
		CreateLargeBlobInput: CreateLargeBlobInput{
			LargeBlob: CreateLargeBlobParams{Support: extension.LargeBlobSupportRequired},
		},
	})
	require.NoError(t, err)
	var create map[string]map[string]any
	require.NoError(t, cbor.Unmarshal(createEncoded, &create))
	assert.Equal(t, "required", create["largeBlob"]["support"])

	emptyBlob := []byte{}
	getEncoded, err := encMode.Marshal(GetExtensionInputs{
		GetLargeBlobInput: GetLargeBlobInput{
			LargeBlob: GetLargeBlobParams{
				Write:        emptyBlob,
				OriginalSize: new(uint(0)),
			},
		},
	})
	require.NoError(t, err)
	var get map[string]map[string]any
	require.NoError(t, cbor.Unmarshal(getEncoded, &get))
	require.Contains(t, get["largeBlob"], "write")
	assert.Empty(t, get["largeBlob"]["write"])
	assert.Equal(t, uint64(0), get["largeBlob"]["originalSize"])

	getEncoded, err = encMode.Marshal(GetExtensionInputs{
		GetLargeBlobInput: GetLargeBlobInput{
			LargeBlob: GetLargeBlobParams{Read: true},
		},
	})
	require.NoError(t, err)
	get = nil
	require.NoError(t, cbor.Unmarshal(getEncoded, &get))
	assert.Equal(t, true, get["largeBlob"]["read"])
	assert.NotContains(t, get["largeBlob"], "write")
	assert.NotContains(t, get["largeBlob"], "originalSize")

	outputEncoded, err := encMode.Marshal(GetLargeBlobOutput{Blob: []byte{}})
	require.NoError(t, err)
	var output map[string]any
	require.NoError(t, cbor.Unmarshal(outputEncoded, &output))
	require.Contains(t, output, "blob")
	assert.Empty(t, output["blob"])

	outputEncoded, err = encMode.Marshal(GetLargeBlobOutput{})
	require.NoError(t, err)
	output = nil
	require.NoError(t, cbor.Unmarshal(outputEncoded, &output))
	assert.NotContains(t, output, "blob")
}

func TestLargeBlobUnsignedOutputsPreserveUnknownExtensionsAndProvideTypedAccessors(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		6: map[string]any{
			"largeBlob":      map[string]any{"supported": false},
			"vendor.example": map[string]any{"value": uint64(42)},
		},
	})
	require.NoError(t, err)

	var makeCredential AuthenticatorMakeCredentialResponse
	require.NoError(t, cbor.Unmarshal(raw, &makeCredential))
	require.NotNil(t, makeCredential.UnsignedExtensionOutputs)
	require.Contains(t, makeCredential.UnsignedExtensionOutputs, extension.ExtensionIdentifier("vendor.example"))
	makeCredentialOutput, err := makeCredential.LargeBlobUnsignedExtensionOutput()
	require.NoError(t, err)
	require.NotNil(t, makeCredentialOutput)
	require.False(t, makeCredentialOutput.Supported)

	raw, err = cbor.Marshal(map[uint64]any{
		8: map[string]any{
			"largeBlob": map[string]any{
				"written":      false,
				"blob":         []byte{},
				"originalSize": uint64(0),
			},
			"vendor.example": true,
		},
	})
	require.NoError(t, err)

	var getAssertion AuthenticatorGetAssertionResponse
	require.NoError(t, cbor.Unmarshal(raw, &getAssertion))
	require.Contains(t, getAssertion.UnsignedExtensionOutputs, extension.ExtensionIdentifier("vendor.example"))
	output, err := getAssertion.LargeBlobUnsignedExtensionOutput()
	require.NoError(t, err)
	require.NotNil(t, output)
	require.NotNil(t, output.Written)
	require.False(t, *output.Written)
	require.NotNil(t, output.Blob)
	require.Empty(t, output.Blob)
	require.NotNil(t, output.OriginalSize)
	require.Zero(t, *output.OriginalSize)
}
