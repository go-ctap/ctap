package protocol

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/extension"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
