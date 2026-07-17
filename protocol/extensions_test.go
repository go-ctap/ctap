package protocol

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
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
				CreateLargeBlobKeyInput: &CreateLargeBlobKeyInput{LargeBlobKey: true},
			},
		},
		{
			name: "GetAssertion",
			input: GetExtensionInputs{
				GetLargeBlobKeyInput: &GetLargeBlobKeyInput{LargeBlobKey: true},
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
