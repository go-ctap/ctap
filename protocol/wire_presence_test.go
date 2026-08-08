package protocol

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/stretchr/testify/require"
)

func cborIntegerFields(t *testing.T, value any) map[uint64]cbor.RawMessage {
	t.Helper()

	raw, err := cbor.Marshal(value)
	require.NoError(t, err)

	var fields map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(raw, &fields))
	return fields
}

func TestEmptyExtensionAggregatesAreOmittedFromRequests(t *testing.T) {
	makeFields := cborIntegerFields(t, AuthenticatorMakeCredentialRequest{})
	require.NotContains(t, makeFields, uint64(6))

	getFields := cborIntegerFields(t, AuthenticatorGetAssertionRequest{})
	require.NotContains(t, getFields, uint64(4))
}

func TestZeroLengthPinUvAuthParamPreservesPresence(t *testing.T) {
	tests := []struct {
		name      string
		absent    any
		present   any
		memberKey uint64
	}{
		{
			name:      "MakeCredential",
			absent:    AuthenticatorMakeCredentialRequest{},
			present:   AuthenticatorMakeCredentialRequest{PinUvAuthParam: []byte{}},
			memberKey: 8,
		},
		{
			name:      "GetAssertion",
			absent:    AuthenticatorGetAssertionRequest{},
			present:   AuthenticatorGetAssertionRequest{PinUvAuthParam: []byte{}},
			memberKey: 6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absentFields := cborIntegerFields(t, tt.absent)
			require.NotContains(t, absentFields, tt.memberKey)

			presentFields := cborIntegerFields(t, tt.present)
			require.Equal(t, cbor.RawMessage{0x40}, presentFields[tt.memberKey])
		})
	}
}

func TestGetInfoPreservesOnlyPresenceSensitiveZeroValues(t *testing.T) {
	absentFields := cborIntegerFields(t, AuthenticatorGetInfoResponse{})
	for _, key := range []uint64{5, 7, 8, 11, 12, 13, 15, 17, 29} {
		require.NotContains(t, absentFields, key)
	}

	zero := uint(0)
	disabled := false
	presentFields := cborIntegerFields(t, AuthenticatorGetInfoResponse{
		MaxRPIDsForSetMinPINLength:       &zero,
		RemainingDiscoverableCredentials: &zero,
		VendorPrototypeConfigCommands:    []VendorCommandID{},
		UvCountSinceLastPinEntry:         &zero,
		LongTouchForReset:                &disabled,
		PinComplexityPolicy:              &disabled,
		AuthenticatorConfigCommands:      []ConfigSubCommand{},
	})
	for _, key := range []uint64{16, 20, 21, 23, 24, 27, 31} {
		require.Contains(t, presentFields, key)
	}
}

func TestPresenceSensitiveEmptyWireValuesAreEncoded(t *testing.T) {
	t.Run("none attestation statement", func(t *testing.T) {
		fields := cborIntegerFields(t, AuthenticatorMakeCredentialResponse{
			Format:               attestation.AttestationStatementFormatIdentifierNone,
			AttestationStatement: map[string]any{},
		})
		require.Equal(t, cbor.RawMessage{0xa0}, fields[3])
	})

	t.Run("large blob EOF fragment", func(t *testing.T) {
		fields := cborIntegerFields(t, AuthenticatorLargeBlobsResponse{Config: []byte{}})
		require.Equal(t, cbor.RawMessage{0x40}, fields[1])
	})

	t.Run("empty biometric friendly name", func(t *testing.T) {
		empty := ""
		fields := cborIntegerFields(t, BioEnrollmentSubCommandParams{TemplateFriendlyName: &empty})
		require.Equal(t, cbor.RawMessage{0x60}, fields[2])
	})

	t.Run("empty user names are omitted", func(t *testing.T) {
		raw, err := cbor.Marshal(credential.PublicKeyCredentialUserEntity{ID: []byte{}})
		require.NoError(t, err)

		var fields map[string]cbor.RawMessage
		require.NoError(t, cbor.Unmarshal(raw, &fields))
		require.Equal(t, cbor.RawMessage{0x40}, fields["id"])
		require.NotContains(t, fields, "name")
		require.NotContains(t, fields, "displayName")
	})
}

func TestLargeBlobsRequestPreservesZeroLengthOperations(t *testing.T) {
	zero := uint(0)

	getFields := cborIntegerFields(t, AuthenticatorLargeBlobsRequest{Get: &zero})
	require.Equal(t, cbor.RawMessage{0x00}, getFields[1])
	require.NotContains(t, getFields, uint64(2))

	setFields := cborIntegerFields(t, AuthenticatorLargeBlobsRequest{Set: []byte{}})
	require.NotContains(t, setFields, uint64(1))
	require.Equal(t, cbor.RawMessage{0x40}, setFields[2])
}

func TestConditionalResponseMembersAreOmittedWhenAbsent(t *testing.T) {
	require.Empty(t, cborIntegerFields(t, AuthenticatorClientPINResponse{}))
	require.Empty(t, cborIntegerFields(t, AuthenticatorCredentialManagementResponse{}))

	assertionFields := cborIntegerFields(t, AuthenticatorGetAssertionResponse{})
	require.NotContains(t, assertionFields, uint64(1), "CTAP 2.0 permits credential to be omitted")
}

func TestPresenceSensitiveZeroResponseMembersAreEncoded(t *testing.T) {
	zero := uint(0)
	disabled := false

	clientPINFields := cborIntegerFields(t, AuthenticatorClientPINResponse{
		PinRetries:      &zero,
		PowerCycleState: &disabled,
		UvRetries:       &zero,
	})
	for _, key := range []uint64{3, 4, 5} {
		require.Contains(t, clientPINFields, key)
	}

	goodSample := LastEnrollSampleStatus(0)
	bioFields := cborIntegerFields(t, AuthenticatorBioEnrollmentResponse{
		LastEnrollSampleStatus: &goodSample,
		RemainingSamples:       &zero,
	})
	require.Equal(t, cbor.RawMessage{0x00}, bioFields[5])
	require.Equal(t, cbor.RawMessage{0x00}, bioFields[6])

	raw, err := cbor.Marshal(GetExtensionOutputs{
		GetCredBlobOutput: GetCredBlobOutput{CredBlob: []byte{}},
	})
	require.NoError(t, err)
	var extensionFields map[string]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(raw, &extensionFields))
	require.Equal(t, cbor.RawMessage{0x40}, extensionFields["credBlob"])
}
