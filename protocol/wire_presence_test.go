package protocol

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
)

func cborIntegerFields(t *testing.T, value any) map[uint64]cbor.RawMessage {
	t.Helper()

	raw, err := cbor.Marshal(value)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fields map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return fields
}

func requireRawField[K comparable](t *testing.T, fields map[K]cbor.RawMessage, key K, want cbor.RawMessage) {
	t.Helper()

	if got := fields[key]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Fatalf("field %#v = %#v, want %#v", key, got, want)
	}
}

func TestEmptyExtensionAggregatesAreOmittedFromRequests(t *testing.T) {
	makeFields := cborIntegerFields(t, AuthenticatorMakeCredentialRequest{})
	if _, ok := makeFields[uint64(6)]; ok {
		t.Fatalf("value unexpectedly contains %#v", uint64(6))
	}

	getFields := cborIntegerFields(t, AuthenticatorGetAssertionRequest{})
	if _, ok := getFields[uint64(4)]; ok {
		t.Fatalf("value unexpectedly contains %#v", uint64(4))
	}
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
			if _, ok := absentFields[tt.memberKey]; ok {
				t.Fatalf("value unexpectedly contains %#v", tt.memberKey)
			}

			requireRawField(t, cborIntegerFields(t, tt.present), tt.memberKey, cbor.RawMessage{0x40})
		})
	}
}

func TestGetInfoPreservesOnlyPresenceSensitiveZeroValues(t *testing.T) {
	absentFields := cborIntegerFields(t, AuthenticatorGetInfoResponse{})
	for _, key := range []uint64{5, 7, 8, 11, 12, 13, 15, 17, 29} {
		if _, ok := absentFields[key]; ok {
			t.Fatalf("value unexpectedly contains %#v", key)
		}
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
		if _, ok := presentFields[key]; !ok {
			t.Fatalf("value does not contain %#v", key)
		}
	}
}

func TestPresenceSensitiveEmptyWireValuesAreEncoded(t *testing.T) {
	empty := ""
	tests := []struct {
		name  string
		value any
		key   uint64
		want  cbor.RawMessage
	}{
		{
			name: "none attestation statement",
			value: AuthenticatorMakeCredentialResponse{
				Format:               attestation.AttestationStatementFormatIdentifierNone,
				AttestationStatement: map[string]any{},
			},
			key:  3,
			want: cbor.RawMessage{0xa0},
		},
		{
			name:  "large blob EOF fragment",
			value: AuthenticatorLargeBlobsResponse{Config: []byte{}},
			key:   1,
			want:  cbor.RawMessage{0x40},
		},
		{
			name:  "empty biometric friendly name",
			value: BioEnrollmentSubCommandParams{TemplateFriendlyName: &empty},
			key:   2,
			want:  cbor.RawMessage{0x60},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireRawField(t, cborIntegerFields(t, tt.value), tt.key, tt.want)
		})
	}

	t.Run("empty user names are omitted", func(t *testing.T) {
		raw, err := cbor.Marshal(credential.PublicKeyCredentialUserEntity{ID: []byte{}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var fields map[string]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		requireRawField(t, fields, "id", cbor.RawMessage{0x40})
		if _, ok := fields["name"]; ok {
			t.Fatalf("value unexpectedly contains %#v", "name")
		}
		if _, ok := fields["displayName"]; ok {
			t.Fatalf("value unexpectedly contains %#v", "displayName")
		}
	})
}

func TestLargeBlobsRequestPreservesZeroLengthOperations(t *testing.T) {
	zero := uint(0)

	getFields := cborIntegerFields(t, AuthenticatorLargeBlobsRequest{Get: &zero})
	requireRawField(t, getFields, uint64(1), cbor.RawMessage{0x00})
	if _, ok := getFields[uint64(2)]; ok {
		t.Fatalf("value unexpectedly contains %#v", uint64(2))
	}

	setFields := cborIntegerFields(t, AuthenticatorLargeBlobsRequest{Set: []byte{}})
	if _, ok := setFields[uint64(1)]; ok {
		t.Fatalf("value unexpectedly contains %#v", uint64(1))
	}
	requireRawField(t, setFields, uint64(2), cbor.RawMessage{0x40})
}

func TestConditionalResponseMembersAreOmittedWhenAbsent(t *testing.T) {
	if got := cborIntegerFields(t, AuthenticatorClientPINResponse{}); len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
	if got := cborIntegerFields(t, AuthenticatorCredentialManagementResponse{}); len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	assertionFields := cborIntegerFields(t, AuthenticatorGetAssertionResponse{})
	if _, ok := assertionFields[uint64(1)]; ok {
		t.Fatalf("value unexpectedly contains %#v; context: %s", uint64(1), "CTAP 2.0 permits credential to be omitted")
	}
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
		if _, ok := clientPINFields[key]; !ok {
			t.Fatalf("value does not contain %#v", key)
		}
	}

	goodSample := LastEnrollSampleStatus(0)
	bioFields := cborIntegerFields(t, AuthenticatorBioEnrollmentResponse{
		LastEnrollSampleStatus: &goodSample,
		RemainingSamples:       &zero,
	})
	for _, key := range []uint64{5, 6} {
		requireRawField(t, bioFields, key, cbor.RawMessage{0x00})
	}

	raw, err := cbor.Marshal(GetExtensionOutputs{
		GetCredBlobOutput: GetCredBlobOutput{CredBlob: []byte{}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var extensionFields map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &extensionFields); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireRawField(t, extensionFields, "credBlob", cbor.RawMessage{0x40})
}
