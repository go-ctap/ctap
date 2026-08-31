package protocol

import (
	"bytes"
	"fmt"
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

func TestEmptyExtensionAggregatesAreOmittedFromRequests(t *testing.T) {
	makeFields := cborIntegerFields(t, AuthenticatorMakeCredentialRequest{})
	{
		container, element := makeFields, uint64(6)
		_, ok := container[element]
		if ok {
			t.Fatalf("value unexpectedly contains %#v", element)
		}
	}

	getFields := cborIntegerFields(t, AuthenticatorGetAssertionRequest{})
	{
		container, element := getFields, uint64(4)
		_, ok := container[element]
		if ok {
			t.Fatalf("value unexpectedly contains %#v", element)
		}
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
			{
				container, element := absentFields, tt.memberKey
				_, ok := container[element]
				if ok {
					t.Fatalf("value unexpectedly contains %#v", element)
				}
			}

			presentFields := cborIntegerFields(t, tt.present)
			{
				want, got := cbor.RawMessage{0x40}, presentFields[tt.memberKey]
				if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			}
		})
	}
}

func TestGetInfoPreservesOnlyPresenceSensitiveZeroValues(t *testing.T) {
	absentFields := cborIntegerFields(t, AuthenticatorGetInfoResponse{})
	for _, key := range []uint64{5, 7, 8, 11, 12, 13, 15, 17, 29} {
		{
			container, element := absentFields, key
			_, ok := container[element]
			if ok {
				t.Fatalf("value unexpectedly contains %#v", element)
			}
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
		{
			container, element := presentFields, key
			_, ok := container[element]
			if !ok {
				t.Fatalf("value does not contain %#v", element)
			}
		}
	}
}

func TestPresenceSensitiveEmptyWireValuesAreEncoded(t *testing.T) {
	t.Run("none attestation statement", func(t *testing.T) {
		fields := cborIntegerFields(t, AuthenticatorMakeCredentialResponse{
			Format:               attestation.AttestationStatementFormatIdentifierNone,
			AttestationStatement: map[string]any{},
		})
		{
			want, got := cbor.RawMessage{0xa0}, fields[3]
			if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		}
	})

	t.Run("large blob EOF fragment", func(t *testing.T) {
		fields := cborIntegerFields(t, AuthenticatorLargeBlobsResponse{Config: []byte{}})
		{
			want, got := cbor.RawMessage{0x40}, fields[1]
			if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		}
	})

	t.Run("empty biometric friendly name", func(t *testing.T) {
		empty := ""
		fields := cborIntegerFields(t, BioEnrollmentSubCommandParams{TemplateFriendlyName: &empty})
		{
			want, got := cbor.RawMessage{0x60}, fields[2]
			if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		}
	})

	t.Run("empty user names are omitted", func(t *testing.T) {
		raw, err := cbor.Marshal(credential.PublicKeyCredentialUserEntity{ID: []byte{}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var fields map[string]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		{
			want, got := cbor.RawMessage{0x40}, fields["id"]
			if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		}
		{
			container, element := fields, "name"
			_, ok := container[element]
			if ok {
				t.Fatalf("value unexpectedly contains %#v", element)
			}
		}
		{
			container, element := fields, "displayName"
			_, ok := container[element]
			if ok {
				t.Fatalf("value unexpectedly contains %#v", element)
			}
		}
	})
}

func TestLargeBlobsRequestPreservesZeroLengthOperations(t *testing.T) {
	zero := uint(0)

	getFields := cborIntegerFields(t, AuthenticatorLargeBlobsRequest{Get: &zero})
	{
		want, got := cbor.RawMessage{0x00}, getFields[1]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	{
		container, element := getFields, uint64(2)
		_, ok := container[element]
		if ok {
			t.Fatalf("value unexpectedly contains %#v", element)
		}
	}

	setFields := cborIntegerFields(t, AuthenticatorLargeBlobsRequest{Set: []byte{}})
	{
		container, element := setFields, uint64(1)
		_, ok := container[element]
		if ok {
			t.Fatalf("value unexpectedly contains %#v", element)
		}
	}
	{
		want, got := cbor.RawMessage{0x40}, setFields[2]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestConditionalResponseMembersAreOmittedWhenAbsent(t *testing.T) {
	if got := cborIntegerFields(t, AuthenticatorClientPINResponse{}); len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
	if got := cborIntegerFields(t, AuthenticatorCredentialManagementResponse{}); len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}

	assertionFields := cborIntegerFields(t, AuthenticatorGetAssertionResponse{})
	{
		container, element := assertionFields, uint64(1)
		_, ok := container[element]
		if ok {
			t.Fatalf("value unexpectedly contains %#v; context: %s", element, fmt.Sprint("CTAP 2.0 permits credential to be omitted"))
		}
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
		{
			container, element := clientPINFields, key
			_, ok := container[element]
			if !ok {
				t.Fatalf("value does not contain %#v", element)
			}
		}
	}

	goodSample := LastEnrollSampleStatus(0)
	bioFields := cborIntegerFields(t, AuthenticatorBioEnrollmentResponse{
		LastEnrollSampleStatus: &goodSample,
		RemainingSamples:       &zero,
	})
	{
		want, got := cbor.RawMessage{0x00}, bioFields[5]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := cbor.RawMessage{0x00}, bioFields[6]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
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
	{
		want, got := cbor.RawMessage{0x40}, extensionFields["credBlob"]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}
