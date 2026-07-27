package protocol

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorGetInfoResponseUsesZeroSentinelsForEquivalentOrInvalidValues(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		4:  map[string]bool{string(OptionClientPIN): false},
		5:  uint64(0),
		12: false,
	})
	require.NoError(t, err)

	var resp AuthenticatorGetInfoResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))

	require.Zero(t, resp.MaxMsgSize)
	require.False(t, resp.ForcePINChange)

	clientPIN, ok := resp.Options[OptionClientPIN]
	require.True(t, ok)
	require.False(t, clientPIN)

	_, ok = resp.Options[OptionUserVerification]
	require.False(t, ok)
	require.Zero(t, resp.MinPINLength)
	require.Nil(t, resp.LongTouchForReset)
}

func TestAuthenticatorGetInfoResponseOmitsAbsentOptionalScalarsJSON(t *testing.T) {
	raw, err := json.Marshal(AuthenticatorGetInfoResponse{})
	require.NoError(t, err)

	text := string(raw)
	for _, absentField := range []string{
		"maxMsgSize",
		"forcePINChange",
		"preferredPlatformUvAttempts",
		"uvModality",
		"uvCountSinceLastPinEntry",
		"longTouchForReset",
		"pinComplexityPolicy",
		"pinComplexityPolicyURL",
		"maxPINLength",
		"encCredStoreState",
	} {
		require.NotContains(t, text, absentField)
	}

	zero := uint(0)
	disabled := false
	raw, err = json.Marshal(AuthenticatorGetInfoResponse{
		UvModality:               (*UserVerify)(&zero),
		UvCountSinceLastPinEntry: &zero,
		LongTouchForReset:        &disabled,
		PinComplexityPolicy:      &disabled,
	})
	require.NoError(t, err)

	text = string(raw)
	for _, presentValue := range []string{
		`"uvModality":0`,
		`"uvCountSinceLastPinEntry":0`,
		`"longTouchForReset":false`,
		`"pinComplexityPolicy":false`,
	} {
		require.Contains(t, text, presentValue)
	}
}

func TestAuthenticatorGetInfoResponseEffectiveDefaults(t *testing.T) {
	var resp AuthenticatorGetInfoResponse
	require.Equal(t, DefaultMaxMsgSize, resp.EffectiveMaxMsgSize())
	require.Equal(t, DefaultMinPINCodePoints, resp.EffectiveMinPINLength())
	require.Equal(t, DefaultMaxPINCodePoints, resp.EffectiveMaxPINLength())

	resp.MaxMsgSize = 2048
	resp.MinPINLength = 8
	resp.MaxPINLength = 48

	require.Equal(t, uint(2048), resp.EffectiveMaxMsgSize())
	require.Equal(t, uint(8), resp.EffectiveMinPINLength())
	require.Equal(t, uint(48), resp.EffectiveMaxPINLength())
}

func TestAuthenticatorGetInfoResponseCTAP23TypedFields(t *testing.T) {
	policyURL := []byte("https://example.com/pin-policy")
	raw, err := cbor.Marshal(map[uint64]any{
		1:  []string{"FIDO_2_3"},
		9:  []string{"usb", "future-transport"},
		21: []uint64{math.MaxUint64},
		22: []string{"packed"},
		26: []string{"nfc"},
		28: policyURL,
		31: []uint64{uint64(ConfigSubCommandSetMinPINLength)},
	})
	require.NoError(t, err)

	var resp AuthenticatorGetInfoResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))
	require.Equal(t, []credential.AuthenticatorTransport{
		credential.AuthenticatorTransportUSB,
		credential.AuthenticatorTransport("future-transport"),
	}, resp.Transports)
	require.Equal(t, []credential.AuthenticatorTransport{credential.AuthenticatorTransportNFC}, resp.TransportsForReset)
	require.Equal(t, []VendorCommandID{VendorCommandID(math.MaxUint64)}, resp.VendorPrototypeConfigCommands)
	require.Equal(t, []attestation.AttestationStatementFormatIdentifier{
		attestation.AttestationStatementFormatIdentifierPacked,
	}, resp.AttestationFormats)
	require.Equal(t, []ConfigSubCommand{ConfigSubCommandSetMinPINLength}, resp.AuthenticatorConfigCommands)
	require.Equal(t, policyURL, resp.PinComplexityPolicyURL)
	require.Equal(t, string(policyURL), resp.PinComplexityPolicyURLString())
}

func TestAuthenticatorGetInfoResponseEncodesConfigCommandsAsArray(t *testing.T) {
	resp := AuthenticatorGetInfoResponse{
		AuthenticatorConfigCommands: []ConfigSubCommand{
			ConfigSubCommandToggleAlwaysUv,
			ConfigSubCommandSetMinPINLength,
		},
	}

	raw, err := cbor.Marshal(resp)
	require.NoError(t, err)

	var fields map[uint64]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(raw, &fields))
	require.NotEmpty(t, fields[31])
	require.Equal(t, byte(0x80), fields[31][0]&0xe0, "authenticatorConfigCommands must be a CBOR array")

	var commands []uint64
	require.NoError(t, cbor.Unmarshal(fields[31], &commands))
	require.Equal(t, []uint64{2, 3}, commands)

	raw, err = json.Marshal(resp)
	require.NoError(t, err)

	var jsonFields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &jsonFields))
	require.JSONEq(t, `[2, 3]`, string(jsonFields["authenticatorConfigCommands"]))
}

func TestAuthenticatorGetInfoResponseDecodesFIDO20WithoutNewFields(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		1: []string{"FIDO_2_0"},
		4: map[string]bool{string(OptionResidentKeys): false},
	})
	require.NoError(t, err)

	var resp AuthenticatorGetInfoResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))
	require.Equal(t, Versions{FIDO_2_0}, resp.Versions)
	require.Zero(t, resp.MaxPINLength)
	require.Nil(t, resp.AuthenticatorConfigCommands)
	require.Empty(t, resp.PinComplexityPolicyURLString())
	require.Equal(t, DefaultMaxPINCodePoints, resp.EffectiveMaxPINLength())
}

func TestCredentialManagementOptionalScalarsPreservePresence(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		1:  uint64(0),
		2:  uint64(0),
		5:  uint64(0),
		9:  uint64(0),
		10: uint64(0),
		12: false,
	})
	require.NoError(t, err)

	var resp AuthenticatorCredentialManagementResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))
	require.Equal(t, uint(0), *resp.ExistingResidentCredentialsCount)
	require.Equal(t, uint(0), *resp.MaxPossibleRemainingResidentCredentialsCount)
	require.Zero(t, resp.TotalRPs)
	require.Zero(t, resp.TotalCredentials)
	require.Zero(t, resp.CredProtect)
	require.False(t, *resp.ThirdPartyPayment)

	raw, err = cbor.Marshal(AuthenticatorCredentialManagementResponse{})
	require.NoError(t, err)
	var fields map[uint64]any
	require.NoError(t, cbor.Unmarshal(raw, &fields))
	for _, key := range []uint64{1, 2, 5, 9, 10, 12} {
		require.NotContains(t, fields, key)
	}
}

func TestMakeCredentialEnterpriseAttestationTreatsFalseAsAbsent(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{4: false})
	require.NoError(t, err)

	var resp AuthenticatorMakeCredentialResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))
	require.False(t, resp.EnterpriseAttestation)

	var absent AuthenticatorMakeCredentialResponse
	require.NoError(t, cbor.Unmarshal([]byte{0xa0}, &absent))
	require.False(t, absent.EnterpriseAttestation)
}

func TestAttestationStatementAccessorsAcceptNormativeWireShapes(t *testing.T) {
	t.Run("packed self attestation omits x5c", func(t *testing.T) {
		resp := AuthenticatorMakeCredentialResponse{AttestationStatement: map[string]any{
			"alg": int64(-7),
			"sig": []byte{1, 2, 3},
		}}

		statement, ok := resp.PackedAttestationStatementFormat()
		require.True(t, ok)
		require.Nil(t, statement.X509Chain)
	})

	t.Run("FIDO U2F accepts generic decoded x5c array", func(t *testing.T) {
		certificate := []byte{1, 2, 3}
		resp := AuthenticatorMakeCredentialResponse{AttestationStatement: map[string]any{
			"x5c": []any{certificate},
			"sig": []byte{4, 5, 6},
		}}

		statement, ok := resp.FIDOU2FAttestationStatementFormat()
		require.True(t, ok)
		require.Equal(t, [][]byte{certificate}, statement.X509Chain)
	})

	t.Run("TPM does not require non-standard aikCert", func(t *testing.T) {
		certificate := []byte{1, 2, 3}
		resp := AuthenticatorMakeCredentialResponse{AttestationStatement: map[string]any{
			"ver":      "2.0",
			"alg":      int64(-7),
			"x5c":      []any{certificate},
			"sig":      []byte{4},
			"certInfo": []byte{5},
			"pubArea":  []byte{6},
		}}

		statement, ok := resp.TPMAttestationStatementFormat()
		require.True(t, ok)
		require.Equal(t, [][]byte{certificate}, statement.X509Chain)
	})
}

func TestAuthenticatorGetInfoResponseMaxCredBlobLengthPresence(t *testing.T) {
	var resp AuthenticatorGetInfoResponse
	value, ok := resp.MaxCredBlobLengthValue()
	require.False(t, ok)
	require.Equal(t, uint(0), value)

	resp.MaxCredBlobLength = 32
	value, ok = resp.MaxCredBlobLengthValue()
	require.True(t, ok)
	require.Equal(t, uint(32), value)
}

func TestParseGetAssertionAuthDataRejectsShortData(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		make([]byte, 36),
	} {
		_, err := ParseGetAssertionAuthData(data)
		require.Error(t, err)
	}
}

func TestParseMakeCredentialAuthDataRejectsTruncatedAttestedCredentialData(t *testing.T) {
	data := make([]byte, 37)
	data[32] = byte(AuthDataFlagAttestedCredentialDataIncluded)

	_, err := ParseMakeCredentialAuthData(data)
	require.Error(t, err)

	data = append(data, make([]byte, 16)...)
	_, err = ParseMakeCredentialAuthData(data)
	require.Error(t, err)

	data = append(data, 0, 2, 0x01)
	_, err = ParseMakeCredentialAuthData(data)
	require.Error(t, err)
}

func TestParseAuthDataRejectsMissingOrNonMapExtensionData(t *testing.T) {
	for _, suffix := range [][]byte{
		nil,
		{0xf6}, // null
		{0x80}, // array
	} {
		data := make([]byte, 37)
		data[32] = byte(AuthDataFlagExtensionDataIncluded)
		data = append(data, suffix...)

		_, err := ParseMakeCredentialAuthData(data)
		require.Error(t, err)

		_, err = ParseGetAssertionAuthData(data)
		require.Error(t, err)
	}
}

func TestParseAuthDataRejectsTrailingBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "without extension flag",
			data: append(make([]byte, 37), 0x00),
		},
		{
			name: "after extension map",
			data: func() []byte {
				data := make([]byte, 37)
				data[32] = byte(AuthDataFlagExtensionDataIncluded)

				return append(data, 0xa0, 0x00)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseMakeCredentialAuthData(test.data)
			require.Error(t, err)

			_, err = ParseGetAssertionAuthData(test.data)
			require.Error(t, err)
		})
	}
}

func TestParseAuthDataRejectsReservedFlags(t *testing.T) {
	for _, flag := range []byte{1 << 1, 1 << 5} {
		data := make([]byte, 37)
		data[32] = flag

		_, err := ParseGetAssertionAuthData(data)
		require.Error(t, err, "reserved flag 0x%02x", flag)
	}
}
