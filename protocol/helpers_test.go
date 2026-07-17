package protocol

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorGetInfoResponsePreservesOptionalScalarPresence(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{
		4:  map[string]bool{string(OptionClientPIN): false},
		5:  uint64(0),
		12: false,
	})
	require.NoError(t, err)

	var resp AuthenticatorGetInfoResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))

	require.NotNil(t, resp.MaxMsgSize)
	require.Equal(t, uint(0), *resp.MaxMsgSize)
	require.NotNil(t, resp.ForcePINChange)
	require.False(t, *resp.ForcePINChange)

	clientPIN, ok := resp.Options[OptionClientPIN]
	require.True(t, ok)
	require.False(t, clientPIN)

	_, ok = resp.Options[OptionUserVerification]
	require.False(t, ok)
	require.Nil(t, resp.MinPINLength)
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
		MaxMsgSize:                  &zero,
		PreferredPlatformUvAttempts: &zero,
		UvModality:                  (*UserVerify)(&zero),
		UvCountSinceLastPinEntry:    &zero,
		LongTouchForReset:           &disabled,
		PinComplexityPolicy:         &disabled,
	})
	require.NoError(t, err)

	text = string(raw)
	for _, presentValue := range []string{
		`"maxMsgSize":0`,
		`"preferredPlatformUvAttempts":0`,
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

	resp.MaxMsgSize = lo.ToPtr(uint(2048))
	resp.MinPINLength = lo.ToPtr(uint(8))
	resp.MaxPINLength = lo.ToPtr(uint(48))

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
	require.Nil(t, resp.MaxPINLength)
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
	require.Equal(t, uint(0), *resp.TotalRPs)
	require.Equal(t, uint(0), *resp.TotalCredentials)
	require.Equal(t, uint(0), *resp.CredProtect)
	require.False(t, *resp.ThirdPartyPayment)

	raw, err = cbor.Marshal(AuthenticatorCredentialManagementResponse{})
	require.NoError(t, err)
	var fields map[uint64]any
	require.NoError(t, cbor.Unmarshal(raw, &fields))
	for _, key := range []uint64{1, 2, 5, 9, 10, 12} {
		require.NotContains(t, fields, key)
	}
}

func TestMakeCredentialEnterpriseAttestationPreservesFalsePresence(t *testing.T) {
	raw, err := cbor.Marshal(map[uint64]any{4: false})
	require.NoError(t, err)

	var resp AuthenticatorMakeCredentialResponse
	require.NoError(t, cbor.Unmarshal(raw, &resp))
	require.NotNil(t, resp.EnterpriseAttestation)
	require.False(t, *resp.EnterpriseAttestation)

	var absent AuthenticatorMakeCredentialResponse
	require.NoError(t, cbor.Unmarshal([]byte{0xa0}, &absent))
	require.Nil(t, absent.EnterpriseAttestation)
}

func TestAuthenticatorGetInfoResponseMaxCredBlobLengthPresence(t *testing.T) {
	var resp AuthenticatorGetInfoResponse
	value, ok := resp.MaxCredBlobLengthValue()
	require.False(t, ok)
	require.Equal(t, uint(0), value)

	resp.MaxCredBlobLength = lo.ToPtr(uint(0))
	value, ok = resp.MaxCredBlobLengthValue()
	require.True(t, ok)
	require.Equal(t, uint(0), value)
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
