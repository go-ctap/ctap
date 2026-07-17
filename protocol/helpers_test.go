package protocol

import (
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

	resp.MaxMsgSize = lo.ToPtr(uint(2048))
	resp.MinPINLength = lo.ToPtr(uint(8))

	require.Equal(t, uint(2048), resp.EffectiveMaxMsgSize())
	require.Equal(t, uint(8), resp.EffectiveMinPINLength())
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
