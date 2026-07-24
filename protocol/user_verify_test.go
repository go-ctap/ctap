package protocol

import "testing"

func TestUserVerifyValuesMatchFIDORegistry(t *testing.T) {
	tests := []struct {
		method UserVerify
		want   UserVerify
	}{
		{UserVerifyPresenceInternal, 0x00000001},
		{UserVerifyFingerprintInternal, 0x00000002},
		{UserVerifyPasscodeInternal, 0x00000004},
		{UserVerifyVoiceprintInternal, 0x00000008},
		{UserVerifyFaceprintInternal, 0x00000010},
		{UserVerifyLocationInternal, 0x00000020},
		{UserVerifyEyeprintInternal, 0x00000040},
		{UserVerifyPatternInternal, 0x00000080},
		{UserVerifyHandprintInternal, 0x00000100},
		{UserVerifyNone, 0x00000200},
		{UserVerifyAll, 0x00000400},
		{UserVerifyPasscodeExternal, 0x00000800},
		{UserVerifyPatternExternal, 0x00001000},
	}

	for _, tt := range tests {
		if tt.method != tt.want {
			t.Errorf("UserVerify value = %#08x, want %#08x", tt.method, tt.want)
		}
	}
}

func TestUserVerifyString(t *testing.T) {
	tests := []struct {
		modality UserVerify
		want     string
	}{
		{0, ""},
		{UserVerifyPresenceInternal, "presence_internal"},
		{UserVerifyFingerprintInternal, "fingerprint_internal"},
		{UserVerifyPasscodeInternal, "passcode_internal"},
		{UserVerifyVoiceprintInternal, "voiceprint_internal"},
		{UserVerifyFaceprintInternal, "faceprint_internal"},
		{UserVerifyLocationInternal, "location_internal"},
		{UserVerifyEyeprintInternal, "eyeprint_internal"},
		{UserVerifyPatternInternal, "pattern_internal"},
		{UserVerifyHandprintInternal, "handprint_internal"},
		{UserVerifyPasscodeExternal, "passcode_external"},
		{UserVerifyPatternExternal, "pattern_external"},
		{UserVerifyNone, "none"},
		{UserVerifyAll, "all"},
		{
			UserVerifyPresenceInternal |
				UserVerifyFingerprintInternal |
				UserVerifyPasscodeExternal,
			"presence_internal,fingerprint_internal,passcode_external",
		},
		{UserVerify(0x2000), "unknown(0x2000)"},
		{
			UserVerifyFingerprintInternal | UserVerify(0x2000),
			"fingerprint_internal,unknown(0x2000)",
		},
	}

	for _, tt := range tests {
		if got := tt.modality.String(); got != tt.want {
			t.Errorf("UserVerify(%#x).String() = %q, want %q", tt.modality, got, tt.want)
		}
	}
}
