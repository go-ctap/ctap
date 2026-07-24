package protocol

import "testing"

func TestLastEnrollSampleStatusValuesMatchCTAP23(t *testing.T) {
	tests := []struct {
		status LastEnrollSampleStatus
		want   LastEnrollSampleStatus
	}{
		{LastEnrollSampleStatusFingerprintGood, 0x00},
		{LastEnrollSampleStatusFingerprintTooHigh, 0x01},
		{LastEnrollSampleStatusFingerprintTooLow, 0x02},
		{LastEnrollSampleStatusFingerprintTooLeft, 0x03},
		{LastEnrollSampleStatusFingerprintTooRight, 0x04},
		{LastEnrollSampleStatusFingerprintTooFast, 0x05},
		{LastEnrollSampleStatusFingerprintTooSlow, 0x06},
		{LastEnrollSampleStatusFingerprintPoorQuality, 0x07},
		{LastEnrollSampleStatusFingerprintTooSkewed, 0x08},
		{LastEnrollSampleStatusFingerprintTooShort, 0x09},
		{LastEnrollSampleStatusFingerprintMergeFailure, 0x0a},
		{LastEnrollSampleStatusFingerprintExists, 0x0b},
		{LastEnrollSampleStatusNoUserActivity, 0x0d},
		{LastEnrollSampleStatusNoUserPresenceTransition, 0x0e},
	}

	for _, tt := range tests {
		if tt.status != tt.want {
			t.Errorf("LastEnrollSampleStatus value = %#02x, want %#02x", tt.status, tt.want)
		}
	}
}

func TestLastEnrollSampleStatusString(t *testing.T) {
	tests := []struct {
		status LastEnrollSampleStatus
		want   string
	}{
		{LastEnrollSampleStatusFingerprintGood, "CTAP2_ENROLL_FEEDBACK_FP_GOOD"},
		{LastEnrollSampleStatusFingerprintTooHigh, "CTAP2_ENROLL_FEEDBACK_FP_TOO_HIGH"},
		{LastEnrollSampleStatusFingerprintTooLow, "CTAP2_ENROLL_FEEDBACK_FP_TOO_LOW"},
		{LastEnrollSampleStatusFingerprintTooLeft, "CTAP2_ENROLL_FEEDBACK_FP_TOO_LEFT"},
		{LastEnrollSampleStatusFingerprintTooRight, "CTAP2_ENROLL_FEEDBACK_FP_TOO_RIGHT"},
		{LastEnrollSampleStatusFingerprintTooFast, "CTAP2_ENROLL_FEEDBACK_FP_TOO_FAST"},
		{LastEnrollSampleStatusFingerprintTooSlow, "CTAP2_ENROLL_FEEDBACK_FP_TOO_SLOW"},
		{LastEnrollSampleStatusFingerprintPoorQuality, "CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY"},
		{LastEnrollSampleStatusFingerprintTooSkewed, "CTAP2_ENROLL_FEEDBACK_FP_TOO_SKEWED"},
		{LastEnrollSampleStatusFingerprintTooShort, "CTAP2_ENROLL_FEEDBACK_FP_TOO_SHORT"},
		{LastEnrollSampleStatusFingerprintMergeFailure, "CTAP2_ENROLL_FEEDBACK_FP_MERGE_FAILURE"},
		{LastEnrollSampleStatusFingerprintExists, "CTAP2_ENROLL_FEEDBACK_FP_EXISTS"},
		{LastEnrollSampleStatusNoUserActivity, "CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY"},
		{LastEnrollSampleStatusNoUserPresenceTransition, "CTAP2_ENROLL_FEEDBACK_NO_USER_PRESENCE_TRANSITION"},
		{LastEnrollSampleStatus(0x0c), "unknown(0x0c)"},
		{LastEnrollSampleStatus(0xff), "unknown(0xff)"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("LastEnrollSampleStatus(%#02x).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}
