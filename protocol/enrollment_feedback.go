package protocol

import "fmt"

// String returns the symbolic CTAP name of s.
func (s LastEnrollSampleStatus) String() string {
	switch s {
	case LastEnrollSampleStatusFingerprintGood:
		return "CTAP2_ENROLL_FEEDBACK_FP_GOOD"
	case LastEnrollSampleStatusFingerprintTooHigh:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_HIGH"
	case LastEnrollSampleStatusFingerprintTooLow:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_LOW"
	case LastEnrollSampleStatusFingerprintTooLeft:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_LEFT"
	case LastEnrollSampleStatusFingerprintTooRight:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_RIGHT"
	case LastEnrollSampleStatusFingerprintTooFast:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_FAST"
	case LastEnrollSampleStatusFingerprintTooSlow:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_SLOW"
	case LastEnrollSampleStatusFingerprintPoorQuality:
		return "CTAP2_ENROLL_FEEDBACK_FP_POOR_QUALITY"
	case LastEnrollSampleStatusFingerprintTooSkewed:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_SKEWED"
	case LastEnrollSampleStatusFingerprintTooShort:
		return "CTAP2_ENROLL_FEEDBACK_FP_TOO_SHORT"
	case LastEnrollSampleStatusFingerprintMergeFailure:
		return "CTAP2_ENROLL_FEEDBACK_FP_MERGE_FAILURE"
	case LastEnrollSampleStatusFingerprintExists:
		return "CTAP2_ENROLL_FEEDBACK_FP_EXISTS"
	case LastEnrollSampleStatusNoUserActivity:
		return "CTAP2_ENROLL_FEEDBACK_NO_USER_ACTIVITY"
	case LastEnrollSampleStatusNoUserPresenceTransition:
		return "CTAP2_ENROLL_FEEDBACK_NO_USER_PRESENCE_TRANSITION"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint(s))
	}
}
