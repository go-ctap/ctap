package protocol

import "testing"

func TestPermissionString(t *testing.T) {
	tests := []struct {
		permission Permission
		want       string
	}{
		{PermissionNone, "none"},
		{PermissionMakeCredential, "mc"},
		{PermissionGetAssertion, "ga"},
		{PermissionCredentialManagement, "cm"},
		{PermissionBioEnrollment, "be"},
		{PermissionLargeBlobWrite, "lbw"},
		{PermissionAuthenticatorConfiguration, "acfg"},
		{PermissionPersistentCredentialManagementReadOnly, "pcmr"},
		{
			PermissionMakeCredential |
				PermissionGetAssertion |
				PermissionCredentialManagement |
				PermissionBioEnrollment |
				PermissionLargeBlobWrite |
				PermissionAuthenticatorConfiguration,
			"mc,ga,cm,be,lbw,acfg",
		},
		{
			PermissionCredentialManagement | PermissionLargeBlobWrite,
			"cm,lbw",
		},
		{Permission(0x80), "unknown(0x80)"},
		{
			PermissionCredentialManagement | Permission(0x80),
			"cm,unknown(0x80)",
		},
	}

	for _, tt := range tests {
		if got := tt.permission.String(); got != tt.want {
			t.Errorf("Permission(%#02x).String() = %q, want %q", tt.permission, got, tt.want)
		}
	}
}
