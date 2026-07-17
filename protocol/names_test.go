package protocol

import "testing"

func TestProtocolNames(t *testing.T) {
	commands := []struct {
		value Command
		name  string
	}{
		{AuthenticatorMakeCredential, "authenticatorMakeCredential"},
		{AuthenticatorGetAssertion, "authenticatorGetAssertion"},
		{AuthenticatorGetNextAssertion, "authenticatorGetNextAssertion"},
		{AuthenticatorGetInfo, "authenticatorGetInfo"},
		{AuthenticatorClientPIN, "authenticatorClientPIN"},
		{AuthenticatorReset, "authenticatorReset"},
		{AuthenticatorBioEnrollment, "authenticatorBioEnrollment"},
		{AuthenticatorCredentialManagement, "authenticatorCredentialManagement"},
		{AuthenticatorSelection, "authenticatorSelection"},
		{AuthenticatorLargeBlobs, "authenticatorLargeBlobs"},
		{AuthenticatorConfig, "authenticatorConfig"},
		{PrototypeAuthenticatorBioEnrollment, "prototypeAuthenticatorBioEnrollment"},
		{PrototypeAuthenticatorCredentialManagement, "prototypeAuthenticatorCredentialManagement"},
	}
	for _, tt := range commands {
		if got, ok := tt.value.Name(); !ok || got != tt.name {
			t.Errorf("Command(%d).Name() = %q, %v, want %q, true", tt.value, got, ok, tt.name)
		}
	}
	if got, ok := Command(0x7e).Name(); ok || got != "" {
		t.Errorf("unknown Command.Name() = %q, %v, want empty, false", got, ok)
	}

	assertNames(t, "ClientPIN", []namedValue[ClientPINSubCommand]{
		{ClientPINSubCommandGetPINRetries, "getPINRetries"},
		{ClientPINSubCommandGetKeyAgreement, "getKeyAgreement"},
		{ClientPINSubCommandSetPIN, "setPIN"},
		{ClientPINSubCommandChangePIN, "changePIN"},
		{ClientPINSubCommandGetPinToken, "getPinToken"},
		{ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions, "getPinUvAuthTokenUsingUvWithPermissions"},
		{ClientPINSubCommandGetUVRetries, "getUVRetries"},
		{ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions, "getPinUvAuthTokenUsingPinWithPermissions"},
	}, ClientPINSubCommand.Name)
	assertNames(t, "BioEnrollment", []namedValue[BioEnrollmentSubCommand]{
		{BioEnrollmentSubCommandEnrollBegin, "enrollBegin"},
		{BioEnrollmentSubCommandEnrollCaptureNextSample, "enrollCaptureNextSample"},
		{BioEnrollmentSubCommandCancelCurrentEnrollment, "cancelCurrentEnrollment"},
		{BioEnrollmentSubCommandEnumerateEnrollments, "enumerateEnrollments"},
		{BioEnrollmentSubCommandSetFriendlyName, "setFriendlyName"},
		{BioEnrollmentSubCommandRemoveEnrollment, "removeEnrollment"},
		{BioEnrollmentSubCommandGetFingerprintSensorInfo, "getFingerprintSensorInfo"},
	}, BioEnrollmentSubCommand.Name)
	assertNames(t, "CredentialManagement", []namedValue[CredentialManagementSubCommand]{
		{CredentialManagementSubCommandGetCredsMetadata, "getCredsMetadata"},
		{CredentialManagementSubCommandEnumerateRPsBegin, "enumerateRPsBegin"},
		{CredentialManagementSubCommandEnumerateRPsGetNextRP, "enumerateRPsGetNextRP"},
		{CredentialManagementSubCommandEnumerateCredentialsBegin, "enumerateCredentialsBegin"},
		{CredentialManagementSubCommandEnumerateCredentialsGetNextCredential, "enumerateCredentialsGetNextCredential"},
		{CredentialManagementSubCommandDeleteCredential, "deleteCredential"},
		{CredentialManagementSubCommandUpdateUserInformation, "updateUserInformation"},
	}, CredentialManagementSubCommand.Name)
	assertNames(t, "Config", []namedValue[ConfigSubCommand]{
		{ConfigSubCommandEnableEnterpriseAttestation, "enableEnterpriseAttestation"},
		{ConfigSubCommandToggleAlwaysUv, "toggleAlwaysUv"},
		{ConfigSubCommandSetMinPINLength, "setMinPINLength"},
		{ConfigSubCommandEnableLongTouchForReset, "enableLongTouchForReset"},
		{ConfigSubCommandVendorPrototype, "vendorPrototype"},
	}, ConfigSubCommand.Name)
}

type namedUnsigned interface {
	~uint8 | ~uint
}

type namedValue[T namedUnsigned] struct {
	value T
	name  string
}

func assertNames[T namedUnsigned](
	t *testing.T,
	typeName string,
	values []namedValue[T],
	name func(T) (string, bool),
) {
	t.Helper()

	for _, tt := range values {
		if got, ok := name(tt.value); !ok || got != tt.name {
			t.Errorf("%s(%d).Name() = %q, %v, want %q, true", typeName, tt.value, got, ok, tt.name)
		}
	}
	if got, ok := name(T(0xfe)); ok || got != "" {
		t.Errorf("unknown %s.Name() = %q, %v, want empty, false", typeName, got, ok)
	}
}
