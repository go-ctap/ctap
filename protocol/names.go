package protocol

// Name returns the stable CTAP symbolic name for c. Unknown command bytes have
// no name.
func (c Command) Name() (string, bool) {
	switch c {
	case AuthenticatorMakeCredential:
		return "authenticatorMakeCredential", true
	case AuthenticatorGetAssertion:
		return "authenticatorGetAssertion", true
	case AuthenticatorGetNextAssertion:
		return "authenticatorGetNextAssertion", true
	case AuthenticatorGetInfo:
		return "authenticatorGetInfo", true
	case AuthenticatorClientPIN:
		return "authenticatorClientPIN", true
	case AuthenticatorReset:
		return "authenticatorReset", true
	case AuthenticatorBioEnrollment:
		return "authenticatorBioEnrollment", true
	case AuthenticatorCredentialManagement:
		return "authenticatorCredentialManagement", true
	case AuthenticatorSelection:
		return "authenticatorSelection", true
	case AuthenticatorLargeBlobs:
		return "authenticatorLargeBlobs", true
	case AuthenticatorConfig:
		return "authenticatorConfig", true
	case PrototypeAuthenticatorBioEnrollment:
		return "prototypeAuthenticatorBioEnrollment", true
	case PrototypeAuthenticatorCredentialManagement:
		return "prototypeAuthenticatorCredentialManagement", true
	default:
		return "", false
	}
}

// Name returns the stable CTAP symbolic name for c. Unknown subcommand bytes
// have no name.
func (c ClientPINSubCommand) Name() (string, bool) {
	switch c {
	case ClientPINSubCommandGetPINRetries:
		return "getPINRetries", true
	case ClientPINSubCommandGetKeyAgreement:
		return "getKeyAgreement", true
	case ClientPINSubCommandSetPIN:
		return "setPIN", true
	case ClientPINSubCommandChangePIN:
		return "changePIN", true
	case ClientPINSubCommandGetPinToken:
		return "getPinToken", true
	case ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions:
		return "getPinUvAuthTokenUsingUvWithPermissions", true
	case ClientPINSubCommandGetUVRetries:
		return "getUVRetries", true
	case ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions:
		return "getPinUvAuthTokenUsingPinWithPermissions", true
	default:
		return "", false
	}
}

// Name returns the stable CTAP symbolic name for c. Unknown subcommand bytes
// have no name.
func (c BioEnrollmentSubCommand) Name() (string, bool) {
	switch c {
	case BioEnrollmentSubCommandEnrollBegin:
		return "enrollBegin", true
	case BioEnrollmentSubCommandEnrollCaptureNextSample:
		return "enrollCaptureNextSample", true
	case BioEnrollmentSubCommandCancelCurrentEnrollment:
		return "cancelCurrentEnrollment", true
	case BioEnrollmentSubCommandEnumerateEnrollments:
		return "enumerateEnrollments", true
	case BioEnrollmentSubCommandSetFriendlyName:
		return "setFriendlyName", true
	case BioEnrollmentSubCommandRemoveEnrollment:
		return "removeEnrollment", true
	case BioEnrollmentSubCommandGetFingerprintSensorInfo:
		return "getFingerprintSensorInfo", true
	default:
		return "", false
	}
}

// Name returns the stable CTAP symbolic name for c. Unknown subcommand bytes
// have no name.
func (c CredentialManagementSubCommand) Name() (string, bool) {
	switch c {
	case CredentialManagementSubCommandGetCredsMetadata:
		return "getCredsMetadata", true
	case CredentialManagementSubCommandEnumerateRPsBegin:
		return "enumerateRPsBegin", true
	case CredentialManagementSubCommandEnumerateRPsGetNextRP:
		return "enumerateRPsGetNextRP", true
	case CredentialManagementSubCommandEnumerateCredentialsBegin:
		return "enumerateCredentialsBegin", true
	case CredentialManagementSubCommandEnumerateCredentialsGetNextCredential:
		return "enumerateCredentialsGetNextCredential", true
	case CredentialManagementSubCommandDeleteCredential:
		return "deleteCredential", true
	case CredentialManagementSubCommandUpdateUserInformation:
		return "updateUserInformation", true
	default:
		return "", false
	}
}

// Name returns the stable CTAP symbolic name for c. Unknown subcommand bytes
// have no name.
func (c ConfigSubCommand) Name() (string, bool) {
	switch c {
	case ConfigSubCommandEnableEnterpriseAttestation:
		return "enableEnterpriseAttestation", true
	case ConfigSubCommandToggleAlwaysUv:
		return "toggleAlwaysUv", true
	case ConfigSubCommandSetMinPINLength:
		return "setMinPINLength", true
	case ConfigSubCommandEnableLongTouchForReset:
		return "enableLongTouchForReset", true
	case ConfigSubCommandVendorPrototype:
		return "vendorPrototype", true
	default:
		return "", false
	}
}
