//go:generate stringer -type=Command,ClientPINSubCommand,BioEnrollmentSubCommand,LastEnrollSampleStatus,CredentialManagementSubCommand,ConfigSubCommand,Permission -output=consts_string.go
package protocol

type Command byte

const (
	AuthenticatorMakeCredential                Command = 0x01
	AuthenticatorGetAssertion                  Command = 0x02
	AuthenticatorGetNextAssertion              Command = 0x08
	AuthenticatorGetInfo                       Command = 0x04
	AuthenticatorClientPIN                     Command = 0x06
	AuthenticatorReset                         Command = 0x07
	AuthenticatorBioEnrollment                 Command = 0x09
	AuthenticatorCredentialManagement          Command = 0x0a
	AuthenticatorSelection                     Command = 0x0b
	AuthenticatorLargeBlobs                    Command = 0x0c
	AuthenticatorConfig                        Command = 0x0d
	PrototypeAuthenticatorBioEnrollment        Command = 0x40
	PrototypeAuthenticatorCredentialManagement Command = 0x41
)

type ClientPINSubCommand byte

const (
	ClientPINSubCommandGetPINRetries ClientPINSubCommand = iota + 1
	ClientPINSubCommandGetKeyAgreement
	ClientPINSubCommandSetPIN
	ClientPINSubCommandChangePIN
	ClientPINSubCommandGetPinToken
	ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions
	ClientPINSubCommandGetUVRetries
	_
	ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions
)

type BioEnrollmentSubCommand byte

const (
	BioEnrollmentSubCommandEnrollBegin BioEnrollmentSubCommand = iota + 1
	BioEnrollmentSubCommandEnrollCaptureNextSample
	BioEnrollmentSubCommandCancelCurrentEnrollment
	BioEnrollmentSubCommandEnumerateEnrollments
	BioEnrollmentSubCommandSetFriendlyName
	BioEnrollmentSubCommandRemoveEnrollment
	BioEnrollmentSubCommandGetFingerprintSensorInfo
)

type BioModality uint

const (
	BioModalityFingerprint BioModality = iota + 1
)

type LastEnrollSampleStatus uint

const (
	LastEnrollSampleStatusFingerprintGood LastEnrollSampleStatus = iota
	LastEnrollSampleStatusFingerprintTooHigh
	LastEnrollSampleStatusFingerprintTooLow
	LastEnrollSampleStatusFingerprintTooLeft
	LastEnrollSampleStatusFingerprintTooRight
	LastEnrollSampleStatusFingerprintTooFast
	LastEnrollSampleStatusFingerprintTooSlow
	LastEnrollSampleStatusFingerprintPoorQuality
	LastEnrollSampleStatusFingerprintTooSkewed
	LastEnrollSampleStatusFingerprintTooShort
	LastEnrollSampleStatusFingerprintMergeFailure
	LastEnrollSampleStatusFingerprintExists
	_
	LastEnrollSampleStatusNoUserActivity
	LastEnrollSampleStatusNoUserPresenceTransition
)

type CredentialManagementSubCommand byte

const (
	CredentialManagementSubCommandGetCredsMetadata CredentialManagementSubCommand = iota + 1
	CredentialManagementSubCommandEnumerateRPsBegin
	CredentialManagementSubCommandEnumerateRPsGetNextRP
	CredentialManagementSubCommandEnumerateCredentialsBegin
	CredentialManagementSubCommandEnumerateCredentialsGetNextCredential
	CredentialManagementSubCommandDeleteCredential
	CredentialManagementSubCommandUpdateUserInformation
)

type ConfigSubCommand byte

const (
	ConfigSubCommandEnableEnterpriseAttestation ConfigSubCommand = iota + 1
	ConfigSubCommandToggleAlwaysUv
	ConfigSubCommandSetMinPINLength
	ConfigSubCommandEnableLongTouchForReset
	ConfigSubCommandVendorPrototype = 0xff
)

type Option string

const (
	OptionPlatformDevice                 Option = "plat"
	OptionResidentKeys                   Option = "rk"
	OptionClientPIN                      Option = "clientPin"
	OptionUserPresence                   Option = "up"
	OptionUserVerification               Option = "uv"
	OptionPinUvAuthToken                 Option = "pinUvAuthToken"
	OptionNoMcGaPermissionsWithClientPin Option = "noMcGaPermissionsWithClientPin"
	OptionLargeBlobs                     Option = "largeBlobs"
	OptionEnterpriseAttestation          Option = "ep"
	OptionBioEnroll                      Option = "bioEnroll"
	OptionUserVerificationMgmtPreview    Option = "userVerificationMgmtPreview"
	OptionUvBioEnroll                    Option = "uvBioEnroll"
	OptionAuthenticatorConfig            Option = "authnrCfg"
	OptionUvAcfg                         Option = "uvAcfg"
	OptionCredentialManagement           Option = "credMgmt"
	OptionCredentialManagementReadOnly   Option = "perCredMgmtRO"
	OptionCredentialManagementPreview    Option = "credentialMgmtPreview"
	OptionSetMinPINLength                Option = "setMinPINLength"
	OptionMakeCredentialUvNotRequired    Option = "makeCredUvNotRqd"
	OptionAlwaysUv                       Option = "alwaysUv"
)

type Permission byte

const (
	PermissionNone                                   Permission = 0x00
	PermissionMakeCredential                         Permission = 0x01
	PermissionGetAssertion                           Permission = 0x02
	PermissionCredentialManagement                   Permission = 0x04
	PermissionBioEnrollment                          Permission = 0x08
	PermissionLargeBlobWrite                         Permission = 0x10
	PermissionAuthenticatorConfiguration             Permission = 0x20
	PermissionPersistentCredentialManagementReadOnly Permission = 0x40
)
