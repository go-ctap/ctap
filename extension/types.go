package extension

// ExtensionIdentifier is an enum consisting of IANA registered Extension Identifiers.
// https://www.iana.org/assignments/webauthn/webauthn.xhtml
type ExtensionIdentifier string

const (
	ExtensionIdentifierAppID                  ExtensionIdentifier = "appid"
	ExtensionIdentifierTxAuthSimple           ExtensionIdentifier = "txAuthSimple"
	ExtensionIdentifierTxAuthGeneric          ExtensionIdentifier = "txAuthGeneric"
	ExtensionIdentifierAuthnSelection         ExtensionIdentifier = "authnSel"
	ExtensionIdentifierExtensions             ExtensionIdentifier = "exts"
	ExtensionIdentifierUserVerificationIndex  ExtensionIdentifier = "uvi"
	ExtensionIdentifierLocation               ExtensionIdentifier = "loc"
	ExtensionIdentifierUserVerificationMethod ExtensionIdentifier = "uvm"
	ExtensionIdentifierCredentialProtection   ExtensionIdentifier = "credProtect"
	ExtensionIdentifierCredentialBlob         ExtensionIdentifier = "credBlob"
	ExtensionIdentifierLargeBlobKey           ExtensionIdentifier = "largeBlobKey"
	ExtensionIdentifierMinPinLength           ExtensionIdentifier = "minPinLength"
	ExtensionIdentifierPinComplexityPolicy    ExtensionIdentifier = "pinComplexityPolicy"
	ExtensionIdentifierHMACSecret             ExtensionIdentifier = "hmac-secret"
	ExtensionIdentifierHMACSecretMC           ExtensionIdentifier = "hmac-secret-mc"
	ExtensionIdentifierAppIDExclude           ExtensionIdentifier = "appidExclude"
	ExtensionIdentifierCredentialProperties   ExtensionIdentifier = "credProps"
	ExtensionIdentifierLargeBlob              ExtensionIdentifier = "largeBlob"
	ExtensionIdentifierPayment                ExtensionIdentifier = "payment"
	ExtensionIdentifierThirdPartyPayment      ExtensionIdentifier = "thirdPartyPayment"
	ExtensionIdentifierPreviewSign            ExtensionIdentifier = "previewSign"
)

type CredentialProtectionPolicy string

const (
	CredentialProtectionPolicyUserVerificationOptional                     CredentialProtectionPolicy = "userVerificationOptional"
	CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList CredentialProtectionPolicy = "userVerificationOptionalWithCredentialIDList"
	CredentialProtectionPolicyUserVerificationRequired                     CredentialProtectionPolicy = "userVerificationRequired"
)

type LargeBlobSupport string

const (
	LargeBlobSupportRequired  LargeBlobSupport = "required"
	LargeBlobSupportPreferred LargeBlobSupport = "preferred"
)
