package webauthn

import "github.com/telesma-app/ctap/extension"

type CreateCredentialProtectionInputs struct {
	CredentialProtectionPolicy        extension.CredentialProtectionPolicy `cbor:"credentialProtectionPolicy" json:"credentialProtectionPolicy,omitzero"`
	EnforceCredentialProtectionPolicy bool                                 `cbor:"enforceCredentialProtectionPolicy" json:"enforceCredentialProtectionPolicy,omitzero"`
}
