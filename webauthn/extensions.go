package webauthn

type CreateAuthenticationExtensionsClientInputs struct {
	*CreateCredentialBlobInputs
	*CreateCredentialPropertiesInputs
	*CreateCredentialProtectionInputs
	*CreateHMACSecretInputs
	*CreateHMACSecretMCInputs
	*LargeBlobInputs
	*CreateMinPinLengthInputs
	*CreatePinComplexityPolicyInputs
	*PaymentInputs
	*PRFInputs
}

type CreateAuthenticationExtensionsClientOutputs struct {
	*CreateCredentialBlobOutputs
	*CreateCredentialPropertiesOutputs
	*CreateHMACSecretOutputs
	*CreateHMACSecretMCOutputs
	*LargeBlobOutputs
	*CreatePRFOutputs
}

type GetAuthenticationExtensionsClientInputs struct {
	*GetCredentialBlobInputs
	*GetHMACSecretInputs
	*LargeBlobInputs
	*PRFInputs
}

type GetAuthenticationExtensionsClientOutputs struct {
	*GetCredentialBlobOutputs
	*GetHMACSecretOutputs
	*LargeBlobOutputs
	*GetPRFOutputs
}
