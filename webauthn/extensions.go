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
	*PreviewSignInputs
}

type CreateAuthenticationExtensionsClientOutputs struct {
	*CreateCredentialBlobOutputs
	*CreateCredentialPropertiesOutputs
	*CreateHMACSecretOutputs
	*CreateHMACSecretMCOutputs
	*LargeBlobOutputs
	*CreatePRFOutputs
	*PreviewSignOutputs
}

type GetAuthenticationExtensionsClientInputs struct {
	*GetCredentialBlobInputs
	*GetHMACSecretInputs
	*LargeBlobInputs
	*PaymentInputs
	*PRFInputs
	*PreviewSignInputs
}

type GetAuthenticationExtensionsClientOutputs struct {
	*GetCredentialBlobOutputs
	*GetHMACSecretOutputs
	*LargeBlobOutputs
	*GetPRFOutputs
	*PreviewSignOutputs
}
