package protocol

type AuthenticatorConfigRequest struct {
	SubCommand        ConfigSubCommand  `cbor:"1,keyasint"`
	SubCommandParams  any               `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocol `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte            `cbor:"4,keyasint,omitempty" ctapdiag:"redact"`
}

// VendorCommandID identifies a vendor-defined authenticatorConfig command.
// CTAP assigns the complete unsigned 64-bit range to these identifiers.
type VendorCommandID uint64

// SetMinPINLengthConfigSubCommandParams contains the optional parameters of
// the setMinPINLength authenticatorConfig subcommand. NewMinPINLength retains
// presence because an explicit zero is rejected while absence means "keep the
// current minimum". The other zero values have no state-changing meaning.
type SetMinPINLengthConfigSubCommandParams struct {
	NewMinPINLength     *uint    `cbor:"1,keyasint,omitzero"`
	MinPINLengthRPIDs   []string `cbor:"2,keyasint,omitempty"`
	ForceChangePIN      bool     `cbor:"3,keyasint,omitzero"`
	PINComplexityPolicy bool     `cbor:"4,keyasint,omitzero"`
}
