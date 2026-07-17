package protocol

type AuthenticatorConfigRequest struct {
	SubCommand        ConfigSubCommand  `cbor:"1,keyasint"`
	SubCommandParams  any               `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocol `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte            `cbor:"4,keyasint,omitempty"`
}

// VendorCommandID identifies a vendor-defined authenticatorConfig command.
// CTAP assigns the complete unsigned 64-bit range to these identifiers.
type VendorCommandID uint64

// SetMinPINLengthConfigSubCommandParams contains the optional parameters of
// the setMinPINLength authenticatorConfig subcommand. Pointers preserve the
// distinction between absent scalar parameters and explicitly supplied zero
// or false values. MinPINLengthRPIDs uses nil and non-nil slices to distinguish
// an absent parameter from an explicitly supplied empty array.
type SetMinPINLengthConfigSubCommandParams struct {
	NewMinPINLength     *uint    `cbor:"1,keyasint,omitempty"`
	MinPINLengthRPIDs   []string `cbor:"2,keyasint,omitzero"`
	ForceChangePIN      *bool    `cbor:"3,keyasint,omitempty"`
	PINComplexityPolicy *bool    `cbor:"4,keyasint,omitempty"`
}
