package protocol

import "github.com/go-ctap/ctap/cose"

type AuthenticatorClientPINRequest struct {
	PinUvAuthProtocol PinUvAuthProtocol   `cbor:"1,keyasint,omitzero"`
	SubCommand        ClientPINSubCommand `cbor:"2,keyasint"`
	KeyAgreement      cose.Key            `cbor:"3,keyasint,omitzero"`
	PinUvAuthParam    []byte              `cbor:"4,keyasint,omitempty"`
	NewPinEnc         []byte              `cbor:"5,keyasint,omitempty"`
	PinHashEnc        []byte              `cbor:"6,keyasint,omitempty"`
	Permissions       Permission          `cbor:"9,keyasint,omitempty"`
	RPID              string              `cbor:"10,keyasint,omitempty"`
}

type AuthenticatorClientPINResponse struct {
	KeyAgreement    cose.Key `cbor:"1,keyasint,omitzero"`
	PinUvAuthToken  []byte   `cbor:"2,keyasint,omitempty"`
	PinRetries      *uint    `cbor:"3,keyasint,omitzero"`
	PowerCycleState *bool    `cbor:"4,keyasint,omitzero"`
	UvRetries       *uint    `cbor:"5,keyasint,omitzero"`
}
