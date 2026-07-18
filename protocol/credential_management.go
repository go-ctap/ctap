package protocol

import (
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/credential"
)

type AuthenticatorCredentialManagementRequest struct {
	SubCommand        CredentialManagementSubCommand       `cbor:"1,keyasint"`
	SubCommandParams  CredentialManagementSubCommandParams `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocol                    `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte                               `cbor:"4,keyasint,omitempty" ctapdiag:"redact"`
}

type CredentialManagementSubCommandParams struct {
	RPIDHash     []byte                                   `cbor:"1,keyasint,omitempty"`
	CredentialID credential.PublicKeyCredentialDescriptor `cbor:"2,keyasint,omitzero"`
	User         credential.PublicKeyCredentialUserEntity `cbor:"3,keyasint,omitzero"`
}

type AuthenticatorCredentialManagementResponse struct {
	ExistingResidentCredentialsCount             *uint                                    `cbor:"1,keyasint,omitempty"`
	MaxPossibleRemainingResidentCredentialsCount *uint                                    `cbor:"2,keyasint,omitempty"`
	RP                                           credential.PublicKeyCredentialRpEntity   `cbor:"3,keyasint,omitzero"`
	RPIDHash                                     []byte                                   `cbor:"4,keyasint,omitempty"`
	TotalRPs                                     uint                                     `cbor:"5,keyasint,omitzero"`
	User                                         credential.PublicKeyCredentialUserEntity `cbor:"6,keyasint,omitzero"`
	CredentialID                                 credential.PublicKeyCredentialDescriptor `cbor:"7,keyasint,omitzero"`
	PublicKey                                    cose.Key                                 `cbor:"8,keyasint,omitempty"`
	TotalCredentials                             uint                                     `cbor:"9,keyasint,omitzero"`
	CredProtect                                  uint                                     `cbor:"10,keyasint,omitzero"`
	LargeBlobKey                                 []byte                                   `cbor:"11,keyasint,omitempty" ctapdiag:"redact"`
	ThirdPartyPayment                            *bool                                    `cbor:"12,keyasint,omitempty"`
}
