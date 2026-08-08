package protocol

import (
	"github.com/telesma-app/ctap/cose"
	"github.com/google/uuid"
)

type AuthDataFlag byte

const (
	AuthDataFlagUserPresent AuthDataFlag = 1 << iota
	_
	AuthDataFlagUserVerified
	_
	_
	_
	AuthDataFlagAttestedCredentialDataIncluded
	AuthDataFlagExtensionDataIncluded
)

type AttestedCredentialData struct {
	AAGUID              uuid.UUID
	CredentialID        []byte
	CredentialPublicKey cose.Key
}
