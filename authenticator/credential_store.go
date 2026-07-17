package authenticator

import (
	"context"

	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/protocol"
)

// PersistentCredentialStoreState identifies an authenticator and the current
// state of its discoverable credential store.
type PersistentCredentialStoreState struct {
	AuthenticatorIdentifier [16]byte
	CredentialStoreState    [16]byte
}

// GetPersistentCredentialStoreState returns the decrypted authenticator
// identifier and credential store state from a fresh getInfo response. The
// token must have the standalone pcmr permission.
func (d *Device) GetPersistentCredentialStoreState(
	ctx context.Context,
	persistentPinUvAuthToken []byte,
) (PersistentCredentialStoreState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.info.Options[protocol.OptionCredentialManagementReadOnly] {
		return PersistentCredentialStoreState{}, newErrorMessage(
			ErrNotSupported,
			"device doesn't support perCredMgmtRO",
		)
	}
	if _, err := d.pinUvAuthProtocolForRequest(persistentPinUvAuthToken, true); err != nil {
		return PersistentCredentialStoreState{}, err
	}
	if err := d.refreshInfoLocked(ctx); err != nil {
		return PersistentCredentialStoreState{}, err
	}
	if len(d.info.EncIdentifier) == 0 || len(d.info.EncCredStoreState) == 0 {
		return PersistentCredentialStoreState{}, newErrorMessage(
			ErrNotSupported,
			"device doesn't report persistent credential store identifiers",
		)
	}
	if len(d.info.EncIdentifier) != 32 {
		return PersistentCredentialStoreState{}, newErrorMessage(
			ErrSpecViolation,
			"encIdentifier must be exactly 32 bytes",
		)
	}
	if len(d.info.EncCredStoreState) != 32 {
		return PersistentCredentialStoreState{}, newErrorMessage(
			ErrSpecViolation,
			"encCredStoreState must be exactly 32 bytes",
		)
	}

	identifier, err := crypto.DecryptAuthenticatorIdentifier(
		persistentPinUvAuthToken,
		d.info.EncIdentifier,
	)
	if err != nil {
		return PersistentCredentialStoreState{}, err
	}
	state, err := crypto.DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		d.info.EncCredStoreState,
	)
	if err != nil {
		return PersistentCredentialStoreState{}, err
	}

	return PersistentCredentialStoreState{
		AuthenticatorIdentifier: identifier,
		CredentialStoreState:    state,
	}, nil
}
