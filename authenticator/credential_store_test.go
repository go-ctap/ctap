package authenticator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func encryptedPersistentState(
	t *testing.T,
	token,
	iv,
	plaintext []byte,
	info string,
) []byte {
	t.Helper()

	key := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(hkdf.New(
		sha256.New,
		token,
		make([]byte, sha256.Size),
		[]byte(info),
	), key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	ciphertext := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return append(bytes.Clone(iv), ciphertext...)
}

func persistentCredentialStoreInfo(
	t *testing.T,
	token,
	identifier,
	state []byte,
) protocol.AuthenticatorGetInfoResponse {
	t.Helper()

	return protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_3},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagementReadOnly: true,
		},
		EncIdentifier: encryptedPersistentState(
			t,
			token,
			bytes.Repeat([]byte{0x22}, aes.BlockSize),
			identifier,
			"encIdentifier",
		),
		EncCredStoreState: encryptedPersistentState(
			t,
			token,
			bytes.Repeat([]byte{0x33}, aes.BlockSize),
			state,
			"encCredStoreState",
		),
	}
}

func TestGetPersistentCredentialStoreState(t *testing.T) {
	token := bytes.Repeat([]byte{0x11}, 32)
	identifier := []byte("identifier-12345")
	state := []byte("store-state-1234")
	updatedInfo := persistentCredentialStoreInfo(t, token, identifier, state)
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, updatedInfo))
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_3},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagementReadOnly: true,
		},
	})

	persistentState, err := d.GetPersistentCredentialStoreState(testContext, token)
	require.NoError(t, err)
	assert.Equal(t, identifier, persistentState.AuthenticatorIdentifier[:])
	assert.Equal(t, state, persistentState.CredentialStoreState[:])
	assert.Equal(t, updatedInfo.EncCredStoreState, d.GetInfo().EncCredStoreState)

	command, _ := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorGetInfo, command)
}

func TestGetPersistentCredentialStoreStateValidatesCapabilityAndFields(t *testing.T) {
	token := bytes.Repeat([]byte{0x11}, 32)

	t.Run("requires perCredMgmtRO", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{})

		_, err := d.GetPersistentCredentialStoreState(testContext, token)
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("requires encrypted fields", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_3},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagementReadOnly: true,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, info))
		d := newTestDevice(fake, info)

		_, err := d.GetPersistentCredentialStoreState(testContext, token)
		require.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("requires token", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_3},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagementReadOnly: true,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, info)

		_, err := d.GetPersistentCredentialStoreState(testContext, nil)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assert.Empty(t, fake.Writes())
	})

	t.Run("rejects malformed encrypted fields", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_3},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagementReadOnly: true,
			},
			EncIdentifier:     make([]byte, 31),
			EncCredStoreState: make([]byte, 32),
		}
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, info))
		d := newTestDevice(fake, info)

		_, err := d.GetPersistentCredentialStoreState(testContext, token)
		require.ErrorIs(t, err, ErrSpecViolation)
	})
}

func TestCredentialStoreMutationsRefreshGetInfo(t *testing.T) {
	t.Run("MakeCredential", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalAuthData(),
		})
		updatedInfo := protocol.AuthenticatorGetInfoResponse{
			EncCredStoreState: bytes.Repeat([]byte{0x22}, 32),
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID, response, encodeCBOR(t, updatedInfo))
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionMakeCredentialUvNotRequired: true,
			},
		})

		_, err := d.MakeCredential(
			testContext,
			nil,
			[]byte("client-data"),
			credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
			[]credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: -7,
			}},
			nil,
			nil,
			map[protocol.Option]bool{protocol.OptionResidentKeys: true},
			0,
			nil,
		)
		require.NoError(t, err)
		assert.Equal(t, updatedInfo.EncCredStoreState, d.GetInfo().EncCredStoreState)
	})

	t.Run("DeleteCredential", func(t *testing.T) {
		updatedInfo := protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			EncCredStoreState:  bytes.Repeat([]byte{0x33}, 32),
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, updatedInfo))
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		err := d.DeleteCredential(
			testContext,
			bytes.Repeat([]byte{0x44}, 32),
			credential.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
		)
		require.NoError(t, err)
		assert.Equal(t, updatedInfo.EncCredStoreState, d.GetInfo().EncCredStoreState)
	})

	t.Run("UpdateUserInformation", func(t *testing.T) {
		updatedInfo := protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			EncCredStoreState:  bytes.Repeat([]byte{0x55}, 32),
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, updatedInfo))
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		err := d.UpdateUserInformation(
			testContext,
			bytes.Repeat([]byte{0x66}, 32),
			credential.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "updated"},
		)
		require.NoError(t, err)
		assert.Equal(t, updatedInfo.EncCredStoreState, d.GetInfo().EncCredStoreState)
	})
}

func TestMakeCredentialPreservesResponseWhenGetInfoRefreshFails(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	})

	result, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)
	require.Error(t, err)
	assert.Equal(t, attestation.AttestationStatementFormatIdentifierPacked, result.Format)
}
