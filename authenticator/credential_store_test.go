package authenticator

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/ctap/attestation"
	"github.com/telesma-app/ctap/credential"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialStoreMutationsDoNotRequestGetInfo(t *testing.T) {
	t.Run("MakeCredential", func(t *testing.T) {
		response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: minimalAuthData(),
		})
		fake := testhid.NewCBORDevice(t, testCID, response)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		requests := fake.Requests(t)
		require.Len(t, requests, 1)
		command, _ := requests[0].CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	})

	t.Run("DeleteCredential", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		requests := fake.Requests(t)
		require.Len(t, requests, 1)
		command, _ := requests[0].CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorCredentialManagement, command)
	})

	t.Run("UpdateUserInformation", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		requests := fake.Requests(t)
		require.Len(t, requests, 1)
		command, _ := requests[0].CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorCredentialManagement, command)
	})
}

func TestMakeCredentialDoesNotRequestGetInfoAfterSuccess(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
	require.NoError(t, err)
	assert.Equal(t, attestation.AttestationStatementFormatIdentifierPacked, result.Format)
	requests := fake.Requests(t)
	require.Len(t, requests, 1)
	command, _ := requests[0].CTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
}

func TestCredentialManagementUnsupportedIteratorsReturnBeforeCommand(t *testing.T) {
	t.Run("enumerate RPs", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})

		var count int
		for rp, err := range d.EnumerateRPs(testContext, nil) {
			count++
			assert.Equal(t, protocol.AuthenticatorCredentialManagementResponse{}, rp)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNotSupported))
		}

		assert.Equal(t, 1, count)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("enumerate credentials", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})

		var count int
		for cred, err := range d.EnumerateCredentials(testContext, nil, make([]byte, 32)) {
			count++
			assert.Equal(t, protocol.AuthenticatorCredentialManagementResponse{}, cred)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNotSupported))
		}

		assert.Equal(t, 1, count)
		assertNoAuthenticatorIO(t, fake)
	})
}

func TestUpdateUserInformationUsesPreviewCommandForPreviewOnlyDevice(t *testing.T) {
	info := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagementPreview: true,
		},
	}
	fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
	d := newTestDevice(t, fake, info)

	err := d.UpdateUserInformation(
		testContext,
		make([]byte, 32),
		credential.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
	)
	require.NoError(t, err)

	command, _ := fake.FirstCTAPPayload(t)
	assert.Equal(t, protocol.PrototypeAuthenticatorCredentialManagement, command)
}
