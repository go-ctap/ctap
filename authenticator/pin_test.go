package authenticator

import (
	"errors"
	"testing"

	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMissingPinUvAuthProtocolsReturnsError(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	err := d.SetPIN(testContext, "1234")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotSupported))
	assertNoAuthenticatorIO(t, fake)
}

func TestGetPinUvAuthTokenUsingPINValidatesPINBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	_, err := d.GetPinUvAuthTokenUsingPIN(testContext, "123\x00", protocol.PermissionCredentialManagement, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0x00")
	assertNoAuthenticatorIO(t, fake)
}

func TestGetPinUvAuthTokenUsingPINRequiresPINChangeBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		ForcePINChange:         true,
		PinComplexityPolicyURL: []byte("https://example.com/pin-policy"),
	})

	_, err := d.GetPinUvAuthTokenUsingPIN(
		testContext,
		"1234",
		protocol.PermissionCredentialManagement,
		"",
	)
	require.ErrorIs(t, err, ErrPinChangeRequired)
	assert.Contains(t, err.Error(), "https://example.com/pin-policy")
	assertNoAuthenticatorIO(t, fake)
}

func TestGetPinUvAuthTokenUsingUVUsesPreviewRequestShape(t *testing.T) {
	keyAgreement := encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	encryptedToken := encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		PinUvAuthToken: make([]byte, 16),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, encryptedToken)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolTwo,
			protocol.PinUvAuthProtocolOne,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionUvToken:                     true,
			protocol.OptionUserVerificationMgmtPreview: true,
		},
	})

	token, err := d.GetPinUvAuthTokenUsingUV(testContext, protocol.PermissionBioEnrollment, "")
	require.NoError(t, err)
	assert.Len(t, token, 16)

	requests := fake.Requests(t)
	require.Len(t, requests, 2)

	command, request := requests[0].CTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorClientPIN, command)
	assert.Len(t, request, 2)
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)])
	assert.Equal(t, uint64(protocol.ClientPINSubCommandGetKeyAgreement), request[uint64(2)])

	command, request = requests[1].CTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorClientPIN, command)
	assert.Len(t, request, 3)
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)])
	assert.Equal(
		t,
		uint64(protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions),
		request[uint64(2)],
	)
	assert.Contains(t, request, uint64(3))
	assert.NotContains(t, request, uint64(9))
	assert.NotContains(t, request, uint64(10))
}

func TestSetPINValidatesPINBeforeCommand(t *testing.T) {
	t.Run("rejects too short PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 4")
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("honors minPinLength", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MinPINLength:       8,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "1234567")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 8")
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("honors maxPINLength", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MaxPINLength:       8,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "123456789")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 8")
		assertNoAuthenticatorIO(t, fake)
	})
}

func TestNormalizeAndValidateNewPINAppliesMaximumAfterNFCNormalization(t *testing.T) {
	d := &Device{info: protocol.AuthenticatorGetInfoResponse{
		MaxPINLength: 4,
	}}

	pin, err := d.normalizeAndValidateNewPIN("e\u0301123")
	require.NoError(t, err)
	assert.Equal(t, "\u00e9123", pin)

	_, err = d.normalizeAndValidateNewPIN("12345")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most 4")
}

func TestSetPINAddsPINPolicyURLToAuthenticatorError(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.New(
		t,
		testhid.CBOROK(testCID, keyAgreement),
		testhid.CBORStatus(testCID, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION),
	)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:     []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		PinComplexityPolicyURL: []byte("https://example.com/pin-policy"),
		Options:                map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	err := d.SetPIN(testContext, "1234")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https://example.com/pin-policy")
	var ctapErr *ctaptransport.CTAPError
	require.ErrorAs(t, err, &ctapErr)
	assert.Equal(t, ctaptransport.CTAP2_ERR_PIN_POLICY_VIOLATION, ctapErr.StatusCode)
}

func TestSetPINDoesNotRequestGetInfo(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	require.NoError(t, d.SetPIN(testContext, "1234"))
	_, valid := d.GetInfoCached()
	assert.False(t, valid)

	requests := fake.Requests(t)
	require.Len(t, requests, 2)
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorClientPIN, command)
	}
}

func TestSetPINInvalidatesInfoAndChangePINRefreshesIt(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	currentInfo := encodeCBOR(t, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil, currentInfo, keyAgreement, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	require.NoError(t, d.SetPIN(testContext, "1234"))
	require.NoError(t, d.ChangePIN(testContext, "1234", "5678"))

	requests := fake.Requests(t)
	require.Len(t, requests, 5)
	commands := make([]protocol.Command, 0, len(requests))
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		commands = append(commands, command)
	}
	assert.Equal(t, []protocol.Command{
		protocol.AuthenticatorClientPIN,
		protocol.AuthenticatorClientPIN,
		protocol.AuthenticatorGetInfo,
		protocol.AuthenticatorClientPIN,
		protocol.AuthenticatorClientPIN,
	}, commands)
}

func TestChangePINValidatesNewPINBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		MinPINLength:       8,
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	err := d.ChangePIN(testContext, "1234", "1234567")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8")
	assertNoAuthenticatorIO(t, fake)
}

func TestChangePINRemainsAvailableWhenPINChangeIsRequired(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		ForcePINChange:     true,
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	require.NoError(t, d.ChangePIN(testContext, "1234", "5678"))
	requests := fake.Requests(t)
	require.Len(t, requests, 2)
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorClientPIN, command)
	}
}
