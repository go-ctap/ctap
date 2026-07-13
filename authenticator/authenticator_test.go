package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/client"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/ctap/yubico"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	ecdhkey "github.com/ldclabs/cose/key/ecdh"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}
var testContext = context.Background()

var (
	_ pinger                 = (*ctaphid.Transport)(nil)
	_ winker                 = (*ctaphid.Transport)(nil)
	_ locker                 = (*ctaphid.Transport)(nil)
	_ yubico.VendorTransport = (*ctaphid.Transport)(nil)
)

type optionTransport struct {
	response []byte
	err      error
	requests [][]byte
	closed   bool
}

type capabilityTransport struct {
	optionTransport
	pingResponse []byte
	winked       bool
	lockSeconds  uint8
}

func (t *capabilityTransport) Ping(context.Context, []byte) ([]byte, error) {
	return slices.Clone(t.pingResponse), nil
}

func (t *capabilityTransport) Wink(context.Context) error {
	t.winked = true
	return nil
}

func (t *capabilityTransport) Lock(_ context.Context, seconds uint8) error {
	t.lockSeconds = seconds
	return nil
}

func (t *optionTransport) CBOR(_ context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.requests = append(t.requests, slices.Clone(data))
	return ctaptransport.CBORResponse{Data: slices.Clone(t.response)}, t.err
}

func (t *optionTransport) Close() error {
	t.closed = true
	return nil
}

func newTestDevice(fake *testhid.Device, info protocol.AuthenticatorGetInfoResponse) *Device {
	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	transport := ctaphid.NewTransport(fake, testCID)
	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		panic(err)
	}
	d := &Device{
		transport:  transport,
		info:       info,
		ctapClient: ctapClient,
		encMode:    encMode,
	}
	if len(info.PinUvAuthProtocols) > 0 {
		d.pinUvAuthProtocol = info.PinUvAuthProtocols[0]
	}

	return d
}

func encodeCBOR(t *testing.T, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestNewUsesConfiguredTransport(t *testing.T) {
	transport := &optionTransport{response: encodeCBOR(t, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	})}

	device, err := New(testContext, transport)
	require.NoError(t, err)
	assert.Equal(t, protocol.Versions{protocol.FIDO_2_1}, device.GetInfo().Versions)
	assert.Equal(t, [][]byte{{byte(protocol.AuthenticatorGetInfo)}}, transport.requests)

	require.NoError(t, device.Close())
	assert.True(t, transport.closed)
}

func TestNewClosesConfiguredTransportAfterGetInfoFailure(t *testing.T) {
	transport := &optionTransport{err: errors.New("get info failed")}

	_, err := New(testContext, transport)
	require.Error(t, err)
	assert.True(t, transport.closed)
}

func TestHIDCapabilitiesPreserveDeviceCommands(t *testing.T) {
	transport := &capabilityTransport{pingResponse: []byte("hello")}
	d := &Device{transport: transport}

	require.NoError(t, d.Ping(testContext, []byte("hello")))
	require.NoError(t, d.Wink(testContext))
	require.NoError(t, d.Lock(testContext, 7))
	assert.True(t, transport.winked)
	assert.Equal(t, uint8(7), transport.lockSeconds)

	transport.pingResponse = []byte("different")
	require.ErrorIs(t, d.Ping(testContext, []byte("hello")), ErrPingPongMismatch)
}

func TestUnsupportedTransportRejectsHIDCommands(t *testing.T) {
	d := &Device{transport: &optionTransport{}}

	require.ErrorIs(t, d.Ping(testContext, nil), ErrNotSupported)
	require.ErrorIs(t, d.Wink(testContext), ErrNotSupported)
	require.ErrorIs(t, d.Lock(testContext, 1), ErrNotSupported)
}

func testKeyAgreement(t *testing.T) key.Key {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := ecdhkey.KeyFromPublic(privateKey.Public().(*ecdh.PublicKey))
	require.NoError(t, err)
	require.NoError(t, coseKey.Set(iana.KeyParameterAlg, -25))
	delete(coseKey, iana.KeyParameterKid)

	return coseKey
}

func minimalAuthData() []byte {
	return make([]byte, 37)
}

func TestGetAssertionContinuesAfterAssertionWithoutExtensionData(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: new(uint(2)),
	})
	second := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{2},
	})
	fake := testhid.NewCBORDevice(t, testCID, first, second)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{})

	var assertions []protocol.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(testContext, nil, "example.com", []byte("client-data"), nil, nil, nil) {
		require.NoError(t, err)
		assertions = append(assertions, assertion)
	}

	require.Len(t, assertions, 2)
	assert.Equal(t, []byte{1}, assertions[0].Signature)
	assert.Equal(t, []byte{2}, assertions[1].Signature)
}

func TestLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, sum[:16]...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Empty(t, blobs)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	require.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	assert.Equal(t, uint64(960), request[uint64(1)])
}

func TestLargeBlobsTreatsCorruptConfigAsInitialEmptyArray(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{{Ciphertext: []byte{0xaa}}})
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, bytes.Repeat([]byte{0x00}, 16)...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestSetLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:          []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		MaxSerializedLargeBlobArray: lo.ToPtr(uint(2048)),
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})
	blob := protocol.LargeBlob{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 1000),
		Nonce:      []byte("nonce"),
	}

	err := d.SetLargeBlobs(testContext, make([]byte, 32), []protocol.LargeBlob{blob})
	require.NoError(t, err)

	command, requestCBOR := fake.FirstCTAPPayload(t)
	require.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	set, ok := request[uint64(2)].([]byte)
	require.True(t, ok)
	assert.Len(t, set, 960)
	assert.Equal(t, uint64(0), request[uint64(3)])
}

func TestSetLargeBlobsRequiresReportedMaxSerializedLargeBlobArray(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	err := d.SetLargeBlobs(testContext, make([]byte, 32), []protocol.LargeBlob{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maxSerializedLargeBlobArray")
	assert.Empty(t, fake.Writes())
}

func TestCredentialManagementUnsupportedIteratorsReturnBeforeCommand(t *testing.T) {
	t.Run("enumerate RPs", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})

		var count int
		for rp, err := range d.EnumerateRPs(testContext, nil) {
			count++
			assert.Equal(t, protocol.AuthenticatorCredentialManagementResponse{}, rp)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNotSupported))
		}

		assert.Equal(t, 1, count)
		assert.Empty(t, fake.Writes())
	})

	t.Run("enumerate credentials", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{Options: map[protocol.Option]bool{}})

		var count int
		for cred, err := range d.EnumerateCredentials(testContext, nil, make([]byte, 32)) {
			count++
			assert.Equal(t, protocol.AuthenticatorCredentialManagementResponse{}, cred)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNotSupported))
		}

		assert.Equal(t, 1, count)
		assert.Empty(t, fake.Writes())
	})
}

func TestUpdateUserInformationUsesPreviewCommandForPreviewOnlyDevice(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagementPreview: true,
		},
	})

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

func TestMakeCredentialCredPropsOutputDependsOnCredPropsInput(t *testing.T) {
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

	resp, err := d.MakeCredential(
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
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthn.CreateCredentialPropertiesInputs{CredentialProperties: true},
		},
		map[protocol.Option]bool{protocol.OptionResidentKeys: true},
		0,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs)
	assert.True(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
}

func TestMakeCredentialRequiresMaxCredBlobLengthWhenCredBlobExtensionReported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierCredentialBlob,
		},
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
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialBlobInputs: &webauthn.CreateCredentialBlobInputs{CredBlob: []byte("blob")},
		},
		nil,
		0,
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maxCredBlobLength")
	assert.Empty(t, fake.Writes())
}

func TestMissingPinUvAuthProtocolsReturnsError(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	err := d.SetPIN(testContext, "1234")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotSupported))
	assert.Empty(t, fake.Writes())
}

func TestGetPinUvAuthTokenUsingPINValidatesPINBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	_, err := d.GetPinUvAuthTokenUsingPIN(testContext, "123\x00", protocol.PermissionCredentialManagement, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0x00")
	assert.Empty(t, fake.Writes())
}

func TestSetPINValidatesPINBeforeCommand(t *testing.T) {
	t.Run("rejects too short PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 4")
		assert.Empty(t, fake.Writes())
	})

	t.Run("honors minPinLength", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MinPINLength:       lo.ToPtr(uint(8)),
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "1234567")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 8")
		assert.Empty(t, fake.Writes())
	})
}

func TestSetPINRefreshesCachedGetInfo(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	updatedInfo := encodeCBOR(t, &protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil, updatedInfo)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
	})

	require.NoError(t, d.SetPIN(testContext, "1234"))

	info := d.GetInfo()
	assert.True(t, info.Options[protocol.OptionClientPIN])
}

func TestChangePINValidatesNewPINBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		MinPINLength:       lo.ToPtr(uint(8)),
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	err := d.ChangePIN(testContext, "1234", "1234567")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8")
	assert.Empty(t, fake.Writes())
}

func TestGetAssertionValidatesHMACSecretSalts(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthn.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 31)},
			},
		},
		nil,
	) {
		count++
		assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSaltSize))
	}

	assert.Equal(t, 1, count)
	assert.Empty(t, fake.Writes())
}

func TestMakeCredentialValidatesHMACSecretMCSalts(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecretMC},
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
		&webauthn.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthn.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32), Salt2: make([]byte, 31)},
			},
		},
		nil,
		0,
		nil,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSaltSize))
	assert.Empty(t, fake.Writes())
}

func TestLockRejectsOutOfRangeSeconds(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{})

	err := d.Lock(testContext, 11)
	require.Error(t, err)
	assert.True(t, errors.Is(err, SyntaxError))
	assert.Empty(t, fake.Writes())
}
