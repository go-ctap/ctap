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
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/client"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/ctap/yubico"
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

func TestHMACSecretPinUvAuthProtocolWirePresence(t *testing.T) {
	tests := []struct {
		name       string
		protocol   protocol.PinUvAuthProtocol
		wantMember bool
	}{
		{name: "protocol one is implicit", protocol: protocol.PinUvAuthProtocolOne},
		{name: "protocol two is explicit", protocol: protocol.PinUvAuthProtocolTwo, wantMember: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := newHMACSecretInput(cose.Key{1: 2}, []byte{3}, []byte{4}, tt.protocol)
			raw, err := cbor.Marshal(input)
			require.NoError(t, err)

			var fields map[uint64]cbor.RawMessage
			require.NoError(t, cbor.Unmarshal(raw, &fields))
			if tt.wantMember {
				require.Contains(t, fields, uint64(4))
			} else {
				require.NotContains(t, fields, uint64(4))
			}
		})
	}
}

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
	transport := ctaphid.NewTransport(fake, testCID)
	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		panic(err)
	}
	d := &Device{
		transport:  transport,
		ctapClient: ctapClient,
		info:       info,
		infoValid:  true,
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
	info, err := device.GetInfo(testContext)
	require.NoError(t, err)
	assert.Equal(t, protocol.Versions{protocol.FIDO_2_1}, info.Versions)
	assert.Equal(t, [][]byte{
		{byte(protocol.AuthenticatorGetInfo)},
		{byte(protocol.AuthenticatorGetInfo)},
	}, transport.requests)

	require.NoError(t, device.Close())
	assert.True(t, transport.closed)
}

func TestGetInfoAlwaysRequestsCurrentDeviceInfo(t *testing.T) {
	first := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_1},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
	}
	second := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_3},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
	}
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, first), encodeCBOR(t, second))
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
	})

	got, err := d.GetInfo(testContext)
	require.NoError(t, err)
	assert.Equal(t, first.Versions, got.Versions)

	got, err = d.GetInfo(testContext)
	require.NoError(t, err)
	assert.Equal(t, second.Versions, got.Versions)
	selected, err := d.requirePinUvAuthProtocol()
	require.NoError(t, err)
	assert.Equal(t, protocol.PinUvAuthProtocolOne, selected)

	requests := fake.Requests(t)
	require.Len(t, requests, 2)
	for _, request := range requests {
		command, _ := request.CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorGetInfo, command)
	}
}

func TestGetInfoCachedReportsValidityWithoutRequestingDeviceInfo(t *testing.T) {
	initial := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_1},
	}
	current := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
	}
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, current))
	d := newTestDevice(fake, initial)

	got, valid := d.GetInfoCached()
	assert.True(t, valid)
	assert.Equal(t, initial.Versions, got.Versions)
	assert.Empty(t, fake.Requests(t))

	d.invalidateInfoLocked()
	got, valid = d.GetInfoCached()
	assert.False(t, valid)
	assert.Equal(t, initial.Versions, got.Versions)
	assert.Empty(t, fake.Requests(t))

	got, err := d.GetInfo(testContext)
	require.NoError(t, err)
	assert.Equal(t, current.Versions, got.Versions)

	got, valid = d.GetInfoCached()
	assert.True(t, valid)
	assert.Equal(t, current.Versions, got.Versions)
	requests := fake.Requests(t)
	require.Len(t, requests, 1)
	command, _ := requests[0].CTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorGetInfo, command)
}

func TestGetInfoCachedDoesNotWaitForDeviceRequestMutex(t *testing.T) {
	d := &Device{
		info: protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
		},
		infoValid: true,
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.GetInfoCached()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("GetInfoCached waited for the device request mutex")
	}
}

func TestRequirePinUvAuthProtocolSelectsFirstSupported(t *testing.T) {
	tests := []struct {
		name       string
		advertised []protocol.PinUvAuthProtocol
		want       protocol.PinUvAuthProtocol
	}{
		{
			name:       "skips a newer protocol",
			advertised: []protocol.PinUvAuthProtocol{3, protocol.PinUvAuthProtocolTwo},
			want:       protocol.PinUvAuthProtocolTwo,
		},
		{
			name:       "preserves authenticator preference",
			advertised: []protocol.PinUvAuthProtocol{3, protocol.PinUvAuthProtocolOne, protocol.PinUvAuthProtocolTwo},
			want:       protocol.PinUvAuthProtocolOne,
		},
		{
			name:       "uses the first supported protocol",
			advertised: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo, protocol.PinUvAuthProtocolOne},
			want:       protocol.PinUvAuthProtocolTwo,
		},
		{
			name:       "rejects unsupported protocols",
			advertised: []protocol.PinUvAuthProtocol{3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{info: protocol.AuthenticatorGetInfoResponse{PinUvAuthProtocols: tt.advertised}}
			got, err := d.requirePinUvAuthProtocol()
			if tt.want == 0 {
				require.ErrorIs(t, err, ErrNotSupported)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewLeavesConfiguredTransportOpenAfterGetInfoFailure(t *testing.T) {
	transport := &optionTransport{err: errors.New("get info failed")}

	_, err := New(testContext, transport)
	require.Error(t, err)
	assert.False(t, transport.closed)
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

func testKeyAgreement(t *testing.T) cose.Key {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	require.NoError(t, err)

	return coseKey
}

func minimalAuthData() []byte {
	return make([]byte, 37)
}

func TestGetAssertionContinuesAfterAssertionWithoutExtensionData(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 2,
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

func TestGetLargeBlobsReadsAllFullFragments(t *testing.T) {
	want := []protocol.LargeBlob{{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 32),
		Nonce:      bytes.Repeat([]byte{0xbb}, 12),
		OrigSize:   16,
	}}
	encodedBlobs, err := marshalLargeBlobArray(want)
	require.NoError(t, err)
	sum := sha256.Sum256(encodedBlobs)
	config := slices.Concat(encodedBlobs, sum[:16])

	const maxFragmentLength = 16
	chunks := lo.Chunk(config, maxFragmentLength)
	require.Greater(t, len(chunks), 2)
	responses := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		responses[i] = encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: chunk})
	}

	fake := testhid.NewCBORDevice(t, testCID, responses...)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize: uint(maxFragmentLength + 64),
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	got, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Len(t, fake.Requests(t), len(chunks))
}

func TestGetLargeBlobsStopsAfterTrailingEmptyFragment(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []protocol.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	config := slices.Concat(encodedBlobs, sum[:16])
	maxMsgSize := uint(len(config) + 64)

	fake := testhid.NewCBORDevice(
		t,
		testCID,
		encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: config}),
		encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{Config: []byte{}}),
	)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		MaxMsgSize: maxMsgSize,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs(testContext)
	require.NoError(t, err)
	assert.Empty(t, blobs)

	requests := fake.Requests(t)
	require.Len(t, requests, 2)
	command, request := requests[1].CTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	assert.Equal(t, uint64(len(config)), request[uint64(3)])
}

func TestLargeBlobsReturnsIntegrityErrorForCorruptConfig(t *testing.T) {
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

	_, err := d.GetLargeBlobs(testContext)
	require.ErrorIs(t, err, ErrLargeBlobsIntegrityCheck)
}

func TestLargeBlobsReturnsInvalidArrayError(t *testing.T) {
	invalidArray := []byte{0xff}
	sum := sha256.Sum256(invalidArray)
	response := encodeCBOR(t, &protocol.AuthenticatorLargeBlobsResponse{
		Config: append(invalidArray, sum[:16]...),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})

	_, err := d.GetLargeBlobs(testContext)
	require.ErrorIs(t, err, SyntaxError)
}

func TestSetLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:          []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		MaxSerializedLargeBlobArray: 2048,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	})
	blob := protocol.LargeBlob{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 1000),
		Nonce:      bytes.Repeat([]byte{0xbb}, 12),
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
	info := protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		Options: map[protocol.Option]bool{
			protocol.OptionCredentialManagementPreview: true,
		},
	}
	fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
	d := newTestDevice(fake, info)

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

func TestValidateMakeCredentialAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		info    protocol.AuthenticatorGetInfoResponse
		token   []byte
		options map[protocol.Option]bool
		wantErr error
	}{
		{
			name: "FIDO 2.0 unprotected authenticator",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
			},
		},
		{
			name: "FIDO 2.0 configured PIN requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 configured built-in UV requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 token satisfies authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "FIDO 2.0 built-in UV satisfies authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		},
		{
			name: "FIDO 2.0 ignores makeCredUvNotRqd",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 ignores alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
		},
		{
			name: "FIDO 2.1 configured PIN requires authorization by default",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 token satisfies default requirement",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "FIDO 2.1 non-discoverable credential may omit authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.1 discoverable credential still requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 always UV requires authorization without built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 always UV implicitly uses configured built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
		},
		{
			name: "FIDO 2.3 uses modern makeCredUvNotRqd semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.3 discoverable credential still requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "device supporting FIDO 2.0 and 2.1 uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.1 preview uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "unknown future FIDO version uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.Version("FIDO_2_4")},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "missing versions preserves modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "built-in UV unsupported",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "built-in UV not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: false,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name:  "token and built-in UV are mutually exclusive",
			token: []byte("token"),
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: SyntaxError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateMakeCredentialAuthorization(test.info, test.token, test.options)
			if test.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestValidateGetAssertionAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		info    protocol.AuthenticatorGetInfoResponse
		token   []byte
		options map[protocol.Option]bool
		wantErr error
	}{
		{
			name: "FIDO 2.0 configured PIN does not require authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "FIDO 2.0 ignores alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.U2F_V2},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "configured PIN without alwaysUv permits UP-only assertion",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "token and built-in UV are mutually exclusive",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			token: []byte("token"),
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: SyntaxError,
		},
		{
			name: "built-in UV unsupported",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "built-in UV not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: false,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name: "rk is unsupported even when false",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: false,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "FIDO 2.1 alwaysUv requires token for PIN-only authenticator",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.3 token satisfies alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "explicit built-in UV satisfies alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		},
		{
			name: "configured built-in UV is used implicitly for alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
		},
		{
			name: "up false bypasses alwaysUv requirement",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserPresence: false,
			},
		},
		{
			name: "alwaysUv reports unconfigured built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: false,
				},
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name: "alwaysUv without available UV mechanism requires built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			wantErr: ErrBuiltInUVRequired,
		},
		{
			name: "client PIN without GetAssertion permission cannot satisfy alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:                       true,
					protocol.OptionClientPIN:                      true,
					protocol.OptionNoMcGaPermissionsWithClientPin: true,
				},
			},
			wantErr: ErrBuiltInUVRequired,
		},
		{
			name: "device supporting FIDO 2.0 and 2.1 uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "missing versions preserves modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateGetAssertionAuthorization(test.info, test.token, test.options)
			if test.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestGetAssertionValidatesAuthorizationBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Options: map[protocol.Option]bool{
			protocol.OptionAlwaysUv:  true,
			protocol.OptionClientPIN: true,
		},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		nil,
		nil,
	) {
		count++
		assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
	}

	assert.Equal(t, 1, count)
	assert.Empty(t, fake.Writes())
}

func TestMakeCredentialAllowsFIDO20BuiltInUV(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := testhid.NewCBORDevice(t, testCID, response)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification: true,
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
			Algorithm: cose.AlgorithmES256,
		}},
		nil,
		nil,
		map[protocol.Option]bool{protocol.OptionUserVerification: true},
		0,
		nil,
	)
	require.NoError(t, err)
	assert.NotEmpty(t, fake.Writes())
}

func TestMakeCredentialCredPropsOutputDependsOnCredPropsInput(t *testing.T) {
	response := encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	info := protocol.AuthenticatorGetInfoResponse{
		Options: map[protocol.Option]bool{
			protocol.OptionMakeCredentialUvNotRequired: true,
		},
	}
	fake := testhid.NewCBORDevice(t, testCID, response, encodeCBOR(t, info))
	d := newTestDevice(fake, info)

	resp, err := d.MakeCredential(
		testContext,
		nil,
		[]byte("client-data"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: cose.AlgorithmES256,
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
	require.NotNil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
	assert.True(t, *resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
}

func TestMakeCredentialRequiresMaxCredBlobLengthWhenCredBlobExtensionReported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierCredentialBlob,
			extension.ExtensionIdentifierCredentialProtection,
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
			Algorithm: cose.AlgorithmES256,
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

func TestGetPinUvAuthTokenUsingPINRequiresPINChangeBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
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
	assert.Empty(t, fake.Writes())
}

func TestGetPinUvAuthTokenUsingUVUsesPreviewRequestShape(t *testing.T) {
	keyAgreement := encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	encryptedToken := encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
		PinUvAuthToken: make([]byte, 16),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, encryptedToken)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
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
			MinPINLength:       8,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "1234567")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 8")
		assert.Empty(t, fake.Writes())
	})

	t.Run("honors maxPINLength", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			MaxPINLength:       8,
			Options:            map[protocol.Option]bool{protocol.OptionClientPIN: false},
		})

		err := d.SetPIN(testContext, "123456789")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at most 8")
		assert.Empty(t, fake.Writes())
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
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
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
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
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
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
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
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		MinPINLength:       8,
		Options:            map[protocol.Option]bool{protocol.OptionClientPIN: true},
	})

	err := d.ChangePIN(testContext, "1234", "1234567")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8")
	assert.Empty(t, fake.Writes())
}

func TestChangePINRemainsAvailableWhenPINChangeIsRequired(t *testing.T) {
	keyAgreement := encodeCBOR(t, &protocol.AuthenticatorClientPINResponse{
		KeyAgreement: testKeyAgreement(t),
	})
	fake := testhid.NewCBORDevice(t, testCID, keyAgreement, nil)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
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
		Extensions: []extension.ExtensionIdentifier{
			extension.ExtensionIdentifierHMACSecret,
			extension.ExtensionIdentifierHMACSecretMC,
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
			Algorithm: cose.AlgorithmES256,
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
