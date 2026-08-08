package authenticator

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ pinger = (*ctaphid.Transport)(nil)
	_ winker = (*ctaphid.Transport)(nil)
	_ locker = (*ctaphid.Transport)(nil)
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
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
	d := newTestDevice(t, fake, initial)

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
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

	var assertions []protocol.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(testContext, nil, "example.com", []byte("client-data"), nil, nil, nil) {
		require.NoError(t, err)
		assertions = append(assertions, assertion)
	}

	require.Len(t, assertions, 2)
	assert.Equal(t, []byte{1}, assertions[0].Signature)
	assert.Equal(t, []byte{2}, assertions[1].Signature)
}

func TestLockRejectsOutOfRangeSeconds(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{})

	err := d.Lock(testContext, 11)
	require.Error(t, err)
	assert.True(t, errors.Is(err, SyntaxError))
	assertNoAuthenticatorIO(t, fake)
}
