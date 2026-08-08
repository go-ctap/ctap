package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}

func newTestClient(t testing.TB, device *testhid.Device) *Client {
	t.Helper()
	client, err := NewClient(options.WithTransport(ctaphid.NewTransport(device, testCID)))
	require.NoError(t, err)
	return client
}

type fakeCBORTransport struct {
	t        testing.TB
	request  []byte
	response []byte
	status   ctaptransport.StatusCode
}

func (f *fakeCBORTransport) CBOR(_ context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	f.t.Helper()
	assert.Equal(f.t, f.request, data)
	return ctaptransport.ValidateCBORResponse(protocol.Command(data[0]), ctaptransport.CBORResponse{
		StatusCode: f.status,
		Data:       slices.Clone(f.response),
	})
}

func encodeCBOR(t testing.TB, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func minimalAuthData() []byte {
	return make([]byte, 37)
}

func assertRequestKeys(t testing.TB, request map[uint64]any, keys ...uint64) {
	t.Helper()

	actual := make([]uint64, 0, len(request))
	for key := range request {
		actual = append(actual, key)
	}
	assert.ElementsMatch(t, keys, actual)
}

type expectedCTAPRequest struct {
	command protocol.Command
	keys    []uint64
	fields  map[uint64]any
}

func assertCTAPRequest(t testing.TB, device *testhid.Device, want expectedCTAPRequest) map[uint64]any {
	t.Helper()

	command, request := device.FirstCTAPRequestMap(t)
	assert.Equal(t, want.command, command)
	assertRequestKeys(t, request, want.keys...)
	for key, value := range want.fields {
		assert.Equal(t, value, request[key], "request field %d", key)
	}
	return request
}

func testKeyAgreement(t testing.TB) cose.Key {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	require.NoError(t, err)

	return coseKey
}

func pinUvAuthToken() []byte {
	return bytes.Repeat([]byte{0x11}, 32)
}

func testClientDataHash() []byte {
	clientDataHash := sha256.Sum256([]byte("client-data"))
	return slices.Clone(clientDataHash[:])
}
