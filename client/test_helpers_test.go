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
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}

func newTestClient(t testing.TB, device *testhid.Device) *Client {
	t.Helper()
	client, err := NewClient(options.WithTransport(ctaphid.NewTransport(device, testCID)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	if got, want := data, f.request; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		f.t.Errorf("got %#v, want %#v", got, want)
	}
	return ctaptransport.ValidateCBORResponse(protocol.Command(data[0]), ctaptransport.CBORResponse{
		StatusCode: f.status,
		Data:       slices.Clone(f.response),
	})
}

func encodeCBOR(t testing.TB, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	want := slices.Clone(keys)
	slices.Sort(want)
	slices.Sort(actual)
	if !slices.Equal(actual, want) {
		t.Errorf("got request keys %v, want %v", actual, want)
	}
}

func requestBytes(t testing.TB, request map[uint64]any, key uint64) []byte {
	t.Helper()

	value, ok := request[key].([]byte)
	if !ok {
		t.Fatalf("request field %d has type %T, want []byte", key, request[key])
	}

	return value
}

func requestString(t testing.TB, request map[uint64]any, key uint64) string {
	t.Helper()
	value, ok := request[key].(string)
	if !ok {
		t.Fatalf("request field %d has type %T, want string", key, request[key])
	}
	return value
}

func assertionResponseIsZero(response protocol.AuthenticatorGetAssertionResponse) bool {
	return response.Credential.Type == "" &&
		response.Credential.ID == nil &&
		response.Credential.Transports == nil &&
		response.AuthDataRaw == nil &&
		response.AuthData == nil &&
		response.Signature == nil &&
		response.User == nil &&
		response.NumberOfCredentials == 0 &&
		!response.UserSelected &&
		response.LargeBlobKey == nil &&
		response.UnsignedExtensionOutputs == nil &&
		response.ExtensionOutputs == nil
}

type expectedCTAPRequest struct {
	command protocol.Command
	keys    []uint64
	fields  map[uint64]uint64
}

func assertCTAPRequest(t testing.TB, device *testhid.Device, want expectedCTAPRequest) map[uint64]any {
	t.Helper()

	command, request := device.FirstCTAPRequestMap(t)
	if got, want := command, want.command; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	assertRequestKeys(t, request, want.keys...)
	for key, wantValue := range want.fields {
		gotValue, ok := request[key].(uint64)
		if !ok || gotValue != wantValue {
			t.Errorf("request field %d = %#v, want %#v", key, request[key], wantValue)
		}
	}
	return request
}

func testKeyAgreement(t testing.TB) cose.Key {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	coseKey, err := cose.KeyFromP256PublicKey(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return coseKey
}

func pinUvAuthToken() []byte {
	return bytes.Repeat([]byte{0x11}, 32)
}

func testClientDataHash() []byte {
	clientDataHash := sha256.Sum256([]byte("client-data"))
	return slices.Clone(clientDataHash[:])
}
