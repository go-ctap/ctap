package authenticator

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/client"
	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}
var testContext = context.Background()

func newTestDevice(t testing.TB, fake *testhid.Device, info protocol.AuthenticatorGetInfoResponse) *Device {
	t.Helper()
	transport := ctaphid.NewTransport(fake, testCID)
	ctapClient, err := client.NewClient(options.WithTransport(transport))
	require.NoError(t, err)
	return &Device{
		transport:  transport,
		ctapClient: ctapClient,
		info:       info,
		infoValid:  true,
	}
}

func encodeCBOR(t testing.TB, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func testKeyAgreement(t testing.TB) cose.Key {
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

func assertNoAuthenticatorIO(t testing.TB, fake *testhid.Device) {
	t.Helper()
	assert.Empty(t, fake.Writes(), "validation must fail before transport I/O")
}
