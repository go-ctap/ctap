package authenticator

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/telesma-app/ctap/client"
	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/options"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport/ctaphid"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}
var testContext = context.Background()

func newTestDevice(t testing.TB, fake *testhid.Device, info protocol.AuthenticatorGetInfoResponse) *Device {
	t.Helper()
	transport := ctaphid.NewTransport(fake, testCID)
	ctapClient, err := client.NewClient(options.WithTransport(transport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return b
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

func minimalAuthData() []byte {
	return make([]byte, 37)
}

func hmacSecretIsZero(secret protocol.HMACSecret) bool {
	return secret.KeyAgreement == nil &&
		secret.SaltEnc == nil &&
		secret.SaltAuth == nil &&
		secret.PinUvAuthProtocol == 0
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

func credentialManagementResponseIsZero(response protocol.AuthenticatorCredentialManagementResponse) bool {
	return response.ExistingResidentCredentialsCount == nil &&
		response.MaxPossibleRemainingResidentCredentialsCount == nil &&
		response.RP.ID == "" &&
		response.RP.Name == "" &&
		response.RPIDHash == nil &&
		response.TotalRPs == 0 &&
		response.User.ID == nil &&
		response.User.DisplayName == "" &&
		response.User.Name == "" &&
		response.User.Icon == "" &&
		response.CredentialID.Type == "" &&
		response.CredentialID.ID == nil &&
		response.CredentialID.Transports == nil &&
		response.PublicKey == nil &&
		response.TotalCredentials == 0 &&
		response.CredProtect == 0 &&
		response.LargeBlobKey == nil &&
		response.ThirdPartyPayment == nil
}

func assertNoAuthenticatorIO(t testing.TB, fake *testhid.Device) {
	t.Helper()
	if got := fake.Writes(); len(got) != 0 {
		t.Errorf("got non-empty value %#v; context: %s", got, "validation must fail before transport I/O")
	}
}
