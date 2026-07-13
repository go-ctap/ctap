# go-ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

go-ctap is an idiomatic Go library for interacting with FIDO2 authenticators using CTAP.
It exposes several abstraction levels, from raw CTAPHID transport framing to ergonomic authenticator workflows.

> [!WARNING]
> Work in progress! API may change during `v0.x`!

## Current Status

The library implements the CTAP 2.1 core command set over CTAPHID and Token2's proprietary CTAP-over-APDU tunnel,
accessed through a smart-card/PC/SC connection. Generic NFC and BLE transports remain out of scope for now.
It also includes selected CTAP 2.2 and CTAP 2.3 features and extensions, such as `largeBlobKey` and `hmac-secret-mc`.
The `hmac-secret-mc` implementation has not yet been tested against a physical authenticator with support for it, and
the dedicated `largeBlob` extension is still pending.

My current priorities are to ensure complete FIDO2/CTAP 2.1 support, prepare the library for FIDO2/CTAP 2.3,
and fix bugs.

## Key Features and Architecture

The library exposes several abstraction levels, allowing you to choose the API that best suits your needs:

1. **Transport Layer (`transport/ctaphid`, `transport/token2`)**

   Direct access to raw CTAPHID framing and Token2's proprietary CTAP-over-APDU applet tunnel. Both implement the
   common `transport.CBOR` message boundary.

2. **Client Layer (`client`)**

   Implements CTAP command messaging over a transport configured with `options.WithTransport`, while callers manage
   PIN/UV auth tokens and command inputs themselves.

3. **Authenticator Layer (`authenticator`)**

   Provides a convenient wrapper over the `client` package, managing transport initialization, cached authenticator
   info, PIN/UV state, and common CTAP flows.

4. **Discovery Helpers (`discover`)**

   A set of helpers for finding and selecting authenticators, including user-presence based selection when
   several authenticators are connected.

5. **Crypto Helpers (`crypto`)**

   Public helpers for CTAP-specific cryptography, including PIN/UV Auth Protocol One and Two, and LargeBlob
   encryption/decryption. The lower-level `crypto/protocolone` and `crypto/protocoltwo` packages are available for
   callers that need direct access to the protocol primitives.

6. **Protocol Model (`protocol`)**

   CTAP command constants, request/response wire structures, options, permissions, parsed authenticator data, and
   CTAP extension wire inputs/outputs.

7. **Domain Types (`credential`, `attestation`, `extension`, `webauthn`)**

   Shared public-key credential primitives, attestation statement formats, extension identifiers/policies, and
   WebAuthn-shaped extension input/output structures used across the lower-level and higher-level APIs.

8. **Vendor Extensions (`yubico`)**

   Yubico-specific commands and response types, including YubiKey Device Information over the vendor CTAPHID
   command `0xc2`.

## Highlights

- Implements major FIDO2 commands: MakeCredential, GetAssertion, ClientPIN (with both PIN/UV methods),
  Reset, CredentialManagement, and more.
- Both low-level access and ergonomic, high-level APIs.
- YubiKey Device Information, including firmware version, serial number, form factor, USB/NFC capabilities,
  configuration-lock state, and device timeouts.
- Modern Go design, making use of language features like iterators.
- HID access uses the [`go-ctap/hid`](https://github.com/go-ctap/hid) `cgo`-free backend.
- Token2's proprietary APDU tunnel works with any compatible raw APDU card connection, including
  [`go-ctap/pcsc`](https://github.com/go-ctap/pcsc).

## Token2 Proprietary CTAP-over-APDU via PC/SC

Token2 exposes a standard USB CCID smart-card interface, which is handled by the operating system's PC/SC stack.
After selecting the Token2 applet, this library wraps each CTAP command byte and CBOR payload in Token2's proprietary
`80 C5 03 00` APDU. The APDU response contains the CTAP status byte and response CBOR; ISO 7816 status words and
`61xx`/GET RESPONSE chaining remain an outer layer. Open the card with `go-ctap/pcsc`, initialize the Token2 APDU
tunnel, and pass ownership to the authenticator:

```go
card, err := pcsc.Open(readerName)
if err != nil {
	return err
}

tokenTransport, err := token2.New(card)
if err != nil {
	_ = card.Close()
	return err
}

device, err := authenticator.New(tokenTransport)
if err != nil {
	return err // authenticator.New closes tokenTransport after initialization failure
}
defer device.Close()

info := device.GetInfo()
```

HID discovery, opening, and CTAPHID channel allocation are available through a separate constructor:

```go
device, err := authenticator.OpenHID(path)
```

The Windows HID proxy can also be opened as an initialized transport and passed to the generic constructor:

```go
proxyTransport, err := hidproxy.Open(ctx, path)
device, err := authenticator.New(proxyTransport)
```

## Examples

Each example is an independent Go module, so its dependencies do not affect the library's root `go.mod`.

- `examples/pin`: HID authenticator with PIN-based authorization.
- `examples/uv`: biometric HID authenticator using built-in UV; prints enrolled fingerprints and credentials.
- `examples/token2`: Token2's proprietary CTAP-over-APDU tunnel via PC/SC; `PCSC_READER` optionally selects a reader
  by name substring.
- `examples/namedpipe`: HID discovery, GetInfo, CTAPHID Ping, and PIN-authorized passkey listing through the Windows
  named-pipe proxy. The `go-ctaphid-windows-proxy` process must already be running and its named pipe must be accessible.

```sh
cd examples/pin
FIDO2_PIN=123456 go run .

cd ../uv
go run .

cd ../token2
FIDO2_PIN=123456 PCSC_READER=Token2 go run .

cd ../namedpipe
FIDO2_PIN=123456 go run .
```

## Feature Matrix

### CTAP 2.3

- [x] MakeCredential
    - [x] attestationFormatsPreference
    - [x] unsignedExtensionOutputs
    - [ ] credential-store state invalidation for discoverable credentials
- [x] GetAssertion / GetNextAssertion
    - [x] unsignedExtensionOutputs
- [x] GetInfo
    - [x] `attestationFormats`
    - [x] `uvCountSinceLastPinEntry`
    - [x] `longTouchForReset`
    - [x] `encIdentifier`
    - [x] `encCredStoreState`
    - [x] `transportsForReset`
    - [x] `pinComplexityPolicy`
    - [x] `pinComplexityPolicyURL`
    - [x] `maxPINLength`
    - [x] `authenticatorConfigCommands`
    - [x] `perCredMgmtRO` option
- [x] ClientPIN
    - [x] getPINRetries
    - [x] getKeyAgreement
    - [x] setPIN
    - [x] changePIN
    - [x] getPinToken
    - [x] getPinUvAuthTokenUsingUvWithPermissions
    - [x] getUVRetries
    - [x] getPinUvAuthTokenUsingPinWithPermissions
    - [ ] persistent PIN/UV auth token state
    - [ ] `pcmr` permission
    - [ ] `perCredMgmtRO` flow
- [x] Reset
    - [ ] `transportsForReset` handling
    - [ ] long-touch reset handling
    - [ ] reset unsupported / alternate reset handling
    - [ ] credential-store cache invalidation after reset
- [x] BioEnrollment
    - [x] enrollBegin
    - [x] enrollCaptureNextSample
    - [x] cancelCurrentEnrollment
    - [x] enumerateEnrollments
    - [x] setFriendlyName
    - [x] removeEnrollment
    - [x] getFingerprintSensorInfo
- [x] CredentialManagement
    - [x] getCredsMetadata
    - [x] enumerateRPsBegin / enumerateRPsGetNextRP
    - [x] enumerateCredentialsBegin / enumerateCredentialsGetNextCredential
    - [x] deleteCredential
    - [x] updateUserInformation
    - [ ] read-only persistent credential management via `pcmr`
    - [ ] `encCredStoreState`-based cache invalidation
- [x] Selection
- [x] LargeBlobs
    - [x] raw get
    - [x] raw set
    - [x] get serialized large-blob array
    - [x] set serialized large-blob array
    - [ ] `largeBlob` extension integration
    - [x] unsigned `largeBlob` extension outputs
- [x] Config
    - [x] enableEnterpriseAttestation
    - [x] toggleAlwaysUv
    - [x] setMinPINLength
    - [ ] enableLongTouchForReset
    - [x] `authenticatorConfigCommands` feature detection
    - [ ] `setMinPINLength` CTAP 2.3 refinements
    - [ ] PIN complexity policy CTAP 2.3 refinements
- [ ] Hybrid Transports
    - [ ] QR-initiated transactions
    - [ ] state-assisted transactions
    - [ ] post-handshake `getInfo`
    - [ ] post-handshake supported features: `ctap`
    - [ ] post-handshake supported features: `dc`
    - [ ] WebSocket data transfer channel
    - [ ] BLE data transfer channel
    - [ ] multiple data transfer channels / QR key `6`
- [ ] JSON-based Messages / Digital Credentials
    - [ ] tunnel message type `3`
    - [ ] JSON-based request
    - [ ] JSON-based response
- [ ] NFC / ISO7816 refinements
    - [ ] ISO7816 contact `smart-card` interface
    - [ ] explicit FIDO applet selection
    - [ ] applet deselection handling
    - [ ] `NFCCTAP_GETRESPONSE` timeout handling
    - [ ] `NFCCTAP_GETRESPONSE` cancel handling
- [x] Prototype BioEnrollment
- [x] Prototype CredentialManagement

### Extensions

#### CTAP

- [x] credProtect
- [x] credBlob
- [x] largeBlobKey
- [ ] largeBlob
    - [ ] MakeCredential `support`
    - [ ] MakeCredential `supported` output
    - [ ] GetAssertion read
    - [ ] GetAssertion write
- [x] minPinLength
- [x] pinComplexityPolicy
- [x] hmac-secret
- [x] hmac-secret-mc (not tested)
- [x] thirdPartyPayment

#### WebAuthn

- [x] credProps
- [x] prf
- [ ] largeBlob

### Crypto

- [x] PIN/UV Auth Protocol One
- [x] PIN/UV Auth Protocol Two
- [x] Encrypt/Decrypt using `LargeBlobsKey` extension
- [ ] persistent PIN/UV auth token support
- [ ] Decrypt `GetInfo.encIdentifier`
- [ ] Decrypt `GetInfo.encCredStoreState`

### Yubico Device Information

YubiKey 5 Series devices and Security Keys by Yubico expose firmware, serial number, form factor, capabilities, and
other device information through `GetYubiKeyDeviceInfo`:

```go
info, err := device.GetYubiKeyDeviceInfo()
if err != nil {
	return err
}

if info.Serial != nil {
	fmt.Printf("YubiKey serial: %d\n", *info.Serial)
}
version := info.FirmwareVersion
fmt.Printf("Firmware: %d.%d.%d\n", version.Major, version.Minor, version.Build)
```

The implementation uses Yubico's vendor-specific CTAPHID command `0xc2`. Lower-level callers can use
`yubico.GetDeviceInfo` with an `io.ReadWriter` and channel ID directly.

## Planned Improvements

- [ ] CTAP 2.2/2.3 support
