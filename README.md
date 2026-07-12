# go-ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

go-ctap is an idiomatic Go library for interacting with FIDO2 authenticators using CTAP.
It exposes several abstraction levels, from raw CTAPHID transport framing to ergonomic authenticator workflows.

> [!WARNING]
> Work in progress! API may change during `v0.x`!

## Current Status

The library implements the CTAP 2.1 core command set over CTAPHID, with NFC and BLE transports out of scope for now.
It also includes selected CTAP 2.2 and CTAP 2.3 features and extensions, such as `largeBlobKey` and `hmac-secret-mc`.
The `hmac-secret-mc` implementation has not yet been tested against a physical authenticator with support for it, and
the dedicated `largeBlob` extension is still pending.

My current priorities are to write better tests and completely replace [sstallion/go-hid](https://github.com/sstallion/go-hid)
with the [go-ctap/hid](https://github.com/go-ctap/hid) `cgo`-free alternative.

## Key Features and Architecture

The library exposes several abstraction levels, allowing you to choose the API that best suits your needs:

1. **Transport Layer (`transport/ctaphid`)**

   Direct access to the raw CTAPHID transport protocol. If you need maximum control, you can communicate with devices
   at the frame level.

2. **Client Layer (`client`)**

   Implements CTAP command messaging atop the transport, letting you call authenticator commands while still managing
   the device handle, channel ID, PIN/UV auth tokens, and command inputs yourself.

3. **Authenticator Layer (`authenticator`)**

   Provides a convenient wrapper over the `client` package, managing the HID device descriptor, channel ID (CID),
   cached authenticator info, and common CTAP flows.

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
- `cgo` is currently used only for the macOS HID backend, but CTAP protocol logic is pure Go.

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
- [ ] Better tests (using virtual authenticator?)
- [ ] `cgo`-free version for macOS. See [go-hid](https://github.com/go-ctap/hid).
