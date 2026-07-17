# go-ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

`go-ctap` is a Go library for communicating with FIDO2 authenticators at the CTAP message level. It offers direct CTAP
commands and a higher-level, stateful authenticator API.

> [!WARNING]
> The project is pre-v1.0. Breaking API changes may occur throughout `v0.x`.

This is not a WebAuthn relying-party implementation. The `webauthn` package only provides WebAuthn-shaped extension
types used by the library.

## Protocol support

`go-ctap` supports CTAP 2.0 through CTAP 2.3 at both the command and stateful workflow levels. CTAP 2.3 support follows
the [February 2026 Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
Optional features are selected from `authenticatorGetInfo`; an authenticator does not need to implement every feature
in order to work with the library.

CTAP 2.2 did not define a `FIDO_2_2` value for the `versions` member. Its additions are therefore detected through
advertised fields, options, extensions, and commands rather than a version string.

| Authenticator generation | Support   | Validation                  | Compatibility behavior                                                                 |
|--------------------------|-----------|-----------------------------|----------------------------------------------------------------------------------------|
| `FIDO_2_0`               | Supported | Automated and hardware      | Core commands and the legacy `getPinToken` authorization flow                          |
| `FIDO_2_1_PRE`           | Supported | Automated                   | Preview biometric-enrollment and credential-management command identifiers             |
| `FIDO_2_1`               | Supported | Automated; hardware subset  | Standard 2.1 commands, permissioned PIN/UV tokens, large blobs, and configuration      |
| CTAP 2.2                 | Supported | Specification and automated | Capability-driven additions; the specification defines no `FIDO_2_2` identifier        |
| `FIDO_2_3`               | Supported | Specification and automated | Typed 2.3 `getInfo` data, extensions, PIN policy, persistent state, and reset settings |

### Command and workflow matrix

| Capability                        | `client.Client` | `authenticator.Device` | Notes                                                                                  |
|-----------------------------------|-----------------|------------------------|----------------------------------------------------------------------------------------|
| Make credential and get assertion | Yes             | Yes                    | Multiple assertions are exposed as an iterator                                         |
| Get info and reset                | Yes             | Yes                    | `Device` caches capabilities and refreshes them after state-changing operations        |
| Client PIN and built-in UV        | Yes             | Yes                    | PIN/UV Auth Protocols One and Two, including permissioned and persistent tokens        |
| Credential management             | Yes             | Yes                    | Standard and FIDO 2.1 preview command identifiers                                      |
| Biometric enrollment              | Yes             | Yes                    | Standard and FIDO 2.1 preview command identifiers                                      |
| Authenticator selection           | Yes             | Yes                    | Rejected before I/O when unavailable on CTAP 2.0                                       |
| Large-blob array                  | Yes             | Yes                    | Fragmented reads/writes and integrity validation; orphan garbage collection is omitted |
| Authenticator configuration       | Yes             | Yes                    | Enterprise attestation, `alwaysUv`, minimum PIN length, and long-touch reset           |
| Persistent credential store state | Raw `getInfo`   | Yes                    | Decrypts `encIdentifier` and `encCredStoreState` using a standalone `pcmr` token       |
| CTAP 2.3 `getInfo` members        | Yes             | Yes                    | Optional scalar presence and effective defaults are preserved                          |

### Extension matrix

| Extension             | Wire types | High-level workflow | Notes                                                       |
|-----------------------|------------|---------------------|-------------------------------------------------------------|
| `credProtect`         | Yes        | Yes                 | Credential protection policy                                |
| `credBlob`            | Yes        | Yes                 | Create and read credential blobs                            |
| `largeBlobKey`        | Yes        | Yes                 | Legacy large-blob storage                                   |
| `largeBlob`           | Yes        | Yes                 | Direct CTAP 2.3 large-blob reads and writes                 |
| `minPinLength`        | Yes        | Yes                 | Minimum PIN length output                                   |
| `pinComplexityPolicy` | Yes        | Yes                 | Policy status and policy URL propagation                    |
| `hmac-secret`         | Yes        | Yes                 | One or two encrypted salt values                            |
| `hmac-secret-mc`      | Yes        | Yes                 | Creation-time evaluation                                    |
| `thirdPartyPayment`   | Yes        | Yes                 | Credential tagging and get-assertion confirmation           |
| WebAuthn `prf`        | Mapped     | Yes                 | Maps to `hmac-secret` and, when available, `hmac-secret-mc` |

### Hardware validation

> [!IMPORTANT]
> Hardware coverage is narrower than the implemented protocol surface. No physical CTAP 2.3 authenticator has been
> used for end-to-end testing yet. CTAP 2.2/2.3-only behavior is implemented from the specification and verified with
> automated wire-format, validation, state-transition, and simulated-transport tests.

The library has been exercised with the following physical authenticators:

| Authenticator                       | Firmware | Live-tested scope                                                                     | Features absent from the device                                       |
|-------------------------------------|----------|---------------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| YubiKey 5 Series, FIPS and non-FIPS | 5.7.4    | USB HID, its advertised CTAP 2.1 subset, and legacy large-blob array reads            | Enterprise attestation, direct `largeBlob`, and CTAP 2.3 capabilities |
| Token2 PIN+ Dual                    | R3.3     | USB HID, proprietary CTAP-over-APDU, its CTAP 2.1 subset, and legacy large-blob reads | Enterprise attestation, direct `largeBlob`, and CTAP 2.3 capabilities |

Both product families advertise the same CTAP 2 capability families relevant here: `FIDO_2_0`, `FIDO_2_1`, and
`FIDO_2_1_PRE`; PIN/UV Auth Protocols One and Two; credential management; authenticator configuration; the legacy
large-blob array; and the `credBlob`, `credProtect`, `hmac-secret`, `largeBlobKey`, and `minPinLength` extensions.
Individual limits, algorithms, transports, and option values differ between the devices.

Features unavailable on this hardware or omitted from the live test runs are not claimed as physically validated. In
particular, enterprise attestation, the direct `largeBlob` workflow, the CTAP 2.3 `getInfo` members, persistent
credential store state, `hmac-secret-mc`, `thirdPartyPayment`, PIN complexity and maximum-length policy, and long-touch
reset support currently have specification-driven and automated coverage only. The legacy `largeBlobKey` plus
`authenticatorLargeBlobs` read path has been exercised on both product families; write behavior remains automated-test
coverage.

Support in these tables means that the corresponding types, commands, and high-level flows are implemented. Runtime
availability still depends on the authenticator's advertised capabilities.

## Transports

Supported transports:

- USB HID through the cgo-free [`go-ctap/hid`](https://github.com/go-ctap/hid) backend;
- a Windows named-pipe bridge to an existing `go-ctaphid-windows-proxy` process;
- Token2's proprietary CTAP-over-APDU tunnel through PC/SC.

Generic NFC, BLE, hybrid, and digital-credential transports are not implemented. Token2 support is experimental because
its protocol was reverse-engineered from physical hardware and is not publicly documented by the vendor.

## Installation

```sh
go get github.com/go-ctap/ctap@latest
```

The required Go version is declared in [`go.mod`](go.mod).

## Quick start

`discover.SelectDevice` opens the only compatible HID authenticator, or asks the user to touch one when several are
connected:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/go-ctap/ctap/discover"
)

func main() {
	device, err := discover.SelectDevice(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	info := device.GetInfo()
	fmt.Printf("path: %s\nversions: %v\nAAGUID: %s\n", device.Path, info.Versions, info.AAGUID)
}
```

If the HID path is already known, use `authenticator.OpenHID(ctx, path)`.

## Choosing an API

| Package                                                          | Abstraction level      | Responsibility                                                                                   |
|------------------------------------------------------------------|------------------------|--------------------------------------------------------------------------------------------------|
| `discover`                                                       | Application entry      | Selects and opens a device, returning an initialized high-level `authenticator.Device`           |
| `authenticator`                                                  | High-level, stateful   | Owns and serializes device access; caches capabilities and preflights PIN/UV and extension flows |
| `client`                                                         | CTAP command level     | Sends individual CTAP commands; the caller manages capabilities, authorization, and state        |
| `transport`, `transport/ctaphid`, `transport/token2`, `hidproxy` | Transport level        | Provides device I/O and framing without applying CTAP workflow policy                            |
| `protocol`, `credential`, `attestation`, `extension`, `webauthn` | Data model             | Defines CTAP constants, wire types, credentials, attestations, and extension data                |
| `crypto`, `yubico`                                               | Helpers and vendor API | Implements CTAP cryptography and Yubico-specific device operations                               |

Concrete transports expose a common `transport.CBOR` boundary, so `client.Client` and `authenticator.Device` do not
depend on HID packets or APDUs. For a custom high-level transport, implement `transport.Device` (`transport.CBOR` plus
`io.Closer`) and pass it to `authenticator.New`.

## PIN/UV authorization

`authenticator.Device` uses its cached `authenticatorGetInfo` response to preflight high-level operations. For PIN/UV-
authorized and extension workflows, it selects the authenticator's most-preferred PIN/UV auth protocol, validates token
lengths, and rejects requests it can determine are unsupported without performing device I/O.

`GetPinUvAuthTokenUsingPIN` uses permissioned tokens when the authenticator advertises `pinUvAuthToken`. It falls back to
the superseded `getPinToken` flow only when the requested permissions can be satisfied by that flow, including CTAP 2.0
and FIDO 2.1 preview biometric-enrollment or credential-management compatibility. A non-empty RP ID is required when
requesting `PermissionMakeCredential` or `PermissionGetAssertion` through the permissioned flow:

```go
token, err := device.GetPinUvAuthTokenUsingPIN(
	ctx,
	pin,
	protocol.PermissionMakeCredential,
	"example.com",
)
```

Request only the permissions needed by subsequent commands. `GetPinUvAuthTokenUsingUV` additionally checks whether the
requested permission can be granted through the authenticator's configured built-in UV method.

Authorization for `SetLargeBlobs` and authenticator-configuration commands is conditional. `SetLargeBlobs` may omit a
token only when the authenticator is not protected by configured PIN/UV and `alwaysUv` is disabled. Configuration
commands follow the same rule, with the CTAP exception that lets an unprotected authenticator disable an initially
enabled `alwaysUv` without authorization. Otherwise these methods return `authenticator.ErrPinUvAuthTokenRequired`
before sending a command.

### Persistent credential store state

Authenticators advertising `perCredMgmtRO` can issue a persistent token with the standalone `pcmr` permission. Use it
to decrypt `encIdentifier` and `encCredStoreState` from a fresh `authenticatorGetInfo` response:

```go
token, err := device.GetPinUvAuthTokenUsingPIN(
	ctx,
	pin,
	protocol.PermissionPersistentCredentialManagementReadOnly,
	"",
)
if err != nil {
	return err
}

persistentState, err := device.GetPersistentCredentialStoreState(ctx, token)
```

`PersistentCredentialStoreState` is comparable. Compare its decrypted fields rather than the encrypted `getInfo`
values, whose IV changes on every response. Treat the persistent token as a long-lived secret and do not store it in
logs.

### PIN policy and reset configuration

New PINs are checked against the effective `minPINLength` and `maxPINLength` in addition to the CTAP UTF-8 size limit.
When `forcePINChange` is true, `GetPinUvAuthTokenUsingPIN` returns `authenticator.ErrPinChangeRequired`; `ChangePIN`
remains available. Authenticator complexity-policy failures retain their `*transport.CTAPError` and include
`pinComplexityPolicyURL` when the authenticator supplies one.

`EnableLongTouchForReset` enables the CTAP 2.3 long-touch requirement and refreshes cached authenticator information.
Applications can inspect `LongTouchForReset` and `TransportsForReset` through `Device.GetInfo()` before calling `Reset`.

## PRF extension

The high-level `authenticator.Device` API maps the WebAuthn Level 3
[`prf` extension](https://www.w3.org/TR/webauthn-3/#prf-extension) to CTAP `hmac-secret` and `hmac-secret-mc`. Supply
`webauthn.PRFInputs` through the extension inputs passed to `MakeCredential` or `GetAssertion`; corresponding PRF
outputs are returned with the response. Do not combine PRF evaluation with the corresponding raw evaluation input:
`hmac-secret-mc` for `MakeCredential` or `hmac-secret` for `GetAssertion`.

PRF evaluation requires user verification. `Device` sends an evaluation when UV is provided by a PIN/UV auth token,
requested with `options[uv]=true`, or guaranteed by CTAP 2.1+ `alwaysUv` with configured built-in UV. Creation-time
evaluation additionally requires `hmac-secret-mc`; when it is unavailable, credential creation can still report PRF
capability but returns no creation-time results. An authentication request that asks for PRF evaluation without an
available UV mechanism fails before device I/O.

When `evalByCredential` resolves to different inputs for credentials in the same allow list, issue one `GetAssertion`
request per credential. A single CTAP request lets the authenticator choose the credential, so `Device.GetAssertion`
rejects that ambiguous combination with `authenticator.ErrNotSupported`.

## Other transports

### Token2 over PC/SC

Token2 applications need a PC/SC implementation; the examples use
[`go-ctap/pcsc`](https://github.com/go-ctap/pcsc):

```sh
go get github.com/go-ctap/pcsc
```

Open the card, wrap it with `token2.New(ctx, card)`, then pass the result to `authenticator.New`. Ownership transfers only
after each constructor succeeds: close the card yourself if `token2.New` fails; `authenticator.New` owns the Token2
transport even when authenticator initialization fails. See [`examples/token2`](examples/token2) for a complete flow.

Token2 APDU calls pass their context to `Card.Transmit`; cancellation is best-effort as provided by the PC/SC driver.

### Windows named-pipe proxy

Use `discover.SelectDevice(ctx, options.WithUseNamedPipes())` to discover and select a device through an already running
proxy. The library connects to the proxy but does not launch or manage it. See
[`examples/namedpipe`](examples/namedpipe).

## Usage notes

- Device I/O accepts `context.Context`; CTAPHID cancellation sends `CTAPHID_CANCEL` when possible.
- `authenticator.Device` owns its transport, serializes commands, and must be closed.
- `Device.GetInfo()` returns cached authenticator information.
- Successful discoverable credential creation, deletion, update, PIN changes, reset, and authenticator configuration
  refresh the cached authenticator information.
- Fully consume assertion and credential-management iterators before sending another command; authenticators keep
  enumeration state only until the next command.
- CTAP failures can be matched as `*transport.CTAPError`; Token2 ISO 7816 failures as `*token2.APDUError`.
- PIN/UV auth tokens are short-lived secrets. Request minimal permissions, never log them, and discard them after use.
- `bioEnroll` and the FIDO 2.1 preview `userVerificationMgmtPreview` option report support by their presence; a `false`
  value means biometric enrollment is supported but no enrollment exists yet.
- PIN and UV retry counters may be queried before the corresponding method is configured, provided the authenticator
  advertises support. CTAP 2.1-only commands such as `GetUVRetries` and `Selection` are rejected on CTAP 2.0 devices.

## Examples

Each example is an independent Go module, keeping device-specific dependencies out of the root module.

| Example                                                  | Purpose                                                      | Configuration                       |
|----------------------------------------------------------|--------------------------------------------------------------|-------------------------------------|
| [`examples/pin`](examples/pin)                           | List discoverable credentials using a PIN                    | `FIDO2_PIN`                         |
| [`examples/uv`](examples/uv)                             | List biometric enrollments and credentials using built-in UV | none                                |
| [`examples/token2`](examples/token2)                     | List credentials through Token2 and PC/SC                    | `FIDO2_PIN`, optional `PCSC_READER` |
| [`examples/token2-selection`](examples/token2-selection) | Test authenticator selection on Token2 hardware              | optional `PCSC_READER`              |
| [`examples/namedpipe`](examples/namedpipe)               | Ping and list credentials through the Windows proxy          | `FIDO2_PIN`, running proxy          |

Run an example from its directory:

```sh
cd examples/pin
FIDO2_PIN=123456 go run .
```

In PowerShell, set the variable first: `$env:FIDO2_PIN = "123456"`.
