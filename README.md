# go-ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

`go-ctap` is a Go library for direct communication with FIDO2 authenticators. It provides both CTAP commands and a
stateful API for common authenticator workflows.

> [!WARNING]
> The project is not yet v1.0. Minor releases may include breaking API changes.

This is not a WebAuthn server library. The `webauthn` package contains only the WebAuthn types needed by this project.

## Support

The library supports CTAP 2.0 through CTAP 2.3. CTAP 2.3 follows the
[February 2026 Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
Available features depend on the capabilities reported by each authenticator.

Main features include:

- credential creation and assertion;
- PIN and built-in user verification (UV);
- credential management and biometric enrollment;
- authenticator configuration and reset;
- legacy and CTAP 2.3 large-blob storage;
- persistent credential store state;
- PIN/UV Auth Protocols One and Two;
- the `credProtect`, `credBlob`, `largeBlobKey`, `largeBlob`, `minPinLength`, `pinComplexityPolicy`, `hmac-secret`,
  `hmac-secret-mc`, `thirdPartyPayment`, and WebAuthn `prf` extensions.

See the [Go API reference](https://pkg.go.dev/github.com/go-ctap/ctap) for command and type details.

### Hardware testing

Automated tests cover the implemented protocol, validation, and state changes. Physical testing covers:

| Authenticator | Firmware | Tested connection and protocol |
|---|---:|---|
| YubiKey 5 Series, FIPS and non-FIPS | 5.7.4 | USB HID and the advertised CTAP 2.1 features |
| Token2 PIN+ Dual | R3.3 | USB HID, CTAP over APDU, and the advertised CTAP 2.1 features |

No CTAP 2.3 authenticator has been tested with the library yet. CTAP 2.2 and 2.3 features are based on the specification
and automated tests. A feature listed above may still be unavailable on a specific device.

## Transports

| Transport | Setup |
|---|---|
| USB HID | Uses the cgo-free [`go-ctap/hid`](https://github.com/go-ctap/hid) backend |
| Windows named pipe | Connects to a running `go-ctaphid-windows-proxy`; see [`examples/namedpipe`](examples/namedpipe) |
| Token2 CTAP over APDU | Requires a PC/SC implementation such as [`go-ctap/pcsc`](https://github.com/go-ctap/pcsc); see [`examples/token2`](examples/token2) |

Generic NFC, BLE, hybrid, and digital-credential transports are not supported. Token2 support is experimental because
its protocol is not publicly documented by the vendor.

## Installation

```sh
go get github.com/go-ctap/ctap@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

`discover.SelectDevice` opens a compatible HID authenticator. If several devices are connected, it asks the user to
touch one.

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

If you know the HID path, use `authenticator.OpenHID(ctx, path)`.

## API levels

| Package | Use it for |
|---|---|
| `discover` | Finding and opening a device |
| `authenticator` | Stateful workflows, capability checks, and PIN/UV handling |
| `client` | Sending individual CTAP commands and managing state yourself |
| `transport`, `transport/ctaphid`, `transport/token2`, `hidproxy` | Device I/O and framing |
| `protocol`, `credential`, `attestation`, `extension`, `webauthn` | CTAP constants and data types |
| `crypto`, `yubico` | Cryptographic helpers and Yubico-specific operations |

For a custom transport, implement `transport.Device` and pass it to `authenticator.New`.

## PIN and user verification

`authenticator.Device` checks the cached device capabilities before it starts a workflow. It selects the preferred
PIN/UV protocol and uses permission-based tokens when supported. On older devices, it can use the legacy token flow.

Request only the permissions required by the next commands. Include an RP ID when requesting
`PermissionMakeCredential` or `PermissionGetAssertion`:

```go
token, err := device.GetPinUvAuthTokenUsingPIN(
	ctx,
	pin,
	protocol.PermissionMakeCredential,
	"example.com",
)
```

PIN/UV tokens are secrets. Do not log or store them, and discard them after use. Some configuration and large-blob
operations may work without a token on an authenticator that has no PIN or UV protection.

## Usage notes

- Always close `authenticator.Device`. It owns the transport and runs one command at a time.
- `Device.GetInfo()` returns cached data. The library refreshes it after operations that change device state.
- Finish assertion and credential-management iterators before sending another command.
- Match CTAP errors as `*transport.CTAPError` and Token2 ISO 7816 errors as `*token2.APDUError`.
- Device I/O accepts `context.Context`. Cancellation depends on transport support.

## Examples

Each example is a separate Go module.

| Example | Purpose | Configuration |
|---|---|---|
| [`examples/pin`](examples/pin) | List credentials with a PIN | `FIDO2_PIN` |
| [`examples/uv`](examples/uv) | List biometric enrollments and credentials with built-in UV | None |
| [`examples/token2`](examples/token2) | List credentials through Token2 and PC/SC | `FIDO2_PIN`, optional `PCSC_READER` |
| [`examples/token2-selection`](examples/token2-selection) | Test device selection on Token2 | Optional `PCSC_READER` |
| [`examples/namedpipe`](examples/namedpipe) | Ping and list credentials through the Windows proxy | `FIDO2_PIN`, running proxy |

Run an example from its directory:

```sh
cd examples/pin
FIDO2_PIN=123456 go run .
```

In PowerShell, set the variable first: `$env:FIDO2_PIN = "123456"`.
