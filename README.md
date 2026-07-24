# go-ctap/ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

`go-ctap/ctap` is a Go library for direct communication with FIDO2 authenticators. It provides both CTAP commands and a
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
- `encIdentifier` and `encCredStoreState` decryption;
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

| Transport             | Setup                                                                                                                                     |
|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| USB HID               | Uses the cgo-free [`go-ctap/hid`](https://github.com/go-ctap/hid) backend                                                                 |
| Windows named pipe    | Connects to a running [`go-ctap/windows-proxy`](https://github.com/go-ctap/windows-proxy); see [`examples/namedpipe`](examples/namedpipe) |
| Token2 CTAP over APDU | Requires a PC/SC implementation such as [`go-ctap/pcsc`](https://github.com/go-ctap/pcsc); see [`examples/token2`](examples/token2)       |

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

	info, err := device.GetInfo(context.Background())
	if err != nil {
		log.Fatal(err)
	}
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

`authenticator.Device` checks the device capabilities before it starts a workflow. It selects the preferred
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
- `Device.GetInfo(ctx)` always sends `authenticatorGetInfo` and returns the current device data. The response is also
  cached for capability checks; known state changes invalidate it, and the next check refreshes it lazily.
- Finish assertion and credential-management iterators before sending another command.
- Match CTAP errors as `*transport.CTAPError` and Token2 ISO 7816 errors as `*token2.APDUError`.
- Device I/O accepts `context.Context`. Cancellation depends on transport support.

### Diagnostic logging

Pass a `diagnostic.Sink` with `options.WithDiagnosticSink` to receive one typed
event per CTAP command. The event includes command and subcommand metadata plus
redacted request and response CBOR diagnostic notation; raw wire bytes are
never passed to the sink. The sink runs synchronously after the transport
exchange, has no error return, and should return promptly.

Diagnostic notation is a normalized, pretty-printed view for troubleshooting,
not a byte-exact dump. Unknown commands and CBOR fields are preserved. Known
integer keys are annotated with CTAP field names using extended diagnostic
notation comments, for example `/clientDataHash/ 1: h'...'`. Fields tagged with
the `redact` option in `ctapdiag` are replaced with an empty value of the same
CBOR type, annotated with `[REDACTED]`, before the log record is created; for
example, a byte string becomes `h'/[REDACTED]/'`. The first tag component
overrides the displayed name; `-` keeps the name derived from the Go field, as
in `ctapdiag:"-,redact"`.

Diagnostic events are redacted, not anonymized. They may contain relying party,
user, credential, and biometric template identifiers and should be treated as
sensitive data. Unknown and vendor-defined fields have no redaction metadata,
so their normalized values are included unredacted.

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

## References

- [Client to Authenticator Protocol 2.0, Proposed Standard](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Client to Authenticator Protocol 2.1, Proposed Standard with errata](https://fidoalliance.org/specs/fido-v2.1-ps-20220621/ctap-2.1-spec-plus-errata-v2.1-ps-20220621.html)
- [Client to Authenticator Protocol 2.2, Proposed Standard](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Client to Authenticator Protocol 2.3, Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [FIDO Registry of Predefined Values 2.3, Proposed Standard](https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html)
- [Web Authentication: An API for accessing Public Key Credentials — Level 3](https://www.w3.org/TR/webauthn-3/)
- [IANA WebAuthn Registries](https://www.iana.org/assignments/webauthn/webauthn.xhtml)
- [IANA CBOR Object Signing and Encryption (COSE) Registries](https://www.iana.org/assignments/cose/cose.xhtml)
