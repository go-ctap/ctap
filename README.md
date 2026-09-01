# telesma-app/ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/ctap.svg)](https://pkg.go.dev/github.com/telesma-app/ctap)
[![Go](https://github.com/telesma-app/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/ctap/actions/workflows/go.yml)

`telesma-app/ctap` is a Go library for direct communication with FIDO2 authenticators. It provides both CTAP commands and a
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
- format-level attestation-object parsing and packed/FIDO U2F signature verification;
- the `credProtect`, `credBlob`, `largeBlobKey`, `largeBlob`, `minPinLength`, `pinComplexityPolicy`, `hmac-secret`,
  `hmac-secret-mc`, `thirdPartyPayment`, WebAuthn `prf`, and draft `previewSign` extensions.

See the [Go API reference](https://pkg.go.dev/github.com/telesma-app/ctap) for command and type details.

Contributors adding or changing tests should follow the [testing guide](TESTING.md).

### Hardware testing

Automated tests cover the implemented protocol, validation, and state changes. Physical testing covers:

| Authenticator                       | Firmware | Tested connection and protocol                                |
|-------------------------------------|---------:|---------------------------------------------------------------|
| YubiKey 5 Series, FIPS and non-FIPS |    5.7.4 | USB HID and the advertised CTAP 2.1 features                  |
| YubiKey 5 Series RC                 |   5.8 RC | USB HID and a `previewSign` create/sign round trip            |
| Token2 PIN+ Dual                    |     R3.3 | USB HID, CTAP over APDU, and the advertised CTAP 2.1 features |

CTAP 2.2 and 2.3 features not named in the table are based on the specification and automated tests. A feature listed
above may still be unavailable on a specific device.

## Transports

| Transport             | Setup                                                                                                                                                |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| USB HID               | Uses the cgo-free [`telesma-app/hid`](https://github.com/telesma-app/hid) backend                                                                    |
| TCP CTAPHID stream    | Connects emulators and proxies that expose a stream of complete 64-byte CTAPHID reports; this is not a FIDO transport                                |
| Windows named pipe    | Connects to a running [`telesma-app/windows-proxy`](https://github.com/telesma-app/windows-proxy); see [`examples/namedpipe`](examples/namedpipe)    |
| ISO 7816 / NFC        | Wraps an exclusive raw APDU connection such as [`telesma-app/pcsc`](https://github.com/telesma-app/pcsc); see [`examples/iso7816`](examples/iso7816) |
| Token2 CTAP over APDU | Requires a PC/SC implementation such as [`telesma-app/pcsc`](https://github.com/telesma-app/pcsc); see [`examples/token2`](examples/token2)          |
| Bluetooth LE          | Experimental cgo-free CoreBluetooth backend for FIDO authenticators on macOS amd64/arm64; see [`examples/ble`](examples/ble)                         |

Hybrid and digital-credential transports are not supported. BLE and Token2 support are experimental; the Token2 protocol
is not publicly documented by the vendor.

## Installation

```sh
go get github.com/telesma-app/ctap@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

Transport adapters enumerate initialized CTAP connections. The authenticator
package builds transport-independent devices and selects one by user presence.
Long-lived discovery and automatic selection belong in an application runtime
such as `telesma-app/kit`.

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/telesma-app/ctap/authenticator"
	directhid "github.com/telesma-app/ctap/backend/hid"
)

func main() {
	ctx := context.Background()
	device, err := authenticator.Select(ctx, directhid.Enumerate)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	info, err := device.GetInfo(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("versions: %v\nAAGUID: %s\n", info.Versions, info.AAGUID)
}
```

`authenticator.Select` accepts a `backend.Enumerator`, initializes every
reported authenticator, and returns the one that confirms user presence. It
closes every other enumerated device. Direct HID, Windows named pipe, standard
PC/SC, and Token2 expose the same enumerator contract.

## API levels

| Package                                                                                           | Use it for                                                                          |
|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `authenticator`                                                                                   | Stateful workflows, capability checks, PIN/UV handling, and user-presence selection |
| `client`                                                                                          | Sending individual CTAP commands and managing state yourself                        |
| `backend/ble`, `backend/hid`, `backend/hidproxy`, `backend/pcsc`, `backend/tcp`, `backend/token2` | Finding and opening local authenticator endpoints                                   |
| `transport`, `transport/ctapble`, `transport/ctaphid`, `transport/iso7816`, `transport/token2`    | CTAP message boundaries and transport framing                                       |
| `protocol`, `credential`, `attestation`, `extension`, `webauthn`                                  | CTAP constants and data types                                                       |
| `crypto`                                                                                          | Cryptographic helpers                                                               |
| `fips140`                                                                                         | Querying the CTAP FIPS 140-3 policy and matching policy rejections                  |

For a custom transport, implement `transport.Device` and pass it to `authenticator.New`.
Yubico-specific device information and identity operations live in
[`telesma-app/yubico`](https://github.com/telesma-app/yubico).

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

## FIPS 140-3 mode

The `fips140` package connects CTAP policy to Go's process-wide FIPS 140-3 mode. When
`crypto/fips140.Enabled()` reports that the mode is enabled, the library:

- makes `client` and `authenticator` filter MakeCredential and `previewSign` key-generation parameters to approved
  algorithms while preserving their order and reject only when none remain;
- makes `client` and `authenticator` reject a MakeCredential response whose credential key falls outside that
  allowlist, which an authenticator can return by ignoring the filtered request;
- requires PIN/UV auth protocol 2 at the `client`, `authenticator`, and high-level `crypto` operation boundaries;
- makes `cose` reject local Ed448, secp256k1, and RS1 paths;
- makes `arkg` reject ARKG-P256 derivation; and
- keeps large-blob encryption inside the Go Cryptographic Module.

The two layers differ on purpose. `client` takes the protocol number from the caller and polices only what it is
given, so subcommands that allow omitting it still work with the member absent. `Device` selects the protocol itself
and rejects a device that offers no approved one, including for commands that carry no keying material.

The credential-creation allowlist is ES256/384/512, ESP256/384/512, explicit Ed25519, RS256/384/512, and
PS256/384/512. Signature verification additionally accepts generic EdDSA, and only when the concrete key is Ed25519:
COSE algorithm -8 does not name a curve, so credential creation cannot rule out Ed448, while verification resolves the
curve from the key in hand. RSA keys must also satisfy the FIPS 186-5 modulus-size and public-exponent requirements.

Both rules come from one classification per algorithm in `cose`, so the creation and verification policies cannot drift
apart.

Build the consuming application with Go's latest validated module selection and run the policy gate by default:

```sh
GOFIPS140=certified go build ./...
```

The policy follows the process-wide mode and has no override, so exercise your own FIPS branches the same way:

```sh
GOFIPS140=certified go test ./...
```

Use strict mode as a test and audit safety net:

```sh
GODEBUG=fips140=only go test ./...
```

Strict mode is not intended as the production switch. The CTAP gate is also not a certification boundary by itself:
it does not certify the consuming application, operating environment, transport, or external authenticator, and it
does not establish a NIST authenticator assurance level. Those properties must be evaluated for the complete deployed
system. The low-level `crypto/protocolone` package and the policy-free `crypto.Authenticate` helper remain available for
wire compatibility and test-vector work; callers using them directly are responsible for keeping those paths outside a
FIPS operation. The `client`, `authenticator`, and `crypto.NewPinUvAuthProtocol` APIs enforce the protocol policy before
starting an operation.

## Usage notes

- Always close `authenticator.Device`. It owns the transport and runs one command at a time.
- `Device.GetInfo(ctx)` always sends `authenticatorGetInfo` and returns the current device data. The response is also
  cached for capability checks; known state changes invalidate it, and the next check refreshes it lazily.
- Finish assertion and credential-management iterators before sending another command.
- Match CTAP errors as `*transport.CTAPError`, standard status-word errors as `*iso7816.APDUError` from
  [`telesma-app/iso7816`](https://github.com/telesma-app/iso7816), and Token2 status-word errors as
  `*token2.APDUError`.
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

| Example                                        | Purpose                                                            | Configuration                                   |
|------------------------------------------------|--------------------------------------------------------------------|-------------------------------------------------|
| [`examples/pin`](examples/pin)                 | List credentials with a PIN                                        | `FIDO2_PIN`                                     |
| [`examples/uv`](examples/uv)                   | List biometric enrollments and credentials with built-in UV        | None                                            |
| [`examples/iso7816`](examples/iso7816)         | Read authenticator information from a standard FIDO smart card     | Optional `PCSC_READER`                          |
| [`examples/token2`](examples/token2)           | List credentials through Token2 and PC/SC                          | `FIDO2_PIN`, optional `PCSC_READER`             |
| [`examples/namedpipe`](examples/namedpipe)     | Ping and list credentials through the Windows proxy                | `FIDO2_PIN`, running proxy                      |
| [`examples/transports`](examples/transports)   | Print `authenticatorGetInfo` for every transport                   | Optional Windows proxy and PC/SC service        |
| [`examples/ble`](examples/ble)                 | Scan BLE authenticators and print `authenticatorGetInfo`           | Optional `-scan` and `-id` flags                |
| [`examples/previewsign`](examples/previewsign) | Create a previewSign key, sign a message, and verify the signature | Optional `FIDO2_PIN`, previewSign authenticator |

Run an example from its directory:

```sh
cd examples/pin
FIDO2_PIN=123456 go run .
```

In PowerShell, set the variable first: `$env:FIDO2_PIN = "123456"`.

### BLE prototype

The BLE demo scans for FIDO advertisements during an explicit window, prints
each opaque CoreBluetooth identifier, name, and RSSI, then performs
`authenticatorGetInfo`:

```sh
cd examples/ble
go run . -scan 8s
go run . -scan 8s -id 01234567-89AB-CDEF-0123-456789ABCDEF
```

Use `-id` when multiple candidates are found. A conforming authenticator
protects its FIDO GATT characteristics. The transport relies on macOS to pair
when necessary and establish the encrypted link when those characteristics are
accessed, and waits for the protected GATT operations used during
initialization. Pairing and bond management APIs remain outside this
prototype. macOS may display its pairing prompt on the first run. The terminal
application needs Bluetooth permission; packaged host applications also need
`NSBluetoothAlwaysUsageDescription`.

## References

- [Client to Authenticator Protocol 2.0, Proposed Standard](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
- [Client to Authenticator Protocol 2.1, Proposed Standard with errata](https://fidoalliance.org/specs/fido-v2.1-ps-20220621/ctap-2.1-spec-plus-errata-v2.1-ps-20220621.html)
- [Client to Authenticator Protocol 2.2, Proposed Standard](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [Client to Authenticator Protocol 2.3, Proposed Standard](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
- [FIDO Registry of Predefined Values 2.3, Proposed Standard](https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html)
- [Web Authentication: An API for accessing Public Key Credentials — Level 3](https://www.w3.org/TR/webauthn-3/)
- [Yubico Signing Extension Preview for YubiKey firmware 5.8+](https://developers.yubico.com/Passkeys/Passkey_concepts/Security_key_capabilities/Signing_Extension_Preview.html)
- [WebAuthn Signing Extension, Draft Version 4](https://yubicolabs.github.io/webauthn-sign-extension/4/)
- [The Asynchronous Remote Key Generation (ARKG) Algorithm, Internet-Draft 11](https://datatracker.ietf.org/doc/html/draft-bradleylundberg-cfrg-arkg-11)
- [COSE Algorithms for Two-Party Signing, Internet-Draft 05](https://datatracker.ietf.org/doc/html/draft-lundberg-cose-two-party-signing-algs-05)
- [IANA WebAuthn Registries](https://www.iana.org/assignments/webauthn/webauthn.xhtml)
- [IANA CBOR Object Signing and Encryption (COSE) Registries](https://www.iana.org/assignments/cose/cose.xhtml)
