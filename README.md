# go-ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

`go-ctap` is a Go library for communicating with FIDO2 authenticators at the CTAP message level. It offers direct CTAP
commands and a higher-level, stateful authenticator API.

> [!WARNING]
> The project is pre-v1.0. Breaking API changes may occur throughout `v0.x`.

This is not a WebAuthn relying-party implementation. The `webauthn` package only provides WebAuthn-shaped extension
types used by the library.

## Status

The main CTAP 2.1 command set is implemented, including PIN/UV Auth Protocols One and Two, credential management,
biometric enrollment, large-blob storage, and selected CTAP 2.2/2.3 fields.

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

| Package                                                          | Use it for                                                                          |
|------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `discover`, `authenticator`                                      | Device selection and convenient stateful workflows, including PIN/UV and extensions |
| `client`                                                         | Individual CTAP commands with caller-managed transport and authorization state      |
| `transport`, `transport/ctaphid`, `transport/token2`, `hidproxy` | Custom device access and transport implementations                                  |
| `protocol`, `credential`, `attestation`, `extension`, `webauthn` | CTAP constants, wire types, credentials, attestations, and extension data           |
| `crypto`, `yubico`                                               | CTAP cryptography and Yubico-specific device information                            |

Concrete transports expose a common `transport.CBOR` boundary, so `client.Client` and `authenticator.Device` do not
depend on HID packets or APDUs. For a custom high-level transport, implement `transport.Device` (`transport.CBOR` plus
`io.Closer`) and pass it to `authenticator.New`.

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

Token2 APDU calls cannot be interrupted once `Card.Transmit` has started. Context cancellation is checked between APDUs.

### Windows named-pipe proxy

Use `discover.SelectDevice(ctx, options.WithUseNamedPipes())` to discover and select a device through an already running
proxy. The library connects to the proxy but does not launch or manage it. See
[`examples/namedpipe`](examples/namedpipe).

## Usage notes

- Device I/O accepts `context.Context`; CTAPHID cancellation sends `CTAPHID_CANCEL` when possible.
- `authenticator.Device` owns its transport, serializes commands, and must be closed.
- `Device.GetInfo()` returns cached authenticator information.
- Fully consume assertion and credential-management iterators before sending another command; authenticators keep
  enumeration state only until the next command.
- CTAP failures can be matched as `*transport.CTAPError`; Token2 ISO 7816 failures as `*token2.APDUError`.
- PIN/UV auth tokens are short-lived secrets. Request minimal permissions, never log them, and discard them after use.

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
