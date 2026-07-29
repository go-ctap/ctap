# ISO 7816 examples

`main.go` prints basic CTAP information for a card that is already present.

`cmd/assertion-probe` reproduces a PIN-protected `GetAssertion` on a guaranteed
fresh card power-up. It waits for a card removal and insertion, obtains a new
`ga` PIN/UV token, and sends the request with `up=true`.

The probe defaults to the `example.com` request used during NFC user-presence
debugging. Transport mode defaults to `auto`: it first selects the standard
FIDO ISO7816 applet and falls back to Token2's proprietary APDU applet. Force a
mode with `-transport iso7816` or `-transport token2`.

The probe reads the PIN only from `FIDO2_PIN` and redacts PIN-related CTAP fields
from its diagnostic output:

```sh
FIDO2_PIN='1234' go run ./cmd/assertion-probe -reader 'Smart Reader'
```

Some PC/SC drivers do not publish card-removal events. After manually removing
and re-presenting the card, bypass event waiting with:

```sh
FIDO2_PIN='1234' go run ./cmd/assertion-probe -reader 'Smart Reader' -card-is-fresh
```

`-reader` (or `PCSC_READER`) is required because the probe sends a PIN and must
never guess among connected PC/SC devices. Use `-client-data-hash`,
`-credential-id`, and `-rp-id` to test another assertion.
