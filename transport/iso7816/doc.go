// Package iso7816 implements the FIDO CTAP binding over
// github.com/telesma-app/iso7816 for smart cards and NFC authenticators.
//
// Transport works with a raw APDU connection such as pcsc.Card. It selects the
// standard FIDO applet, uses short APDU command chaining, reassembles chained
// responses, and polls NFCCTAP_GETRESPONSE while an authenticator is processing
// a command or waiting for user presence.
//
// The connection must not be used for unrelated APDUs during the lifetime of a
// Transport. PC/SC callers should prefer an exclusive connection so another
// application cannot interleave commands with a chained CTAP exchange.
package iso7816
