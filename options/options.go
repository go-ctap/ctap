package options

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/diagnostic"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

type Options struct {
	DiagnosticSink diagnostic.Sink
	EncMode        cbor.EncMode
	DecMode        cbor.DecMode
	Transport      ctaptransport.CBOR
}

type Option func(*Options)

func WithDiagnosticSink(sink diagnostic.Sink) Option {
	return func(opts *Options) {
		opts.DiagnosticSink = sink
	}
}

func WithEncMode(encMode cbor.EncMode) Option {
	return func(opts *Options) {
		opts.EncMode = encMode
	}
}

// WithDecMode configures decoding of CBOR responses received from an
// authenticator.  The default decoder rejects invalid UTF-8 text strings.
func WithDecMode(decMode cbor.DecMode) Option {
	return func(opts *Options) {
		opts.DecMode = decMode
	}
}

// WithTransport binds client commands to a transport-independent CBOR
// connection. Higher-level authenticators receive their owned transport
// directly through authenticator.New.
func WithTransport(transport ctaptransport.CBOR) Option {
	return func(opts *Options) {
		opts.Transport = transport
	}
}

func NewOptions(opts ...Option) *Options {
	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	decMode, _ := cbor.DecOptions{
		UTF8: cbor.UTF8DecodeInvalid,
	}.DecMode()
	oo := &Options{EncMode: encMode, DecMode: decMode}

	for _, opt := range opts {
		opt(oo)
	}

	return oo
}
