package options

import (
	"log/slog"

	"github.com/fxamacker/cbor/v2"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

type Options struct {
	Logger       *slog.Logger
	EncMode      cbor.EncMode
	DecMode      cbor.DecMode
	Paths        []string
	UseNamedPipe bool
	Transport    ctaptransport.CBOR
}

type Option func(*Options)

func WithLogger(logger *slog.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
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

func WithPaths(paths ...string) Option {
	return func(opts *Options) {
		opts.Paths = paths
	}
}

func WithUseNamedPipes() Option {
	return func(opts *Options) {
		opts.UseNamedPipe = true
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
	oo := &Options{
		Logger:  slog.Default(),
		EncMode: encMode,
		DecMode: decMode,
	}

	for _, opt := range opts {
		opt(oo)
	}

	return oo
}
