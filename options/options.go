package options

import (
	"log/slog"

	"github.com/fxamacker/cbor/v2"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

type Options struct {
	Logger       *slog.Logger
	EncMode      cbor.EncMode
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
	oo := &Options{
		Logger:  slog.Default(),
		EncMode: encMode,
	}

	for _, opt := range opts {
		opt(oo)
	}

	return oo
}
