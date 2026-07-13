package authenticator

import (
	"context"
	"iter"

	"github.com/go-ctap/ctap/hidproxy"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/transport/ctaphid"
	ghid "github.com/go-ctap/hid"
)

func Enumerate(ctx context.Context, opts ...options.Option) iter.Seq2[*ghid.DeviceInfo, error] {
	oo := options.NewOptions(opts...)
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}
		if oo.UseNamedPipe {
			for device, err := range hidproxy.Enumerate(ctx) {
				if !yield(device, err) {
					return
				}
			}
			return
		}

		for devInfo, err := range ghid.Enumerate() {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(devInfo, err) {
				return
			}
		}
	}
}

func OpenPath(ctx context.Context, path string, opts ...options.Option) (dev ctaphid.Device, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.NewOptions(opts...).UseNamedPipe {
		return hidproxy.OpenPath(ctx, path)
	}

	dev, err = ghid.OpenPath(path)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = dev.Close()
		return nil, err
	}
	return dev, nil
}
