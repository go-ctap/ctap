//go:build linux || darwin

package authenticator

import (
	"context"
	"io"
	"iter"

	ghid "github.com/go-ctap/hid"
)

func Enumerate(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
			useNamedPipe, ok := v.(bool)
			if ok && useNamedPipe {
				yield(nil, ErrNotSupported)
				return
			}
		}

		for devInfo, err := range ghid.Enumerate(
			ghid.WithUsagePage(0xf1d0),
			ghid.WithUsage(0x01),
		) {
			if !yield(devInfo, err) {
				return
			}
		}
	}
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			return nil, ErrNotSupported
		}
	}

	return ghid.OpenPath(path)
}

func hidExit() error { return nil }
