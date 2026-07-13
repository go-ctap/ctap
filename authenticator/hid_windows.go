package authenticator

import (
	"context"
	"io"
	"iter"

	"github.com/go-ctap/ctap/hidproxy"
	ghid "github.com/go-ctap/hid"
)

func Enumerate(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		if useNamedPipe(ctx) {
			for device, err := range hidproxy.Enumerate(ctx) {
				if !yield(device, err) {
					return
				}
			}
			return
		}

		for devInfo, err := range ghid.Enumerate() {
			if !yield(devInfo, err) {
				return
			}
		}
	}
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	if useNamedPipe(ctx) {
		return hidproxy.OpenPath(ctx, path)
	}

	return ghid.OpenPath(path)
}
