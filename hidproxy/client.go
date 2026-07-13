//go:build !windows

package hidproxy

import (
	"context"
	"io"
	"iter"

	ghid "github.com/go-ctap/hid"
)

func Enumerate(context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		yield(nil, ErrNotSupported)
	}
}

func openPath(context.Context, string) (io.ReadWriteCloser, error) {
	return nil, ErrNotSupported
}
