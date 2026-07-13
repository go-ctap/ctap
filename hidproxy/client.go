//go:build !windows

package hidproxy

import (
	"context"
	"iter"

	"github.com/go-ctap/ctap/transport/ctaphid"
	ghid "github.com/go-ctap/hid"
)

func Enumerate(context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		yield(nil, ErrNotSupported)
	}
}

func openPath(context.Context, string) (ctaphid.Device, error) {
	return nil, ErrNotSupported
}
