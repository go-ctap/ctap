//go:build !windows

package hidproxy

import (
	"context"
	"iter"

	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
)

func Devices(context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		yield(nil, ErrNotSupported)
	}
}

type DeviceEvent struct {
	Err error
}

func Events(context.Context) (<-chan DeviceEvent, error) {
	return nil, ErrNotSupported
}

func openPath(context.Context, string) (ctaphid.Device, error) {
	return nil, ErrNotSupported
}
