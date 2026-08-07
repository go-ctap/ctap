//go:build !windows

package hidproxy

import (
	"context"
	"iter"

	"github.com/go-ctap/ctap/transport/ctaphid"
	ghid "github.com/go-ctap/hid"
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
