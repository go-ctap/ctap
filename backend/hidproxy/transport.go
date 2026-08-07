package hidproxy

import (
	"context"
	"errors"
	"iter"

	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
)

var ErrNotSupported = errors.New("hidproxy: not supported on this platform")

// Enumerate opens the proxy's FIDO HID endpoints as CTAP transports.
func Enumerate(ctx context.Context) iter.Seq2[ctaptransport.Device, error] {
	return func(yield func(ctaptransport.Device, error) bool) {
		for info, err := range Devices(ctx) {
			if err != nil {
				yield(nil, err)
				return
			}

			transport, err := Open(ctx, info.Path)
			if !yield(transport, err) {
				return
			}
		}
	}
}

// Open starts a proxy session, allocates a CTAPHID channel, and returns an
// initialized transport. The returned transport owns the pipe connection.
func Open(ctx context.Context, path string) (*ctaphid.Transport, error) {
	device, err := openPath(ctx, path)
	if err != nil {
		return nil, err
	}

	transport, err := ctaphid.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}

	return transport, nil
}
