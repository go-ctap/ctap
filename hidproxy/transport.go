package hidproxy

import (
	"context"
	"errors"

	"github.com/go-ctap/ctap/transport/ctaphid"
)

var ErrNotSupported = errors.New("hidproxy: not supported on this platform")

// OpenPath starts a raw CTAPHID proxy session.
func OpenPath(ctx context.Context, path string) (ctaphid.Device, error) {
	return openPath(ctx, path)
}

// Open starts a proxy session, allocates a CTAPHID channel, and returns an
// initialized transport. The returned transport owns the pipe connection.
func Open(ctx context.Context, path string) (*ctaphid.Transport, error) {
	device, err := OpenPath(ctx, path)
	if err != nil {
		return nil, err
	}
	transport, err := ctaphid.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}
	return transport, nil
}
