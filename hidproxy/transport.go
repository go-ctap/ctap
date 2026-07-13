package hidproxy

import (
	"context"
	"crypto/rand"
	"errors"
	"io"

	"github.com/go-ctap/ctap/transport/ctaphid"
)

var ErrNotSupported = errors.New("hidproxy: not supported on this platform")

// OpenPath starts a raw CTAPHID proxy session.
func OpenPath(ctx context.Context, path string) (io.ReadWriteCloser, error) {
	return openPath(ctx, path)
}

// Open starts a proxy session, allocates a CTAPHID channel, and returns an
// initialized transport. The returned transport owns the pipe connection.
func Open(ctx context.Context, path string) (*ctaphid.Transport, error) {
	device, err := OpenPath(ctx, path)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = device.Close()
		}
	}()

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	transport, err := initCTAPHID(device, nonce)
	if err != nil {
		return nil, err
	}

	cleanup = false
	return transport, nil
}

func initCTAPHID(device io.ReadWriteCloser, nonce []byte) (*ctaphid.Transport, error) {
	response, err := ctaphid.Init(device, ctaphid.BROADCAST_CID, nonce)
	if err != nil {
		return nil, err
	}
	return ctaphid.NewTransport(device, response.CID), nil
}
