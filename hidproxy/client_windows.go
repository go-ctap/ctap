//go:build windows

package hidproxy

import (
	"context"
	"io"
	"iter"

	"github.com/Microsoft/go-winio"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/transport/ctaphid"
	ghid "github.com/go-ctap/hid"
)

// Enumerate returns HID authenticators reported by the proxy.
func Enumerate(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		pipe, err := winio.DialPipeContext(ctx, NamedPipePath)
		if err != nil {
			yield(nil, err)
			return
		}
		defer pipe.Close()

		message, err := NewMessage(CommandEnumerate, nil)
		if err != nil {
			yield(nil, err)
			return
		}
		err = withContextIO(ctx, pipe, func() error {
			if _, writeErr := message.WriteTo(pipe); writeErr != nil {
				return writeErr
			}
			message, err = ParseMessage(pipe)
			return err
		})
		if err != nil {
			yield(nil, err)
			return
		}

		var devices []*ghid.DeviceInfo
		if err := cbor.Unmarshal(message.Data, &devices); err != nil {
			yield(nil, err)
			return
		}

		for _, device := range devices {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(device, nil) {
				return
			}
		}
	}
}

func openPath(ctx context.Context, path string) (ctaphid.Device, error) {
	pipe, err := winio.DialPipeContext(ctx, NamedPipePath)
	if err != nil {
		return nil, err
	}

	message, err := NewMessage(CommandStart, path)
	if err != nil {
		_ = pipe.Close()
		return nil, err
	}
	if err := withContextIO(ctx, pipe, func() error {
		_, writeErr := message.WriteTo(pipe)
		return writeErr
	}); err != nil {
		_ = pipe.Close()
		return nil, err
	}

	return &contextDevice{ReadWriteCloser: pipe}, nil
}

type contextDevice struct {
	io.ReadWriteCloser
}

func (d *contextDevice) Read(ctx context.Context, p []byte) (n int, err error) {
	err = withContextIO(ctx, d, func() error {
		n, err = d.ReadWriteCloser.Read(p)
		return err
	})
	return n, err
}

func (d *contextDevice) Write(ctx context.Context, p []byte) (n int, err error) {
	err = withContextIO(ctx, d, func() error {
		n, err = d.ReadWriteCloser.Write(p)
		return err
	})
	return n, err
}
