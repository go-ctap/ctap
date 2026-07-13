//go:build windows

package hidproxy

import (
	"context"
	"io"
	"iter"

	"github.com/Microsoft/go-winio"
	"github.com/fxamacker/cbor/v2"
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
		if _, err := message.WriteTo(pipe); err != nil {
			yield(nil, err)
			return
		}

		message, err = ParseMessage(pipe)
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
			if !yield(device, nil) {
				return
			}
		}
	}
}

func openPath(ctx context.Context, path string) (io.ReadWriteCloser, error) {
	pipe, err := winio.DialPipeContext(ctx, NamedPipePath)
	if err != nil {
		return nil, err
	}

	message, err := NewMessage(CommandStart, path)
	if err != nil {
		_ = pipe.Close()
		return nil, err
	}
	if _, err := message.WriteTo(pipe); err != nil {
		_ = pipe.Close()
		return nil, err
	}

	return pipe, nil
}
