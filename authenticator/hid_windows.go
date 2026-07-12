package authenticator

import (
	"context"
	"io"
	"iter"

	"github.com/Microsoft/go-winio"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/hidproxy"
	ghid "github.com/go-ctap/hid"
)

func Enumerate(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
			useNamedPipe, ok := v.(bool)
			if ok && useNamedPipe {
				dev, err := winio.DialPipeContext(ctx, hidproxy.NamedPipePath)
				if err != nil {
					yield(nil, err)
					return
				}
				defer func() {
					_ = dev.Close()
				}()

				msg, err := hidproxy.NewMessage(hidproxy.CommandEnumerate, nil)
				if err != nil {
					yield(nil, err)
					return
				}

				if _, err := msg.WriteTo(dev); err != nil {
					yield(nil, err)
					return
				}

				msg, err = hidproxy.ParseMessage(dev)
				if err != nil {
					yield(nil, err)
					return
				}

				devInfos := make([]*ghid.DeviceInfo, 0)
				if err := cbor.Unmarshal(msg.Data, &devInfos); err != nil {
					yield(nil, err)
					return
				}

				for _, devInfo := range devInfos {
					if !yield(devInfo, nil) {
						return
					}
				}

				return
			}
		}

		for devInfo, err := range ghid.Enumerate() {
			if !yield(devInfo, err) {
				return
			}
		}
	}
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			dev, err := winio.DialPipeContext(ctx, hidproxy.NamedPipePath)
			if err != nil {
				return nil, err
			}

			pMsg, err := hidproxy.NewMessage(hidproxy.CommandStart, path)
			if err != nil {
				_ = dev.Close()
				return nil, err
			}

			if _, err := pMsg.WriteTo(dev); err != nil {
				_ = dev.Close()
				return nil, err
			}

			return dev, nil
		}
	}

	return ghid.OpenPath(path)
}

func hidExit() error { return nil }
