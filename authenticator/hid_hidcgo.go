//go:build hid_cgo

package authenticator

import (
	"context"
	"errors"
	"io"
	"iter"

	ghid "github.com/go-ctap/hid"
	"github.com/sstallion/go-hid"
)

func Enumerate(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		v := ctx.Value(CtxKeyUseNamedPipe)
		if v != nil {
			useNamedPipe, ok := v.(bool)
			if ok && useNamedPipe {
				yield(nil, ErrNotSupported)
				return
			}
		}

		breakErr := errors.New("break")

		if err := hid.Enumerate(hid.VendorIDAny, hid.ProductIDAny, func(info *hid.DeviceInfo) error {
			if !yield(&ghid.DeviceInfo{
				Path:         info.Path,
				VendorID:     info.VendorID,
				ProductID:    info.ProductID,
				SerialNbr:    info.SerialNbr,
				ReleaseNbr:   info.ReleaseNbr,
				MfrStr:       info.MfrStr,
				ProductStr:   info.ProductStr,
				UsagePage:    info.UsagePage,
				Usage:        info.Usage,
				InterfaceNbr: info.InterfaceNbr,
			}, nil) {
				return breakErr
			}

			return nil
		}); err != nil && !errors.Is(err, breakErr) {
			yield(nil, err)
			return
		}
	}
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	v := ctx.Value(CtxKeyUseNamedPipe)
	if v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			return nil, ErrNotSupported
		}
	}

	return hid.OpenPath(path)
}

func hidExit() error { return hid.Exit() }
