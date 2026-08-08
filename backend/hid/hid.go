// Package hid connects platform HID endpoints to the CTAPHID transport.
package hid

import (
	"context"
	"errors"
	"iter"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/ctaphid"
	ghid "github.com/telesma-app/hid"
)

// Devices returns the platform's FIDO HID endpoints.
func Devices(ctx context.Context) iter.Seq2[*ghid.DeviceInfo, error] {
	return func(yield func(*ghid.DeviceInfo, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}

		for info, err := range ghid.Enumerate(
			ghid.WithUsagePage(0xf1d0),
			ghid.WithUsage(0x01),
		) {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(info, err) {
				return
			}
		}
	}
}

// Enumerate opens the platform's FIDO HID endpoints as CTAP transports.
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

// Open opens a FIDO HID endpoint and allocates a CTAPHID channel. The returned
// transport owns the endpoint.
func Open(ctx context.Context, path string) (*ctaphid.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	device, err := ghid.OpenPath(path)
	if err != nil {
		return nil, err
	}

	transport, err := ctaphid.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}

	return transport, nil
}
