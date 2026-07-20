package discover

import (
	"context"
	"errors"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ghid "github.com/go-ctap/hid"
	"github.com/samber/lo"
)

func EnumerateFIDODevices(ctx context.Context, opts ...options.Option) ([]*ghid.DeviceInfo, error) {
	devInfos := make([]*ghid.DeviceInfo, 0)
	for devInfo, err := range authenticator.Enumerate(ctx, opts...) {
		if err != nil {
			return nil, err
		}

		devInfos = append(devInfos, devInfo)
	}

	return devInfos, nil
}

// SelectDevice allows selecting a device by confirming presence;
// useful while a user has many tokens connected. Works only with FIDO 2.1 tokens (including PRE).
func SelectDevice(ctx context.Context, opts ...options.Option) (*authenticator.Device, error) {
	oo := options.NewOptions(opts...)

	if oo.Paths == nil {
		devInfos, err := EnumerateFIDODevices(ctx, opts...)
		if err != nil {
			return nil, err
		}
		oo.Paths = lo.Map[*ghid.DeviceInfo, string](devInfos, func(devInfo *ghid.DeviceInfo, _ int) string {
			return devInfo.Path
		})
	}

	if len(oo.Paths) == 1 {
		return authenticator.OpenHID(ctx, oo.Paths[0], opts...)
	}

	devices := make([]*authenticator.Device, 0, len(oo.Paths))
	closeDevices := func(except *authenticator.Device) error {
		var closeErr error
		for _, dev := range devices {
			if dev == except {
				continue
			}
			closeErr = errors.Join(closeErr, dev.Close())
		}
		return closeErr
	}

	for _, p := range oo.Paths {
		dev, err := authenticator.OpenHID(ctx, p, opts...)
		if err != nil {
			return nil, errors.Join(err, closeDevices(nil))
		}

		info, err := dev.GetInfo(ctx)
		if err != nil {
			return nil, errors.Join(err, dev.Close(), closeDevices(nil))
		}
		if !info.Versions.Supports(protocol.FIDO_2_1) &&
			!info.Versions.Supports(protocol.FIDO_2_1_PRE) &&
			!info.Versions.Supports(protocol.FIDO_2_3) {
			if err := dev.Close(); err != nil {
				return nil, errors.Join(err, closeDevices(nil))
			}
			continue
		}

		devices = append(devices, dev)
	}

	if len(devices) == 0 {
		return nil, errors.New("no supported devices found")
	}

	type selectionResult struct {
		device *authenticator.Device
		err    error
	}
	results := make(chan selectionResult, len(devices))
	selectionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, dev := range devices {
		go func() {
			results <- selectionResult{device: dev, err: dev.Selection(selectionCtx)}
		}()
	}

	var (
		selectedDev  *authenticator.Device
		selectionErr error
		cleanupErr   error
		decided      bool
	)
	ctxDone := ctx.Done()
	for remaining := len(devices); remaining > 0; {
		select {
		case result := <-results:
			remaining--
			if result.err == nil && !decided && ctx.Err() == nil {
				decided = true
				selectedDev = result.device
				cancel()
				ctxDone = nil
				continue
			}
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				selectionErr = errors.Join(selectionErr, result.err)
			}
		case <-ctxDone:
			decided = true
			cancel()
			ctxDone = nil
		}
	}

	if selectedDev != nil {
		cleanupErr = closeDevices(selectedDev)
		if cleanupErr != nil {
			return nil, errors.Join(cleanupErr, selectedDev.Close())
		}
		return selectedDev, nil
	}
	if err := ctx.Err(); err != nil {
		cleanupErr = closeDevices(nil)
		return nil, errors.Join(err, cleanupErr)
	}
	cleanupErr = closeDevices(nil)
	return nil, errors.Join(selectionErr, cleanupErr)
}
