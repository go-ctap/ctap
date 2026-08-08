package ctaphid

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	ghid "github.com/telesma-app/hid"
)

// Transport adapts a CTAPHID channel to the transport-independent CBOR API.
// CBOR uses CTAPHID_CANCEL when its context is canceled. A background reader
// continuously drains the shared HID endpoint and retains this channel's
// reports for contextual command reads.
type Transport struct {
	device     Device
	cid        ChannelID
	mu         sync.Mutex
	writeMu    sync.Mutex // serializes CTAPHID_CBOR and CTAPHID_CANCEL writes
	activeCBOR atomic.Bool
}

// Device is the contextual I/O subset implemented by hid.Device and proxy
// connections.
type Device interface {
	ghid.ContextReadWriter
	io.Closer
}

var _ ctaptransport.Device = (*Transport)(nil)

const (
	channelBusyRetryDelay = 100 * time.Millisecond
	closeCancelTimeout    = 250 * time.Millisecond
)

func retryChannelBusy[T any](ctx context.Context, operation func() (T, error)) (T, error) {
	for {
		result, err := operation()
		if response, ok := errors.AsType[*ErrorResponse](err); !ok || response.ErrorCode != ERR_CHANNEL_BUSY {
			return result, err
		}

		timer := time.NewTimer(channelBusyRetryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			var zero T
			return zero, ctx.Err()

		case <-timer.C:
		}
	}
}

func retryChannelBusyError(ctx context.Context, operation func() error) error {
	_, err := retryChannelBusy(ctx, func() (struct{}, error) {
		return struct{}{}, operation()
	})

	return err
}

func isDeviceIOError(err error) bool {
	if ioErr, ok := errors.AsType[*ctaptransport.IOError](err); ok {
		switch ioErr.Operation {
		case ctaptransport.IORead, ctaptransport.IOWrite:
			return true
		}
	}

	return false
}

func (t *Transport) closeOnIOError(err error) error {
	if !isDeviceIOError(err) {
		return err
	}

	_ = t.device.Close()
	return &ctaptransport.DeviceInvalidatedError{Err: err}
}

// Open allocates a CTAPHID channel on device. The caller retains ownership of
// device if Open returns an error. The returned Transport owns device on
// success.
func Open(ctx context.Context, device Device) (*Transport, error) {
	if device == nil {
		return nil, errors.New("ctaphid: nil device")
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	channel := newChannelDevice(device, BROADCAST_CID)
	response, err := retryChannelBusy(ctx, func() (InitResponse, error) {
		return Init(ctx, channel, BROADCAST_CID, nonce)
	})
	if err != nil {
		channel.stop()
		return nil, err
	}
	channel.setCID(response.CID)

	return &Transport{device: channel, cid: response.CID}, nil
}

// NewTransport wraps an already allocated CTAPHID channel and takes ownership
// of device.
func NewTransport(device Device, cid ChannelID) *Transport {
	return &Transport{
		device: newChannelDevice(device, cid),
		cid:    cid,
	}
}

// CBOR exchanges one CTAP command on this channel. Canceling ctx sends
// CTAPHID_CANCEL and drains the command's terminal response before returning.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	t.activeCBOR.Store(true)
	defer t.activeCBOR.Store(false)

	response, err := retryChannelBusy(ctx, func() (ctaptransport.CBORResponse, error) {
		return t.exchangeCBOR(ctx, data)
	})

	return response, t.closeOnIOError(err)
}

func (t *Transport) exchangeCBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	command, err := t.writeCBOR(ctx, data)
	if err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := readCBORResponse(ctx, t.device, t.cid, command)
	ctxErr := ctx.Err()
	if ctxErr == nil || !errors.Is(err, ctxErr) {
		return response, err
	}

	return t.cancelAndDrainCBOR(ctx, command, response, err)
}

func (t *Transport) cancelAndDrainCBOR(
	ctx context.Context,
	command protocol.Command,
	response ctaptransport.CBORResponse,
	originalErr error,
) (ctaptransport.CBORResponse, error) {
	cancelCtx := context.WithoutCancel(ctx)
	cancelErr := t.Cancel(cancelCtx)
	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](cancelErr); invalidated {
		return response, &ctaptransport.DeviceInvalidatedError{Err: originalErr}
	}
	if cancelErr != nil {
		return response, originalErr
	}

	// CTAPHID_CANCEL has no response of its own. The canceled CBOR request still
	// completes with CTAP2_ERR_KEEPALIVE_CANCEL, which must be drained before the
	// channel can carry another request.
	_, drainErr := readCBORResponse(cancelCtx, t.device, t.cid, command)
	if _, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](t.closeOnIOError(drainErr)); invalidated {
		return response, &ctaptransport.DeviceInvalidatedError{Err: originalErr}
	}

	return response, originalErr
}

func (t *Transport) writeCBOR(ctx context.Context, data []byte) (protocol.Command, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	return writeCBOR(ctx, t.device, t.cid, data)
}

// Ping checks channel liveness and returns the echoed payload.
func (t *Transport) Ping(ctx context.Context, data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	response, err := retryChannelBusy(ctx, func() (PingResponse, error) {
		return Ping(ctx, t.device, t.cid, data)
	})
	if err != nil {
		return nil, t.closeOnIOError(err)
	}

	return response.Bytes, nil
}

// Wink asks the authenticator to signal its physical presence.
func (t *Transport) Wink(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	err := retryChannelBusyError(ctx, func() error {
		return Wink(ctx, t.device, t.cid)
	})

	return t.closeOnIOError(err)
}

// Lock controls the CTAPHID channel lock.
func (t *Transport) Lock(ctx context.Context, seconds uint8) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	err := retryChannelBusyError(ctx, func() error {
		return Lock(ctx, t.device, t.cid, seconds)
	})

	return t.closeOnIOError(err)
}

// Cancel aborts the active CBOR request on this channel.
func (t *Transport) Cancel(ctx context.Context) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}

	err := Cancel(ctx, t.device, t.cid)
	return t.closeOnIOError(err)
}

// Vendor exchanges one vendor-specific CTAPHID command.
func (t *Transport) Vendor(ctx context.Context, command Command, data []byte) (VendorResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return VendorResponse{}, err
	}

	response, err := retryChannelBusy(ctx, func() (VendorResponse, error) {
		return Vendor(ctx, t.device, t.cid, command, data)
	})

	return response, t.closeOnIOError(err)
}

// Close cancels an active CBOR exchange before releasing the HID connection.
func (t *Transport) Close() error {
	if t.activeCBOR.Load() {
		ctx, cancel := context.WithTimeout(context.Background(), closeCancelTimeout)
		_ = t.Cancel(ctx)
		cancel()
	}

	return t.device.Close()
}
