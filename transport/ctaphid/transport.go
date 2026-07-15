package ctaphid

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	ghid "github.com/go-ctap/hid"
)

// Transport adapts a CTAPHID channel to the transport-independent CBOR API.
// CBOR uses CTAPHID_CANCEL when its context is canceled. A background reader
// continuously drains the shared HID endpoint and retains this channel's
// reports for contextual command reads.
type Transport struct {
	device  Device
	cid     ChannelID
	mu      sync.Mutex
	writeMu sync.Mutex // serializes CTAPHID_CBOR and CTAPHID_CANCEL writes
}

// Device is the contextual I/O subset implemented by hid.Device and proxy
// connections.
type Device interface {
	ghid.ContextReadWriter
	io.Closer
}

var _ ctaptransport.Device = (*Transport)(nil)

const channelBusyRetryDelay = 100 * time.Millisecond

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

// CBOR exchanges a CBOR command and cancels it when response waiting is canceled.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := retryChannelBusy(ctx, func() (ctaptransport.CBORResponse, error) {
		command, err := t.writeCBOR(ctx, data)
		if err != nil {
			if ioErr, ok := errors.AsType[*ctaptransport.IOError](err); ok && ioErr.Operation == ctaptransport.IOWrite {
				_ = t.device.Close()
			}

			return ctaptransport.CBORResponse{}, err
		}

		response, err := readCBORResponse(ctx, t.device, t.cid, command)
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			cancelCtx := context.WithoutCancel(ctx)
			if cancelErr := t.cancel(cancelCtx); cancelErr == nil {
				// The canceled request still completes with a terminal response.
				_, _ = readCBORResponse(cancelCtx, t.device, t.cid, command)
			}
		}
		return response, err
	})
	return response, err
}

func (t *Transport) writeCBOR(ctx context.Context, data []byte) (protocol.Command, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return writeCBOR(ctx, t.device, t.cid, data)
}

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
		return nil, err
	}
	return response.Bytes, nil
}

func (t *Transport) Wink(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return retryChannelBusyError(ctx, func() error {
		return Wink(ctx, t.device, t.cid)
	})
}

func (t *Transport) Lock(ctx context.Context, seconds uint8) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return retryChannelBusyError(ctx, func() error {
		return Lock(ctx, t.device, t.cid, seconds)
	})
}

func (t *Transport) Cancel(ctx context.Context) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return Cancel(ctx, t.device, t.cid)
}

func (t *Transport) cancel(ctx context.Context) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return Cancel(ctx, t.device, t.cid)
}

func (t *Transport) Vendor(ctx context.Context, command Command, data []byte) (VendorResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return VendorResponse{}, err
	}
	return retryChannelBusy(ctx, func() (VendorResponse, error) {
		return Vendor(ctx, t.device, t.cid, command, data)
	})
}

func (t *Transport) Close() error {
	return t.device.Close()
}
