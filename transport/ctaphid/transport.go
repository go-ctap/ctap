package ctaphid

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

// Transport adapts a CTAPHID channel to the transport-independent CBOR API.
// CBOR uses CTAPHID_CANCEL when its context is canceled. Device I/O receives
// the command context directly.
type Transport struct {
	device  Device
	cid     ChannelID
	mu      sync.Mutex
	writeMu sync.Mutex // serializes CTAPHID_CBOR and CTAPHID_CANCEL writes
}

// Device is the contextual I/O subset implemented by hid.Device and proxy
// connections.
type Device interface {
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}

var _ ctaptransport.Device = (*Transport)(nil)

// Open allocates a CTAPHID channel on device. It takes ownership of device and
// closes it if channel allocation fails. The returned Transport owns device on
// success.
func Open(ctx context.Context, device Device) (*Transport, error) {
	if device == nil {
		return nil, errors.New("ctaphid: nil device")
	}
	if err := ctx.Err(); err != nil {
		_ = device.Close()
		return nil, err
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		_ = device.Close()
		return nil, err
	}

	response, err := initChannel(ctx, device, BROADCAST_CID, nonce)
	if err != nil {
		_ = device.Close()
		return nil, err
	}

	return NewTransport(device, response.CID), nil
}

// NewTransport wraps an already allocated CTAPHID channel and takes ownership
// of device.
func NewTransport(device Device, cid ChannelID) *Transport {
	return &Transport{device: device, cid: cid}
}

// CBOR exchanges a CBOR command and sends CTAPHID_CANCEL when contextual device
// I/O reports that ctx is done.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	command, err := t.writeCBOR(ctx, data)
	if err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := readCBORResponse(ctx, t.device, t.cid, command)
	if err != nil && ctx.Err() != nil {
		_ = t.cancel(context.WithoutCancel(ctx))
		return response, ctx.Err()
	}
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	response, err := ping(ctx, t.device, t.cid, data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return response.Bytes, nil
}

func (t *Transport) Wink(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := wink(ctx, t.device, t.cid); err != nil {
		return err
	}
	return ctx.Err()
}

func (t *Transport) Lock(ctx context.Context, seconds uint8) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := lock(ctx, t.device, t.cid, seconds); err != nil {
		return err
	}
	return ctx.Err()
}

func (t *Transport) Cancel(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cancel(ctx, t.device, t.cid); err != nil {
		return err
	}
	return ctx.Err()
}

func (t *Transport) cancel(ctx context.Context) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return cancel(ctx, t.device, t.cid)
}

func (t *Transport) Vendor(ctx context.Context, command Command, data []byte) (VendorResponse, error) {
	if err := ctx.Err(); err != nil {
		return VendorResponse{}, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return VendorResponse{}, err
	}
	response, err := vendor(ctx, t.device, t.cid, command, data)
	if err != nil {
		return VendorResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return VendorResponse{}, err
	}
	return response, nil
}

func (t *Transport) Close() error {
	return t.device.Close()
}
