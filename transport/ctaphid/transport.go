package ctaphid

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

// Transport adapts a CTAPHID channel to the transport-independent CBOR API.
// CBOR uses CTAPHID_CANCEL when its context is canceled. Other commands check
// their context before and after synchronous I/O because CTAPHID has no
// cancellation command for them. Close may be called concurrently to interrupt
// blocked device I/O.
type Transport struct {
	device  io.ReadWriteCloser
	cid     ChannelID
	mu      sync.Mutex
	writeMu sync.Mutex // serializes CTAPHID_CBOR and CTAPHID_CANCEL writes
}

var _ ctaptransport.Device = (*Transport)(nil)

// Open allocates a CTAPHID channel on device. It takes ownership of device and
// closes it if channel allocation fails. The returned Transport owns device on
// success.
func Open(ctx context.Context, device io.ReadWriteCloser) (*Transport, error) {
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

	var response InitResponse
	err := withContextIO(ctx, device, func() error {
		var err error
		response, err = initChannel(device, BROADCAST_CID, nonce)
		return err
	})
	if err != nil {
		_ = device.Close()
		return nil, err
	}

	return NewTransport(device, response.CID), nil
}

// NewTransport wraps an already allocated CTAPHID channel and takes ownership
// of device.
func NewTransport(device io.ReadWriteCloser, cid ChannelID) *Transport {
	return &Transport{device: device, cid: cid}
}

// CBOR exchanges a CBOR command and cancels it when ctx is done. A canceled
// context sends nothing if the request has not started. Once an exchange
// starts, cancellation is observed only after the complete request is written.
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

	resultc := make(chan cborResult, 1)
	go func() {
		response, err := readCBORResponse(t.device, t.cid, command)
		resultc <- cborResult{response: response, err: err}
	}()

	select {
	case result := <-resultc:
		return result.response, result.err
	case <-ctx.Done():
		// Prefer a response that completed at the same time as cancellation; it
		// no longer has an active operation to cancel.
		select {
		case result := <-resultc:
			return result.response, result.err
		default:
		}

		cancelErr := t.cancel()
		result := <-resultc // drain the response to keep the channel usable
		if cancelErr != nil {
			return result.response, cancelErr
		}
		return result.response, ctx.Err()
	}
}

type cborResult struct {
	response ctaptransport.CBORResponse
	err      error
}

func (t *Transport) writeCBOR(ctx context.Context, data []byte) (protocol.Command, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return writeCBOR(t.device, t.cid, data)
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

	response, err := ping(t.device, t.cid, data)
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
	if err := wink(t.device, t.cid); err != nil {
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
	if err := lock(t.device, t.cid, seconds); err != nil {
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
	if err := cancel(t.device, t.cid); err != nil {
		return err
	}
	return ctx.Err()
}

func (t *Transport) cancel() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return cancel(t.device, t.cid)
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
	response, err := vendor(t.device, t.cid, command, data)
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

func withContextIO(ctx context.Context, device io.Closer, operation func() error) error {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = device.Close()
		close(done)
	})

	err := operation()
	if stop() {
		return err
	}

	<-done
	return ctx.Err()
}
