package ctaphid

import (
	"io"
	"sync"

	ctaptransport "github.com/go-ctap/ctap/transport"
)

// Transport adapts a CTAPHID channel to the transport-independent CBOR API.
type Transport struct {
	device io.ReadWriteCloser
	cid    ChannelID
	mu     sync.Mutex
}

var _ ctaptransport.Device = (*Transport)(nil)

func NewTransport(device io.ReadWriteCloser, cid ChannelID) *Transport {
	return &Transport{device: device, cid: cid}
}

func (t *Transport) CBOR(data []byte) (ctaptransport.CBORResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return CBOR(t.device, t.cid, data)
}

func (t *Transport) Ping(data []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	response, err := Ping(t.device, t.cid, data)
	if err != nil {
		return nil, err
	}
	return response.Bytes, nil
}

func (t *Transport) Wink() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Wink(t.device, t.cid)
}

func (t *Transport) Lock(seconds uint8) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Lock(t.device, t.cid, seconds)
}

func (t *Transport) Cancel() error {
	// Cancel must be writable while CBOR is blocked waiting for a response.
	return Cancel(t.device, t.cid)
}

func (t *Transport) Vendor(command Command, data []byte) (VendorResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Vendor(t.device, t.cid, command, data)
}

func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.device.Close()
}
