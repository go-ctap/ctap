package ctaphid

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var transportTestCID = ChannelID{1, 2, 3, 4}

func TestOpenAllocatesChannelAndTransfersDevice(t *testing.T) {
	dev := &initOpenDevice{t: t, cid: transportTestCID}

	transport, err := Open(context.Background(), dev)
	require.NoError(t, err)
	assert.Equal(t, transportTestCID, transport.cid)

	require.NoError(t, transport.Close())
	assert.True(t, dev.closed)
}

func TestTransportCBORPreCanceledWritesNothing(t *testing.T) {
	dev := newOrderedDevice(t)
	transport := NewTransport(dev, transportTestCID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, dev.writes)
}

func TestTransportCBORWritesSelectionBeforeCancel(t *testing.T) {
	dev := newOrderedDevice(t)
	transport := NewTransport(dev, transportTestCID)
	ctx, cancel := context.WithCancel(context.Background())

	resultc := make(chan error, 1)
	go func() {
		_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})
		resultc <- err
	}()

	request := receive(t, dev.writes, "Selection request was not written")
	assert.Equal(t, byte(CTAPHID_CBOR)|INIT_PACKET_BIT, request[5])
	cancel()

	select {
	case <-dev.writes:
		t.Fatal("CANCEL was written before the Selection request completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(dev.releaseRequest)
	cancelRequest := receive(t, dev.writes, "CANCEL was not written")
	assert.Equal(t, byte(CTAPHID_CANCEL)|INIT_PACKET_BIT, cancelRequest[5])

	err := receive(t, resultc, "Selection cancellation did not complete")
	require.ErrorIs(t, err, context.Canceled)
}

func TestTransportCBORPreservesReadErrorWhenContextIsCanceledConcurrently(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dev := &cancelingErrorDevice{cancel: cancel}
	transport := NewTransport(dev, transportTestCID)

	_, err := transport.CBOR(ctx, []byte{byte(protocol.AuthenticatorSelection)})

	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.NotErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, dev.writes, "an unrelated read error must not trigger CTAPHID_CANCEL")
}

func TestTransportCloseInterruptsBlockedCBOR(t *testing.T) {
	dev := newBlockingDevice()
	transport := NewTransport(dev, transportTestCID)
	resultc := make(chan error, 1)
	go func() {
		_, err := transport.CBOR(context.Background(), []byte{byte(protocol.AuthenticatorSelection)})
		resultc <- err
	}()

	receive(t, dev.writes, "Selection request was not written")
	require.NoError(t, transport.Close())
	require.ErrorIs(t, receive(t, resultc, "Close did not interrupt Selection"), io.ErrClosedPipe)
}

func receive[T any](t *testing.T, ch <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
		var zero T
		return zero
	}
}

type orderedDevice struct {
	response       *bytes.Reader
	writes         chan []byte
	releaseRequest chan struct{}
	cancelWritten  chan struct{}
}

func newOrderedDevice(t *testing.T) *orderedDevice {
	t.Helper()
	return &orderedDevice{
		response: bytes.NewReader(rawResponseMessage(
			t,
			transportTestCID,
			CTAPHID_CBOR,
			[]byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL)},
		)),
		writes:         make(chan []byte, 2),
		releaseRequest: make(chan struct{}),
		cancelWritten:  make(chan struct{}),
	}
}

func (d *orderedDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.cancelWritten:
		return d.response.Read(p)
	}
}

func (d *orderedDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.writes <- bytes.Clone(p)
	switch p[5] {
	case byte(CTAPHID_CBOR) | INIT_PACKET_BIT:
		<-d.releaseRequest
	case byte(CTAPHID_CANCEL) | INIT_PACKET_BIT:
		close(d.cancelWritten)
	}
	return len(p), nil
}

func (d *orderedDevice) Close() error { return nil }

type blockingDevice struct {
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

type cancelingErrorDevice struct {
	cancel context.CancelFunc
	writes int
}

func (d *cancelingErrorDevice) Read(_ context.Context, _ []byte) (int, error) {
	d.cancel()
	return 0, io.ErrUnexpectedEOF
}

func (d *cancelingErrorDevice) Write(_ context.Context, p []byte) (int, error) {
	d.writes++
	return len(p), nil
}

func (d *cancelingErrorDevice) Close() error { return nil }

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{
		writes: make(chan []byte, 1),
		closed: make(chan struct{}),
	}
}

func (d *blockingDevice) Read(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *blockingDevice) Write(_ context.Context, p []byte) (int, error) {
	d.writes <- bytes.Clone(p)
	return len(p), nil
}

func (d *blockingDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

type initOpenDevice struct {
	t        *testing.T
	cid      ChannelID
	response *bytes.Reader
	closed   bool
}

func (d *initOpenDevice) Write(_ context.Context, p []byte) (int, error) {
	d.t.Helper()
	require.Len(d.t, p, hidReportPacketSize)
	assert.Equal(d.t, byte(CTAPHID_INIT)|INIT_PACKET_BIT, p[5])
	nonce := bytes.Clone(p[8:16])
	response := append(bytes.Clone(nonce), d.cid[:]...)
	response = append(response, 2, 1, 0, 0, byte(CAPABILITY_CBOR))
	d.response = bytes.NewReader(rawResponseMessage(d.t, BROADCAST_CID, CTAPHID_INIT, response))
	return len(p), nil
}

func (d *initOpenDevice) Read(_ context.Context, p []byte) (int, error) {
	return d.response.Read(p)
}

func (d *initOpenDevice) Close() error {
	d.closed = true
	return nil
}
