package ctaphid

import (
	"bytes"
	"context"
	"errors"
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
	dev := &initOpenDevice{
		t:        t,
		cid:      transportTestCID,
		response: make(chan []byte, 1),
	}

	transport, err := Open(context.Background(), dev)
	require.NoError(t, err)
	assert.Equal(t, transportTestCID, transport.cid)

	require.NoError(t, transport.Close())
	assert.True(t, dev.closed)
}

func TestOpenCanceledLeavesDeviceOpen(t *testing.T) {
	dev := &failedOpenDevice{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := Open(ctx, dev)

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, dev.closed)
}

func TestOpenInitFailureLeavesDeviceOpen(t *testing.T) {
	dev := &failedOpenDevice{readErr: io.ErrUnexpectedEOF}

	_, err := Open(t.Context(), dev)

	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	var deviceErr *ctaptransport.IOError
	require.ErrorAs(t, err, &deviceErr)
	assert.Equal(t, ctaptransport.IORead, deviceErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	assert.False(t, invalidated)
	assert.False(t, dev.closed)
}

func TestOpenInitWriteFailureReturnsTypedIOError(t *testing.T) {
	dev := &failedOpenDevice{writeErr: io.ErrClosedPipe}

	_, err := Open(t.Context(), dev)

	require.ErrorIs(t, err, io.ErrClosedPipe)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOWrite, ioErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	assert.False(t, invalidated)
	assert.False(t, dev.closed)
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

func TestTransportCommandsCloseDeviceAfterWriteFailure(t *testing.T) {
	tests := []struct {
		name string
		call func(*Transport) error
	}{
		{
			name: "CBOR",
			call: func(transport *Transport) error {
				_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
				return err
			},
		},
		{
			name: "Ping",
			call: func(transport *Transport) error {
				_, err := transport.Ping(t.Context(), []byte("ping"))
				return err
			},
		},
		{name: "Wink", call: func(transport *Transport) error { return transport.Wink(t.Context()) }},
		{name: "Lock", call: func(transport *Transport) error { return transport.Lock(t.Context(), 1) }},
		{name: "Cancel", call: func(transport *Transport) error { return transport.Cancel(t.Context()) }},
		{
			name: "Vendor",
			call: func(transport *Transport) error {
				_, err := transport.Vendor(t.Context(), CTAPHID_VENDOR_FIRST, nil)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev := &failedOpenDevice{writeErr: io.ErrClosedPipe}
			transport := NewTransport(dev, transportTestCID)

			err := test.call(transport)

			require.ErrorIs(t, err, io.ErrClosedPipe)
			var ioErr *ctaptransport.IOError
			require.ErrorAs(t, err, &ioErr)
			assert.Equal(t, ctaptransport.IOWrite, ioErr.Operation)
			invalidatedErr, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
			require.True(t, ok)
			assert.Same(t, ioErr, invalidatedErr.Err)
			assert.True(t, dev.closed)
		})
	}
}

func TestTransportCBORKeepsDeviceOpenAfterResponseError(t *testing.T) {
	tests := []struct {
		name      string
		command   Command
		data      []byte
		wantError error
		wantCode  Error
	}{
		{
			name:      "invalid response message",
			command:   CTAPHID_CBOR,
			wantError: ErrInvalidResponseMessage,
		},
		{
			name:      "unexpected command",
			command:   CTAPHID_PING,
			wantError: ErrUnexpectedCommand,
		},
		{
			name:     "invalid channel",
			command:  CTAPHID_ERROR,
			data:     []byte{byte(ERR_INVALID_CHANNEL)},
			wantCode: ERR_INVALID_CHANNEL,
		},
		{
			name:    "CTAP error",
			command: CTAPHID_CBOR,
			data:    []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR)},
		},
		{
			name:    "other CTAPHID error",
			command: CTAPHID_ERROR,
			data:    []byte{byte(ERR_INVALID_LEN)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dev := newResponseDevice(rawResponseReport(transportTestCID, test.command, test.data))
			transport := NewTransport(dev, transportTestCID)

			_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})

			if test.wantError != nil {
				require.ErrorIs(t, err, test.wantError)
			} else if test.wantCode != 0 {
				requireCTAPHIDError(t, err, test.wantCode)
			} else {
				require.Error(t, err)
			}
			_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
			assert.False(t, invalidated)
			assert.False(t, dev.isClosed())
			require.NoError(t, transport.Close())
		})
	}
}

func TestTransportCBORContinuesOnSameChannelAfterUnexpectedCommand(t *testing.T) {
	dev := newResponseDevice(
		rawResponseReport(transportTestCID, CTAPHID_PING, nil),
		rawResponseReport(transportTestCID, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)}),
	)
	transport := NewTransport(dev, transportTestCID)
	t.Cleanup(func() {
		require.NoError(t, transport.Close())
	})

	_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	require.ErrorIs(t, err, ErrUnexpectedCommand)
	assert.False(t, dev.isClosed())

	response, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, response.StatusCode)
	assert.False(t, dev.isClosed())
}

func TestOpenDrainsReportsForOtherChannelsBeforeAllocation(t *testing.T) {
	dev := newMultiplexedDevice(transportTestCID)
	foreignReport := make([]byte, hidPacketSize)
	foreignCID := ChannelID{5, 6, 7, 8}
	copy(foreignReport, foreignCID[:])
	foreignReport[4] = 0 // Invalid without filtering because it is a continuation packet.
	dev.reads <- foreignReport

	transport, err := Open(t.Context(), dev)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, transport.Close())
	})
	assert.Equal(t, dev.cid, transport.cid)

	response, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, response.StatusCode)
}

func TestRetryChannelBusyRetriesAfterShortDelay(t *testing.T) {
	attempts := 0

	result, err := retryChannelBusy(t.Context(), func() (string, error) {
		attempts++
		if attempts == 1 {
			return "", &ErrorResponse{ErrorCode: ERR_CHANNEL_BUSY}
		}
		return "ok", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 2, attempts)
}

func TestRetryChannelBusyStopsWhenContextExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	attempts := 0

	_, err := retryChannelBusy(ctx, func() (struct{}, error) {
		attempts++
		return struct{}{}, &ErrorResponse{ErrorCode: ERR_CHANNEL_BUSY}
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, 1, attempts)
}

func TestTransportPreCanceledContextTakesPriorityOverValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name string
		call func(*Transport) error
	}{
		{
			name: "CBOR",
			call: func(transport *Transport) error {
				_, err := transport.CBOR(ctx, nil)
				return err
			},
		},
		{
			name: "Lock",
			call: func(transport *Transport) error {
				return transport.Lock(ctx, 11)
			},
		},
		{
			name: "Vendor",
			call: func(transport *Transport) error {
				_, err := transport.Vendor(ctx, 0, nil)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := NewTransport(&failedOpenDevice{}, transportTestCID)

			require.ErrorIs(t, test.call(transport), context.Canceled)
		})
	}
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
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	assert.False(t, invalidated)

	response, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorGetInfo)})
	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, response.StatusCode)
}

func TestTransportCBORReportsInvalidationWhenCanceledResponseCannotBeDrained(t *testing.T) {
	dev := newCancelDrainErrorDevice()
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

	cancelRequest := receive(t, dev.writes, "CANCEL was not written")
	assert.Equal(t, byte(CTAPHID_CANCEL)|INIT_PACKET_BIT, cancelRequest[5])

	err := receive(t, resultc, "Selection cancellation did not complete")
	require.ErrorIs(t, err, context.Canceled)
	invalidatedErr, ok := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	require.True(t, ok)
	require.ErrorIs(t, invalidatedErr.Err, context.Canceled)
	assert.True(t, dev.isClosed())
}

func TestTransportCBORPreservesReadError(t *testing.T) {
	dev := &readErrorDevice{err: io.ErrUnexpectedEOF}
	transport := NewTransport(dev, transportTestCID)

	_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorSelection)})

	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.NotErrorIs(t, err, context.Canceled)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	require.True(t, invalidated)
	assert.Equal(t, 1, dev.writes, "an unrelated read error must not trigger CTAPHID_CANCEL")
	assert.True(t, dev.closed)
}

func TestTransportCBORDoesNotCancelForContextErrorFromActiveContext(t *testing.T) {
	for _, readErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(readErr.Error(), func(t *testing.T) {
			dev := &readErrorDevice{err: readErr}
			transport := NewTransport(dev, transportTestCID)

			_, err := transport.CBOR(t.Context(), []byte{byte(protocol.AuthenticatorSelection)})

			require.ErrorIs(t, err, readErr)
			_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
			require.True(t, invalidated)
			assert.Equal(t, 1, dev.writes, "an error unrelated to the active context must not trigger CTAPHID_CANCEL")
			assert.True(t, dev.closed)
		})
	}
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
	err := receive(t, resultc, "Close did not interrupt Selection")
	require.ErrorIs(t, err, io.ErrClosedPipe)
	var deviceErr *ctaptransport.IOError
	require.ErrorAs(t, err, &deviceErr)
	assert.Equal(t, ctaptransport.IORead, deviceErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	require.True(t, invalidated)
}

func TestTransportCloseReturnsTypedIOError(t *testing.T) {
	dev := &failedOpenDevice{closeErr: io.ErrClosedPipe}
	transport := NewTransport(dev, transportTestCID)

	err := transport.Close()

	require.ErrorIs(t, err, io.ErrClosedPipe)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOClose, ioErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	assert.False(t, invalidated)
	assert.True(t, dev.closed)
}

type orderedDevice struct {
	response       *bytes.Reader
	responses      chan []byte
	writes         chan []byte
	releaseRequest chan struct{}
	cancelWritten  chan struct{}
	cborWrites     int
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
		responses:      make(chan []byte, 1),
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
		if d.response.Len() > 0 {
			return d.response.Read(p)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case response := <-d.responses:
			return copy(p, response), nil
		}
	}
}

func (d *orderedDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.writes <- bytes.Clone(p)
	switch p[5] {
	case byte(CTAPHID_CBOR) | INIT_PACKET_BIT:
		d.cborWrites++
		if d.cborWrites == 1 {
			<-d.releaseRequest
		} else {
			d.responses <- rawResponseReport(
				transportTestCID,
				CTAPHID_CBOR,
				[]byte{byte(ctaptransport.CTAP2_OK)},
			)
		}
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

type cancelDrainErrorDevice struct {
	writes        chan []byte
	cancelWritten chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
}

func newCancelDrainErrorDevice() *cancelDrainErrorDevice {
	return &cancelDrainErrorDevice{
		writes:        make(chan []byte, 2),
		cancelWritten: make(chan struct{}),
		closed:        make(chan struct{}),
	}
}

func (d *cancelDrainErrorDevice) Read(ctx context.Context, _ []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.cancelWritten:
		return 0, io.ErrUnexpectedEOF
	case <-d.closed:
		return 0, io.ErrClosedPipe
	}
}

func (d *cancelDrainErrorDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.writes <- bytes.Clone(p)
	if p[5] == byte(CTAPHID_CANCEL)|INIT_PACKET_BIT {
		close(d.cancelWritten)
	}
	return len(p), nil
}

func (d *cancelDrainErrorDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (d *cancelDrainErrorDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

type readErrorDevice struct {
	err    error
	writes int
	closed bool
}

func (d *readErrorDevice) Read(_ context.Context, _ []byte) (int, error) {
	return 0, d.err
}

func (d *readErrorDevice) Write(_ context.Context, p []byte) (int, error) {
	d.writes++
	return len(p), nil
}

func (d *readErrorDevice) Close() error {
	d.closed = true
	return nil
}

type responseDevice struct {
	mu        sync.Mutex
	responses [][]byte
	reads     chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newResponseDevice(responses ...[]byte) *responseDevice {
	return &responseDevice{
		responses: responses,
		reads:     make(chan []byte, 1),
		closed:    make(chan struct{}),
	}
}

func (d *responseDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case response := <-d.reads:
		return copy(p, response), nil
	}
}

func (d *responseDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	d.mu.Lock()
	var response []byte
	if len(d.responses) > 0 {
		response = d.responses[0]
		d.responses = d.responses[1:]
	}
	d.mu.Unlock()

	if response != nil {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-d.closed:
			return 0, io.ErrClosedPipe
		case d.reads <- bytes.Clone(response):
		}
	}
	return len(p), nil
}

func (d *responseDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}

func (d *responseDevice) isClosed() bool {
	select {
	case <-d.closed:
		return true
	default:
		return false
	}
}

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
	response chan []byte
	closed   bool
}

type failedOpenDevice struct {
	readErr  error
	writeErr error
	closeErr error
	closed   bool
}

func (d *failedOpenDevice) Read(ctx context.Context, _ []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if d.readErr != nil {
		return 0, d.readErr
	}
	return 0, io.EOF
}

func (d *failedOpenDevice) Write(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if d.writeErr != nil {
		return 0, d.writeErr
	}

	return len(p), nil
}

func (d *failedOpenDevice) Close() error {
	d.closed = true
	return d.closeErr
}

func (d *initOpenDevice) Write(_ context.Context, p []byte) (int, error) {
	d.t.Helper()
	require.Len(d.t, p, hidReportPacketSize)
	assert.Equal(d.t, byte(CTAPHID_INIT)|INIT_PACKET_BIT, p[5])
	nonce := bytes.Clone(p[8:16])
	response := append(bytes.Clone(nonce), d.cid[:]...)
	response = append(response, 2, 1, 0, 0, byte(CAPABILITY_CBOR))
	d.response <- rawResponseMessage(d.t, BROADCAST_CID, CTAPHID_INIT, response)
	close(d.response)
	return len(p), nil
}

func (d *initOpenDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case response, ok := <-d.response:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, response), nil
	}
}

func (d *initOpenDevice) Close() error {
	d.closed = true
	return nil
}
