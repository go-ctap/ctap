package iso7816

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	baseiso7816 "github.com/go-ctap/iso7816"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type exchange struct {
	request  []byte
	response []byte
	err      error
	after    func()
}

type fakeCard struct {
	t          *testing.T
	exchanges  []exchange
	closeErr   error
	closed     bool
	closeCalls int
}

func (c *fakeCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	require.NotEmpty(c.t, c.exchanges, "unexpected APDU: %x", apdu)
	next := c.exchanges[0]
	c.exchanges = c.exchanges[1:]
	assert.Equal(c.t, next.request, apdu)
	response := bytes.Clone(next.response)
	if next.after != nil {
		next.after()
	}
	return response, next.err
}

func (c *fakeCard) Close() error {
	c.closeCalls++
	c.closed = true
	return c.closeErr
}

func newFakeTransport(t *testing.T, exchanges ...exchange) (*Transport, *fakeCard) {
	t.Helper()
	card := &fakeCard{t: t, exchanges: append([]exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte(protocol.FIDO_2_0), 0x90, 0x00),
	}}, exchanges...)}

	transport, err := New(context.Background(), card)
	require.NoError(t, err)
	return transport, card
}

func commandBytes(t testing.TB, command baseiso7816.Command) []byte {
	t.Helper()
	apdu, err := command.MarshalBinary()
	require.NoError(t, err)
	return apdu
}

func TestNewSelectsFIDOApplet(t *testing.T) {
	transport, card := newFakeTransport(t)

	assert.Equal(t, protocol.FIDO_2_0, transport.Version())
	require.Empty(t, card.exchanges)
}

func TestNewAcceptsCombinedCTAP1AndCTAP2Version(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte(protocol.U2F_V2), 0x90, 0x00),
	}}}

	transport, err := New(context.Background(), card)

	require.NoError(t, err)
	assert.Equal(t, protocol.U2F_V2, transport.Version())
}

func TestNewReassemblesChainedSelectionResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{
		{request: commandBytes(t, selectAppletCommand), response: []byte("FIDO_"), err: nil},
	}}
	card.exchanges[0].response = append(card.exchanges[0].response, 0x61, 0x03)
	card.exchanges = append(card.exchanges, exchange{
		request:  []byte{0x00, 0xc0, 0x00, 0x00, 0x03},
		response: []byte{'2', '_', '0', 0x90, 0x00},
	})

	transport, err := New(context.Background(), card)

	require.NoError(t, err)
	assert.Equal(t, protocol.FIDO_2_0, transport.Version())
}

func TestNewRejectsUnsupportedSelectionVersion(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte("OTHER"), 0x90, 0x00),
	}}}

	_, err := New(context.Background(), card)

	require.ErrorIs(t, err, ErrUnsupportedVersion)
	assert.False(t, card.closed, "the caller retains ownership when initialization fails")
}

func TestCBORShortAPDU(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa1, 0x01, 0x02, 0x90, 0x00},
	})

	response, err := transport.CBOR(context.Background(), []byte{0x04})

	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       []byte{0xa1, 0x01, 0x02},
	}, response)
	require.Empty(t, card.exchanges)
}

func TestCBORUsesShortCommandChaining(t *testing.T) {
	command := append([]byte{0x01}, bytes.Repeat([]byte{0xaa}, 249)...)
	transport, card := newFakeTransport(t,
		exchange{
			request: slicesConcat(
				[]byte{0x90, 0x10, 0x00, 0x00, 0xf0},
				command[:shortCommandFragmentSize],
			),
			response: []byte{0x90, 0x00},
		},
		exchange{
			request: slicesConcat(
				[]byte{0x80, 0x10, 0x80, 0x00, 0x0a},
				command[shortCommandFragmentSize:],
				[]byte{0x00},
			),
			response: []byte{0x00, 0x90, 0x00},
		},
	)

	response, err := transport.CBOR(context.Background(), command)

	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, response.StatusCode)
	require.Empty(t, card.exchanges)
}

func TestCBORReassemblesISOResponseChaining(t *testing.T) {
	transport, card := newFakeTransport(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x00, 0xa1, 0x61, 0x02},
		},
		exchange{
			request:  []byte{0x80, 0xc0, 0x00, 0x00, 0x02},
			response: []byte{0x01, 0x9f, 0x01},
		},
		exchange{
			request:  []byte{0x80, 0xc0, 0x00, 0x00, 0x01},
			response: []byte{0x02, 0x90, 0x00},
		},
	)

	response, err := transport.CBOR(context.Background(), []byte{0x04})

	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       []byte{0xa1, 0x01, 0x02},
	}, response)
	require.Empty(t, card.exchanges)
}

func TestCBORPollsStatusResponses(t *testing.T) {
	transport, card := newFakeTransport(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x01, 0x91, 0x00},
		},
		exchange{
			request:  commandBytes(t, getResponseCommand),
			response: []byte{0x02, 0x91, 0x00},
		},
		exchange{
			request:  commandBytes(t, getResponseCommand),
			response: []byte{0x00, 0xa0, 0x90, 0x00},
		},
	)

	response, err := transport.CBOR(context.Background(), []byte{0x04})

	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       []byte{0xa0},
	}, response)
	require.Empty(t, card.exchanges)
}

func TestCBORCancelsStatusPollingWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x02, 0x91, 0x00},
			after:    cancel,
		},
		exchange{
			request:  commandBytes(t, cancelGetResponseCommand),
			response: []byte{byte(ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL), 0x90, 0x00},
		},
	)

	_, err := transport.CBOR(ctx, []byte{0x04})

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, card.closed)
	require.Empty(t, card.exchanges)
}

func TestCBORInvalidatesTransportWhenStatusCancellationIsRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t,
		exchange{
			request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
			response: []byte{0x02, 0x91, 0x00},
			after:    cancel,
		},
		exchange{
			request:  commandBytes(t, cancelGetResponseCommand),
			response: []byte{0x6a, 0x86},
		},
	)

	_, err := transport.CBOR(ctx, []byte{0x04})

	require.ErrorIs(t, err, context.Canceled)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	require.True(t, invalidated)
	assert.True(t, card.closed)
	assert.Equal(t, 1, card.closeCalls)
	require.Empty(t, card.exchanges)
}

func TestCBORPreservesFinalResponseWhenContextIsCanceledConcurrently(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa0, 0x90, 0x00},
		after:    cancel,
	})

	response, err := transport.CBOR(ctx, []byte{0x04})

	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, response.StatusCode)
	assert.Equal(t, []byte{0xa0}, response.Data)
	require.Empty(t, card.exchanges)
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR), 0x90, 0x00},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	var ctapErr *ctaptransport.CTAPError
	require.ErrorAs(t, err, &ctapErr)
	assert.Equal(t, protocol.AuthenticatorGetInfo, ctapErr.Command)
	assert.Equal(t, ctaptransport.CTAP2_ERR_INVALID_CBOR, ctapErr.StatusCode)
}

func TestCBORReturnsTypedAPDUError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x6a, 0x82},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	var apduErr *baseiso7816.APDUError
	require.ErrorAs(t, err, &apduErr)
	assert.Equal(t, byte(0x6a), apduErr.SW1)
	assert.Equal(t, byte(0x82), apduErr.SW2)
}

func TestCBORRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{name: "missing status word", response: []byte{0x90}},
		{name: "missing CTAP status", response: []byte{0x90, 0x00}},
		{name: "missing polling status", response: []byte{0x91, 0x00}},
		{name: "extra polling status", response: []byte{0x01, 0x02, 0x91, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, _ := newFakeTransport(t, exchange{
				request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
				response: tt.response,
			})

			_, err := transport.CBOR(context.Background(), []byte{0x04})

			require.ErrorIs(t, err, baseiso7816.ErrInvalidResponse)
		})
	}
}

func TestCBORRejectsUnexpectedIntermediateData(t *testing.T) {
	command := append([]byte{0x01}, bytes.Repeat([]byte{0xaa}, shortCommandFragmentSize)...)
	transport, _ := newFakeTransport(t, exchange{
		request: slicesConcat(
			[]byte{0x90, 0x10, 0x00, 0x00, 0xf0},
			command[:shortCommandFragmentSize],
		),
		response: []byte{0x01, 0x90, 0x00},
	})

	_, err := transport.CBOR(context.Background(), command)

	require.ErrorIs(t, err, baseiso7816.ErrInvalidResponse)
}

func TestCBORValidatesCommandBeforeIO(t *testing.T) {
	transport, card := newFakeTransport(t)

	_, emptyErr := transport.CBOR(context.Background(), nil)
	_, largeErr := transport.CBOR(
		context.Background(),
		make([]byte, maxMessageSize+1),
	)

	require.EqualError(t, emptyErr, "iso7816: empty CTAP command")
	require.ErrorIs(t, largeErr, ErrCommandTooLarge)
	require.Empty(t, card.exchanges)
}

func TestNewPropagatesTransmitError(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: commandBytes(t, selectAppletCommand),
		err:     wantErr,
	}}}

	_, err := New(context.Background(), card)

	require.ErrorIs(t, err, wantErr)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOTransmit, ioErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	assert.False(t, invalidated)
	assert.False(t, card.closed, "the caller retains ownership when initialization fails")
}

func TestNewRejectsNilCard(t *testing.T) {
	_, err := New(context.Background(), nil)

	require.EqualError(t, err, "iso7816: nil card")
}

func TestCBORClosesCardAfterTransmitFailure(t *testing.T) {
	wantErr := errors.New("transmit failed")
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		err:     wantErr,
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	require.ErrorIs(t, err, wantErr)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOTransmit, ioErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	require.True(t, invalidated)
	assert.True(t, card.closed)
	assert.Equal(t, 1, card.closeCalls)
}

func TestCBORDoesNotCloseCardForOwnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		err:     context.Canceled,
		after:   cancel,
	})

	_, err := transport.CBOR(ctx, []byte{0x04})

	require.ErrorIs(t, err, context.Canceled)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	assert.False(t, invalidated)
	assert.False(t, card.closed)
}

func TestNewPreCanceledDoesNotTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	card := &fakeCard{t: t}

	_, err := New(ctx, card)

	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, card.exchanges)
}

func TestCloseDelegatesToCardOnce(t *testing.T) {
	transport, card := newFakeTransport(t)

	require.NoError(t, transport.Close())
	require.NoError(t, transport.Close())

	assert.True(t, card.closed)
	assert.Equal(t, 1, card.closeCalls)
}

func TestCloseReturnsTypedIOError(t *testing.T) {
	transport, card := newFakeTransport(t)
	wantErr := errors.New("reader unavailable")
	card.closeErr = wantErr

	err := transport.Close()

	require.ErrorIs(t, err, wantErr)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOClose, ioErr.Operation)
}

func TestCloseInterruptsBlockedTransmit(t *testing.T) {
	card := newBlockingCard()
	transport := &Transport{card: ioCard{Card: card}, version: protocol.FIDO_2_0}
	resultc := make(chan error, 1)
	go func() {
		_, err := transport.CBOR(context.Background(), []byte{0x04})
		resultc <- err
	}()

	receive(t, card.started, "card transmit did not start")
	require.NoError(t, transport.Close())
	err := receive(t, resultc, "blocked transmit did not stop after close")

	require.ErrorIs(t, err, io.ErrClosedPipe)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOTransmit, ioErr.Operation)
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	require.True(t, invalidated)
}

type blockingCard struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockingCard() *blockingCard {
	return &blockingCard{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (c *blockingCard) Transmit(ctx context.Context, _ []byte) ([]byte, error) {
	c.once.Do(func() { close(c.started) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.ErrClosedPipe
	}
}

func (c *blockingCard) Close() error {
	close(c.closed)
	return nil
}

func slicesConcat(slices ...[]byte) []byte {
	var result []byte
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}
