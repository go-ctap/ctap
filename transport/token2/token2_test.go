package token2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
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
	card := &fakeCard{t: t, exchanges: append([]exchange{
		{request: []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01}, response: []byte{0x61, 0x04}},
		{request: []byte{0x00, 0xc0, 0x00, 0x00, 0x04}, response: []byte{'1', '0', '0', '0', 0x90, 0x00}},
	}, exchanges...)}

	transport, err := New(context.Background(), card)
	require.NoError(t, err)
	return transport, card
}

func TestCBORShortAPDU(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
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

func TestCBORExtendedAPDUAndGetResponse(t *testing.T) {
	command := append([]byte{0x06}, bytes.Repeat([]byte{0xaa}, 255)...)
	wantAPDU := append([]byte{0x80, 0xc5, 0x03, 0x00, 0x00, 0x01, 0x00}, command...)
	transport, card := newFakeTransport(t,
		exchange{request: wantAPDU, response: []byte{0x00, 0xa1, 0x61, 0x02}},
		exchange{request: []byte{0x80, 0xc0, 0x00, 0x00, 0x02}, response: []byte{0x01, 0x02, 0x90, 0x00}},
	)

	response, err := transport.CBOR(context.Background(), command)
	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CBORResponse{
		StatusCode: ctaptransport.CTAP2_OK,
		Data:       []byte{0xa1, 0x01, 0x02},
	}, response)
	require.Empty(t, card.exchanges)
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR), 0x90, 0x00},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})
	var ctapErr *ctaptransport.CTAPError
	require.ErrorAs(t, err, &ctapErr)
	assert.Equal(t, protocol.AuthenticatorGetInfo, ctapErr.Command)
	assert.Equal(t, ctaptransport.CTAP2_ERR_INVALID_CBOR, ctapErr.StatusCode)
}

func TestCBORReturnsAPDUError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x6a, 0x82},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})
	var apduErr *APDUError
	require.ErrorAs(t, err, &apduErr)
	assert.Equal(t, byte(0x6a), apduErr.SW1)
	assert.Equal(t, byte(0x82), apduErr.SW2)
}

func TestNewRejectsMalformedSelectResponse(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01},
		response: []byte{0x90},
	}}}

	_, err := New(context.Background(), card)
	require.ErrorIs(t, err, ErrInvalidResponse)
}

func TestCloseDelegatesToCard(t *testing.T) {
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
	assert.True(t, card.closed)
}

func TestNewPropagatesTransmitError(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01},
		err:     wantErr,
	}}}

	_, err := New(context.Background(), card)
	require.ErrorIs(t, err, wantErr)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOTransmit, ioErr.Operation)
	assert.False(t, card.closed, "the caller retains ownership when initialization fails")
}

func TestCBORClosesCardAfterTransmitFailure(t *testing.T) {
	wantErr := errors.New("transmit failed")
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		err:     wantErr,
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	require.ErrorIs(t, err, wantErr)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOTransmit, ioErr.Operation)
	assert.True(t, card.closed)
	require.NoError(t, transport.Close())
	assert.Equal(t, 1, card.closeCalls)
}

func TestCBORClosesCardAfterContextErrorFromActiveContext(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		err:     context.DeadlineExceeded,
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, card.closed, "an unrelated context error still means transmit failed")
}

func TestCBORChecksContextBeforeChainedTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x00, 0x61, 0x04},
		after:    cancel,
	})

	_, err := transport.CBOR(ctx, []byte{0x04})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, card.exchanges)
	assert.False(t, card.closed)
}

func TestCBORPreservesSuccessfulResponseWhenContextIsCanceledConcurrently(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x00, 0x90, 0x00},
		after:    cancel,
	})

	response, err := transport.CBOR(ctx, []byte{0x04})

	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, response.StatusCode)
	require.Empty(t, card.exchanges)
}

func TestNewPreCanceledDoesNotTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	card := &fakeCard{t: t}

	_, err := New(ctx, card)
	require.ErrorIs(t, err, context.Canceled)
}

func TestCloseInterruptsBlockedTransmit(t *testing.T) {
	card := newBlockingCard()
	transport := &Transport{card: ioCard{Card: card}}
	resultc := make(chan error, 1)
	go func() {
		_, err := transport.CBOR(context.Background(), []byte{0x04})
		resultc <- err
	}()

	<-card.started
	require.NoError(t, transport.Close())
	err := <-resultc
	require.ErrorIs(t, err, io.ErrClosedPipe)
	var ioErr *ctaptransport.IOError
	require.ErrorAs(t, err, &ioErr)
	assert.Equal(t, ctaptransport.IOTransmit, ioErr.Operation)
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
