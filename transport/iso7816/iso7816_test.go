package iso7816

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/telesma-app/ctap/protocol"
	ctaptransport "github.com/telesma-app/ctap/transport"
	baseiso7816 "github.com/telesma-app/iso7816"
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
	if got := c.exchanges; len(got) == 0 {
		c.t.Fatalf("got empty value %#v, want non-empty; context: %s", got, fmt.Sprintf("unexpected APDU: %x", apdu))
	}
	next := c.exchanges[0]
	c.exchanges = c.exchanges[1:]
	{
		want, got := next.request, apdu
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			c.t.Errorf("got %#v, want %#v", got, want)
		}
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return transport, card
}

func commandBytes(t testing.TB, command baseiso7816.Command) []byte {
	t.Helper()
	apdu, err := command.MarshalBinary()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return apdu
}

func TestCTAP23ControlCommands(t *testing.T) {
	{
		want, got := []byte{0x80, 0x11, 0x00, 0x00, 0x00}, commandBytes(t, getResponseCommand)
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []byte{0x80, 0x11, 0x11, 0x00, 0x00}, commandBytes(t, cancelGetResponseCommand)
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []byte{0x80, 0x12, 0x01, 0x00}, commandBytes(t, endSessionCommand)
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestNewSelectsFIDOApplet(t *testing.T) {
	_, card := newFakeTransport(t)

	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestNewAcceptsCombinedCTAP1AndCTAP2Version(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte(protocol.U2F_V2), 0x90, 0x00),
	}}}

	_, err := New(context.Background(), card)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

	_, err := New(context.Background(), card)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRejectsUnsupportedSelectionVersion(t *testing.T) {
	card := &fakeCard{t: t, exchanges: []exchange{{
		request:  commandBytes(t, selectAppletCommand),
		response: append([]byte("OTHER"), 0x90, 0x00),
	}}}

	_, err := New(context.Background(), card)

	{
		err, target := err, ErrUnsupportedVersion
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	if got := card.closed; got {
		t.Errorf("got true, want false; context: %s", fmt.Sprint("the caller retains ownership when initialization fails"))
	}
}

func TestCBORShortAPDU(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa1, 0x01, 0x02, 0x90, 0x00},
	})

	response, err := transport.CBOR(context.Background(), []byte{0x04})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xa1, 0x01, 0x02},
		}, response
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CTAP2_OK, response.StatusCode
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xa1, 0x01, 0x02},
		}, response
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
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

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CBORResponse{
			StatusCode: ctaptransport.CTAP2_OK,
			Data:       []byte{0xa0},
		}, response
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
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

	{
		err, target := err, context.Canceled
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	if got := card.closed; got {
		t.Errorf("got true, want false")
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
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

	{
		err, target := err, context.Canceled
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}
	{
		want, got := 1, card.closeCalls
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORPreservesFinalResponseWhenContextIsCanceledConcurrently(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x00, 0xa0, 0x90, 0x00},
		after:    cancel,
	})

	response, err := transport.CBOR(ctx, []byte{0x04})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := ctaptransport.CTAP2_OK, response.StatusCode
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := []byte{0xa0}, response.Data
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR), 0x90, 0x00},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	var ctapErr *ctaptransport.CTAPError
	if err := err; !errors.As(err, &ctapErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := protocol.AuthenticatorGetInfo, ctapErr.Command
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := ctaptransport.CTAP2_ERR_INVALID_CBOR, ctapErr.StatusCode
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestCBORReturnsTypedAPDUError(t *testing.T) {
	transport, _ := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		response: []byte{0x6a, 0x82},
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	var apduErr *baseiso7816.APDUError
	if err := err; !errors.As(err, &apduErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := byte(0x6a), apduErr.SW1
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := byte(0x82), apduErr.SW2
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
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

			{
				err, target := err, baseiso7816.ErrInvalidResponse
				if !errors.Is(err, target) {
					t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
				}
			}
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

	{
		err, target := err, baseiso7816.ErrInvalidResponse
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
}

func TestCBORValidatesCommandBeforeIO(t *testing.T) {
	transport, card := newFakeTransport(t)

	_, emptyErr := transport.CBOR(context.Background(), nil)
	_, largeErr := transport.CBOR(
		context.Background(),
		make([]byte, maxMessageSize+1),
	)

	{
		err, want := emptyErr, "iso7816: empty CTAP command"
		if err == nil || err.Error() != want {
			t.Fatalf("got error %v, want %q", err, want)
		}
	}
	{
		err, target := largeErr, ErrCommandTooLarge
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestNewPropagatesTransmitError(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: commandBytes(t, selectAppletCommand),
		err:     wantErr,
	}}}

	_, err := New(context.Background(), card)

	{
		err, target := err, wantErr
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := ctaptransport.IOTransmit, ioErr.Operation
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}
	if got := card.closed; got {
		t.Errorf("got true, want false; context: %s", fmt.Sprint("the caller retains ownership when initialization fails"))
	}
}

func TestNewRejectsNilCard(t *testing.T) {
	_, err := New(context.Background(), nil)

	{
		err, want := err, "iso7816: nil card"
		if err == nil || err.Error() != want {
			t.Fatalf("got error %v, want %q", err, want)
		}
	}
}

func TestCBORClosesCardAfterTransmitFailure(t *testing.T) {
	wantErr := errors.New("transmit failed")
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		err:     wantErr,
	})

	_, err := transport.CBOR(context.Background(), []byte{0x04})

	{
		err, target := err, wantErr
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := ctaptransport.IOTransmit, ioErr.Operation
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}
	{
		want, got := 1, card.closeCalls
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestCBORDoesNotCloseCardForOwnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport, card := newFakeTransport(t, exchange{
		request: []byte{0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00},
		err:     context.Canceled,
		after:   cancel,
	})

	_, err := transport.CBOR(ctx, []byte{0x04})

	{
		err, target := err, context.Canceled
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; got {
		t.Errorf("got true, want false")
	}
	if got := card.closed; got {
		t.Errorf("got true, want false")
	}
}

func TestNewPreCanceledDoesNotTransmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	card := &fakeCard{t: t}

	_, err := New(ctx, card)

	{
		err, target := err, context.Canceled
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCloseEndsSessionAndClosesCardOnce(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  commandBytes(t, endSessionCommand),
		response: []byte{0x90, 0x00},
	})

	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}
	{
		want, got := 1, card.closeCalls
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCloseReturnsTypedIOError(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  commandBytes(t, endSessionCommand),
		response: []byte{0x90, 0x00},
	})
	wantErr := errors.New("reader unavailable")
	card.closeErr = wantErr

	err := transport.Close()

	{
		err, target := err, wantErr
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := ctaptransport.IOClose, ioErr.Operation
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestCloseClosesCardWhenEndSessionIsRejected(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  commandBytes(t, endSessionCommand),
		response: []byte{0x6a, 0x86},
	})

	err := transport.Close()

	var apduErr *baseiso7816.APDUError
	if err := err; !errors.As(err, &apduErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := byte(0x6a), apduErr.SW1
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := byte(0x86), apduErr.SW2
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.closed; !got {
		t.Errorf("got false, want true")
	}
	{
		want, got := 1, card.closeCalls
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.exchanges; len(got) != 0 {
		t.Fatalf("got non-empty value %#v", got)
	}
}

func TestCloseInterruptsBlockedTransmit(t *testing.T) {
	card := newBlockingCard()
	transport := &Transport{card: ioCard{Card: card}}
	resultc := make(chan error, 1)
	go func() {
		_, err := transport.CBOR(context.Background(), []byte{0x04})
		resultc <- err
	}()

	receive(t, card.started, "card transmit did not start")
	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := receive(t, resultc, "blocked transmit did not stop after close")

	{
		err, target := err, io.ErrClosedPipe
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
	var ioErr *ctaptransport.IOError
	if err := err; !errors.As(err, &ioErr) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := ctaptransport.IOTransmit, ioErr.Operation
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	_, invalidated := errors.AsType[*ctaptransport.DeviceInvalidatedError](err)
	if got := invalidated; !got {
		t.Fatalf("got false, want true")
	}
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
