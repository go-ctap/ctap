package iso7816

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	baseiso7816 "github.com/go-ctap/iso7816"
)

var (
	ErrCommandTooLarge    = errors.New("iso7816: CTAP command is too large")
	ErrUnsupportedVersion = errors.New("iso7816: unsupported FIDO applet version")
)

var fidoAppletAID = []byte{0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01}

const (
	claISO                   = 0x00
	claCTAP                  = 0x80
	insSelect                = 0xa4
	insNFCCTAPMsg            = 0x10
	insNFCCTAPGetResponse    = 0x11
	p1SelectByName           = 0x04
	p1SupportsGetResponse    = 0x80
	p1Cancel                 = 0x11
	statusResponse           = 0x91
	statusResponseFinal      = 0x00
	shortCommandFragmentSize = 240
	maxMessageSize           = 0xffff
)

var (
	selectAppletCommand = baseiso7816.Command{
		CLA:      claISO,
		INS:      insSelect,
		P1:       p1SelectByName,
		Data:     fidoAppletAID,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}
	getResponseCommand = baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPGetResponse,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}
	cancelGetResponseCommand = baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPGetResponse,
		P1:       p1Cancel,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}
)

// Card is the raw APDU subset implemented by pcsc.Card.
type Card interface {
	io.Closer
	baseiso7816.Card
}

type ioCard struct {
	Card
}

func (c ioCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	response, err := c.Card.Transmit(ctx, apdu)
	if err != nil {
		return response, &ctaptransport.IOError{Operation: ctaptransport.IOTransmit, Err: err}
	}

	return response, nil
}

func (c ioCard) Close() error {
	err := c.Card.Close()
	if err != nil {
		return &ctaptransport.IOError{Operation: ctaptransport.IOClose, Err: err}
	}

	return nil
}

// Transport carries CTAP2 commands through the standard FIDO ISO 7816 applet.
type Transport struct {
	card      ioCard
	version   protocol.Version
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

var _ ctaptransport.Device = (*Transport)(nil)

// New selects the standard FIDO applet and returns an initialized transport.
// The caller retains ownership of card if initialization fails.
func New(ctx context.Context, card Card) (*Transport, error) {
	if card == nil {
		return nil, errors.New("iso7816: nil card")
	}

	t := &Transport{card: ioCard{Card: card}}
	response, err := baseiso7816.Exchange(
		ctx,
		t.card,
		selectAppletCommand,
		baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err != nil {
		return nil, fmt.Errorf("iso7816: select FIDO applet: %w", err)
	}
	if response.Status != baseiso7816.StatusSuccess {
		return nil, fmt.Errorf(
			"iso7816: select FIDO applet: %w",
			response.APDUError(),
		)
	}

	version := protocol.Version(response.Data)
	switch version {
	case protocol.FIDO_2_0, protocol.U2F_V2:
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedVersion, response.Data)
	}
	t.version = version

	return t, nil
}

// Version returns the capability string reported when the FIDO applet was
// selected. U2F_V2 can identify either a CTAP1-only authenticator or one that
// supports both CTAP1 and CTAP2; authenticatorGetInfo distinguishes them.
func (t *Transport) Version() protocol.Version {
	return t.version
}

// CBOR sends a CTAP command byte and CBOR payload through NFCCTAP_MSG. It uses
// short APDU chaining and advertises support for NFCCTAP_GETRESPONSE polling.
func (t *Transport) CBOR(ctx context.Context, data []byte) (ctaptransport.CBORResponse, error) {
	if len(data) < 1 {
		return ctaptransport.CBORResponse{}, errors.New("iso7816: empty CTAP command")
	}
	if len(data) > maxMessageSize {
		return ctaptransport.CBORResponse{}, ErrCommandTooLarge
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ctaptransport.CBORResponse{}, err
	}

	response, err := t.exchangeCTAP(ctx, data)
	if err != nil {
		return ctaptransport.CBORResponse{}, t.closeOnIOError(ctx, err)
	}
	if len(response) < 1 {
		return ctaptransport.CBORResponse{}, baseiso7816.ErrInvalidResponse
	}

	return ctaptransport.ValidateCBORResponse(protocol.Command(data[0]), ctaptransport.CBORResponse{
		StatusCode: ctaptransport.StatusCode(response[0]),
		Data:       slices.Clone(response[1:]),
	})
}

func (t *Transport) exchangeCTAP(ctx context.Context, data []byte) ([]byte, error) {
	commands, err := baseiso7816.Chain(baseiso7816.Command{
		CLA:      claCTAP,
		INS:      insNFCCTAPMsg,
		Data:     data,
		Le:       256,
		Encoding: baseiso7816.EncodingShort,
	}, shortCommandFragmentSize)
	if err != nil {
		return nil, err
	}
	commands[len(commands)-1].P1 = p1SupportsGetResponse

	for _, command := range commands[:len(commands)-1] {
		response, err := baseiso7816.Transmit(ctx, t.card, command)
		if err != nil {
			return nil, err
		}
		if err := response.APDUError(); err != nil {
			return nil, err
		}
		if len(response.Data) != 0 {
			return nil, baseiso7816.ErrInvalidResponse
		}
	}

	response, err := baseiso7816.Exchange(
		ctx,
		t.card,
		commands[len(commands)-1],
		baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err != nil {
		return nil, err
	}

	for response.Status == baseiso7816.NewStatusWord(statusResponse, statusResponseFinal) {
		if len(response.Data) != 1 {
			return nil, baseiso7816.ErrInvalidResponse
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, t.cancelPolling(ctx, ctxErr)
		}

		response, err = baseiso7816.Exchange(
			ctx,
			t.card,
			getResponseCommand,
			baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
		)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				return nil, t.cancelPolling(ctx, err)
			}
			return nil, err
		}
	}

	if err := response.APDUError(); err != nil {
		return nil, err
	}

	return response.Data, nil
}

func (t *Transport) cancelPolling(ctx context.Context, originalErr error) error {
	cancelCtx := context.WithoutCancel(ctx)
	response, err := baseiso7816.Exchange(
		cancelCtx,
		t.card,
		cancelGetResponseCommand,
		baseiso7816.WithMoreDataStatusBytes(0x61, 0x9f),
	)
	if err == nil &&
		(response.Status != baseiso7816.StatusSuccess ||
			len(response.Data) != 1 ||
			ctaptransport.StatusCode(response.Data[0]) != ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL) {
		err = baseiso7816.ErrInvalidResponse
	}
	if err == nil {
		return originalErr
	}

	// A rejected or malformed cancellation leaves no proof that the pending
	// CTAP command reached a terminal state. Do not allow another APDU to be
	// mistaken for the continuation of that command.
	_ = t.Close()
	return &ctaptransport.DeviceInvalidatedError{Err: originalErr}
}

func (t *Transport) closeOnIOError(ctx context.Context, err error) error {
	ioErr, ok := errors.AsType[*ctaptransport.IOError](err)
	if !ok || ioErr.Operation != ctaptransport.IOTransmit {
		return err
	}

	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return err
	}

	_ = t.Close()
	return &ctaptransport.DeviceInvalidatedError{Err: err}
}

// Close closes the underlying card.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.closeErr = t.card.Close()
	})
	return t.closeErr
}
