// Package token2 implements Token2's proprietary CTAP-over-APDU tunnel over a
// raw smart-card APDU connection such as pcsc.Card.
package token2

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
)

var (
	ErrInvalidResponse = errors.New("token2: invalid APDU response")
	ErrCommandTooLarge = errors.New("token2: CTAP command is too large")
)

var appletAID = []byte{0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01}

const (
	claToken2      = 0x80
	insCTAP        = 0xc5
	insGetResponse = 0xc0
	maxCommandSize = 0xffff
)

// Card is the raw APDU subset implemented by pcsc.Card.
type Card interface {
	Transmit(apdu []byte) ([]byte, error)
}

// APDUError reports a non-success ISO 7816 status word.
type APDUError struct {
	SW1 byte
	SW2 byte
}

func (e *APDUError) Error() string {
	return fmt.Sprintf("token2: APDU failed (SW=%02x%02x)", e.SW1, e.SW2)
}

// Transport carries CTAP commands through the Token2 applet.
type Transport struct {
	card Card
	mu   sync.Mutex
}

var _ ctaptransport.Device = (*Transport)(nil)

// New selects the Token2 applet and returns an initialized transport. The
// caller retains ownership of card if initialization fails.
func New(card Card) (*Transport, error) {
	if card == nil {
		return nil, errors.New("token2: nil card")
	}

	t := &Transport{card: card}
	selectAPDU := slices.Concat([]byte{0x00, 0xa4, 0x04, 0x00, byte(len(appletAID))}, appletAID)
	if _, err := t.exchange(selectAPDU); err != nil {
		return nil, fmt.Errorf("token2: select applet: %w", err)
	}

	return t, nil
}

// CBOR sends a CTAP command byte and CBOR payload through INS C5/P1 03.
func (t *Transport) CBOR(data []byte) (ctaptransport.CBORResponse, error) {
	if len(data) < 1 {
		return ctaptransport.CBORResponse{}, errors.New("token2: empty CTAP command")
	}
	if len(data) > maxCommandSize {
		return ctaptransport.CBORResponse{}, ErrCommandTooLarge
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	response, err := t.exchange(commandAPDU(data))
	if err != nil {
		return ctaptransport.CBORResponse{}, err
	}
	if len(response) < 1 {
		return ctaptransport.CBORResponse{}, ErrInvalidResponse
	}

	return ctaptransport.ValidateCBORResponse(protocol.Command(data[0]), ctaptransport.CBORResponse{
		StatusCode: ctaptransport.StatusCode(response[0]),
		Data:       slices.Clone(response[1:]),
	})
}

func commandAPDU(data []byte) []byte {
	header := []byte{claToken2, insCTAP, 0x03, 0x00}
	if len(data) <= 0xff {
		return slices.Concat(header, []byte{byte(len(data))}, data)
	}

	return slices.Concat(header, []byte{0x00, byte(len(data) >> 8), byte(len(data))}, data)
}

func (t *Transport) exchange(apdu []byte) ([]byte, error) {
	response, err := t.card.Transmit(apdu)
	if err != nil {
		return nil, err
	}

	var data []byte
	for {
		if len(response) < 2 {
			return nil, ErrInvalidResponse
		}

		body := response[:len(response)-2]
		sw1, sw2 := response[len(response)-2], response[len(response)-1]
		data = append(data, body...)

		switch sw1 {
		case 0x90:
			if sw2 != 0x00 {
				return nil, &APDUError{SW1: sw1, SW2: sw2}
			}
			return data, nil
		case 0x61:
			response, err = t.card.Transmit([]byte{claToken2, insGetResponse, 0x00, 0x00, sw2})
			if err != nil {
				return nil, err
			}
		default:
			return nil, &APDUError{SW1: sw1, SW2: sw2}
		}
	}
}

// Close closes the underlying card when it implements io.Closer.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	closer, ok := t.card.(io.Closer)
	if !ok {
		return nil
	}
	return closer.Close()
}
