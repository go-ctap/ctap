package token2

import (
	"bytes"
	"errors"
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
}

type fakeCard struct {
	t         *testing.T
	exchanges []exchange
	closed    bool
}

func (c *fakeCard) Transmit(apdu []byte) ([]byte, error) {
	c.t.Helper()
	require.NotEmpty(c.t, c.exchanges, "unexpected APDU: %x", apdu)
	next := c.exchanges[0]
	c.exchanges = c.exchanges[1:]
	assert.Equal(c.t, next.request, apdu)
	return bytes.Clone(next.response), next.err
}

func (c *fakeCard) Close() error {
	c.closed = true
	return nil
}

func newFakeTransport(t *testing.T, exchanges ...exchange) (*Transport, *fakeCard) {
	t.Helper()
	card := &fakeCard{t: t, exchanges: append([]exchange{
		{request: []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01}, response: []byte{0x61, 0x04}},
		{request: []byte{0x80, 0xc0, 0x00, 0x00, 0x04}, response: []byte{'1', '0', '0', '0', 0x90, 0x00}},
	}, exchanges...)}

	transport, err := New(card)
	require.NoError(t, err)
	return transport, card
}

func TestCBORShortAPDU(t *testing.T) {
	transport, card := newFakeTransport(t, exchange{
		request:  []byte{0x80, 0xc5, 0x03, 0x00, 0x01, 0x04},
		response: []byte{0x00, 0xa1, 0x01, 0x02, 0x90, 0x00},
	})

	response, err := transport.CBOR([]byte{0x04})
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

	response, err := transport.CBOR(command)
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

	_, err := transport.CBOR([]byte{0x04})
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

	_, err := transport.CBOR([]byte{0x04})
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

	_, err := New(card)
	require.ErrorIs(t, err, ErrInvalidResponse)
}

func TestCloseDelegatesToCard(t *testing.T) {
	transport, card := newFakeTransport(t)
	require.NoError(t, transport.Close())
	assert.True(t, card.closed)
}

func TestNewPropagatesTransmitError(t *testing.T) {
	wantErr := errors.New("transmit failed")
	card := &fakeCard{t: t, exchanges: []exchange{{
		request: []byte{0x00, 0xa4, 0x04, 0x00, 0x08, 0xf0, 0x00, 0x00, 0x01, 0x4f, 0x74, 0x70, 0x01},
		err:     wantErr,
	}}}

	_, err := New(card)
	require.ErrorIs(t, err, wantErr)
}
