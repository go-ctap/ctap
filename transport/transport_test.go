package transport

import (
	"errors"
	"io"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCBORResponsePreservesSuccess(t *testing.T) {
	want := CBORResponse{StatusCode: CTAP2_OK, Data: []byte{0xa1, 0x01, 0x02}}

	got, err := ValidateCBORResponse(protocol.AuthenticatorGetInfo, want)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestValidateCBORResponseReturnsTypedError(t *testing.T) {
	_, err := ValidateCBORResponse(protocol.AuthenticatorGetInfo, CBORResponse{
		StatusCode: CTAP2_ERR_INVALID_CBOR,
	})

	var ctapErr *CTAPError
	require.ErrorAs(t, err, &ctapErr)
	assert.Equal(t, protocol.AuthenticatorGetInfo, ctapErr.Command)
	assert.Equal(t, CTAP2_ERR_INVALID_CBOR, ctapErr.StatusCode)
}

func TestIOErrorPreservesOperationAndCause(t *testing.T) {
	cause := errors.New("device disconnected")
	err := &IOError{Operation: IORead, Err: cause}

	assert.Equal(t, IORead, err.Operation)
	assert.EqualError(t, err, "transport read: device disconnected")
	require.ErrorIs(t, err, cause)

	var got *IOError
	require.ErrorAs(t, err, &got)
	assert.Same(t, err, got)
}

func TestIOErrorPreservesTypedCause(t *testing.T) {
	err := &IOError{Operation: IOWrite, Err: io.ErrClosedPipe}

	require.ErrorIs(t, err, io.ErrClosedPipe)
}
