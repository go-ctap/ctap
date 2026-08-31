package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/ctap/protocol"
)

func TestValidateCBORResponsePreservesSuccess(t *testing.T) {
	want := CBORResponse{StatusCode: CTAP2_OK, Data: []byte{0xa1, 0x01, 0x02}}

	got, err := ValidateCBORResponse(protocol.AuthenticatorGetInfo, want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := want, got
		if got.StatusCode != want.StatusCode || ((got.Data == nil) != (want.Data == nil) || !bytes.Equal(got.Data, want.Data)) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestValidateCBORResponseReturnsTypedError(t *testing.T) {
	_, err := ValidateCBORResponse(protocol.AuthenticatorGetInfo, CBORResponse{
		StatusCode: CTAP2_ERR_INVALID_CBOR,
	})

	var ctapErr *CTAPError
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
		want, got := CTAP2_ERR_INVALID_CBOR, ctapErr.StatusCode
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestIOErrorPreservesOperationAndCause(t *testing.T) {
	cause := errors.New("device disconnected")
	err := &IOError{Operation: IORead, Err: cause}

	{
		want, got := IORead, err.Operation
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		err, want := err, "transport read: device disconnected"
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}
	{
		err, target := err, cause
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}

	var got *IOError
	if err := err; !errors.As(err, &got) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := err, got
		if got != want {
			t.Errorf("got pointer %p, want %p", got, want)
		}
	}
}

func TestIOErrorPreservesTypedCause(t *testing.T) {
	err := &IOError{Operation: IOWrite, Err: io.ErrClosedPipe}

	{
		err, target := err, io.ErrClosedPipe
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
}

func TestDeviceInvalidatedErrorPreservesCause(t *testing.T) {
	cause := &IOError{Operation: IORead, Err: io.ErrUnexpectedEOF}
	err := &DeviceInvalidatedError{Err: cause}

	{
		err, want := err, "transport read: unexpected EOF"
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}
	{
		err, target := err, io.ErrUnexpectedEOF
		if !errors.Is(err, target) {
			t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}

	ioErr, ok := errors.AsType[*IOError](err)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}
	{
		want, got := cause, ioErr
		if got != want {
			t.Errorf("got pointer %p, want %p", got, want)
		}
	}

	invalidatedErr, ok := errors.AsType[*DeviceInvalidatedError](err)
	if got := ok; !got {
		t.Fatalf("got false, want true")
	}
	{
		want, got := err, invalidatedErr
		if got != want {
			t.Errorf("got pointer %p, want %p", got, want)
		}
	}
}

func TestStatusCodeName(t *testing.T) {
	name, ok := CTAP2_ERR_NOT_ALLOWED.Name()
	if !ok || name != CTAP2_ERR_NOT_ALLOWED.String() {
		t.Fatalf("known status Name() = %q, %v", name, ok)
	}

	for _, status := range []StatusCode{0x41, 0xe1, 0xf1} {
		if name, ok := status.Name(); ok || name != "" {
			t.Errorf("unknown StatusCode(0x%02x).Name() = %q, %v, want empty, false", byte(status), name, ok)
		}
	}
}
