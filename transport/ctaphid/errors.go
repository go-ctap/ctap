package ctaphid

import (
	"context"
	"errors"

	ctaptransport "github.com/telesma-app/ctap/transport"
)

var (
	ErrMessageTooLarge        = errors.New("ctaphid: message payload too large")
	ErrInvalidRequestMessage  = errors.New("ctaphid: invalid request message")
	ErrUnexpectedCommand      = errors.New("ctaphid: unexpected command")
	ErrInvalidResponseMessage = errors.New("ctaphid: invalid response message")
)

// ioDevice marks errors at the exact boundary between CTAPHID framing and the
// underlying HID or proxy connection. Codec errors therefore remain framing
// errors and never need to be classified after the fact.
type ioDevice struct {
	Device
}

func (d ioDevice) Read(ctx context.Context, p []byte) (int, error) {
	n, err := d.Device.Read(ctx, p)
	if err != nil {
		return n, &ctaptransport.IOError{Operation: ctaptransport.IORead, Err: err}
	}

	return n, nil
}

func (d ioDevice) Write(ctx context.Context, p []byte) (int, error) {
	n, err := d.Device.Write(ctx, p)
	if err != nil {
		return n, &ctaptransport.IOError{Operation: ctaptransport.IOWrite, Err: err}
	}

	return n, nil
}

func (d ioDevice) Close() error {
	err := d.Device.Close()
	if err != nil {
		return &ctaptransport.IOError{Operation: ctaptransport.IOClose, Err: err}
	}

	return nil
}
