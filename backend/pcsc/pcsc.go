// Package pcsc connects inserted PC/SC cards to the standard FIDO ISO 7816
// transport.
package pcsc

import (
	"context"
	"errors"
	"iter"

	ctaptransport "github.com/telesma-app/ctap/transport"
	"github.com/telesma-app/ctap/transport/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
)

// Devices returns PC/SC readers that currently contain a card.
func Devices(ctx context.Context) iter.Seq2[*nativepcsc.ReaderInfo, error] {
	return func(yield func(*nativepcsc.ReaderInfo, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(nil, err)
			return
		}

		for reader, err := range nativepcsc.Enumerate() {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}
			if err != nil {
				yield(nil, err)
				return
			}
			if reader.State&nativepcsc.ReaderStatePresent == 0 {
				continue
			}
			if !yield(reader, nil) {
				return
			}
		}
	}
}

// Open connects to the card in reader and selects the standard FIDO applet.
func Open(ctx context.Context, reader string) (*iso7816.Transport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	card, err := nativepcsc.Open(
		reader,
		nativepcsc.WithShareMode(nativepcsc.ShareModeShared),
		nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard),
	)
	if err != nil {
		return nil, err
	}

	transport, err := iso7816.New(ctx, card)
	if err != nil {
		return nil, errors.Join(err, card.Close())
	}

	return transport, nil
}

// Enumerate opens inserted PC/SC cards as standard FIDO transports.
func Enumerate(ctx context.Context) iter.Seq2[ctaptransport.Device, error] {
	return func(yield func(ctaptransport.Device, error) bool) {
		for reader, err := range Devices(ctx) {
			if err != nil {
				yield(nil, err)
				return
			}

			transport, err := Open(ctx, reader.Name)
			if !yield(transport, err) {
				return
			}
		}
	}
}
