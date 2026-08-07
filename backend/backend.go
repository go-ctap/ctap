// Package backend defines the host-side authenticator access boundary.
package backend

import (
	"context"
	"iter"

	"github.com/go-ctap/ctap/transport"
)

// Enumerator opens CTAP transports and transfers their ownership to its
// consumer.
type Enumerator func(context.Context) iter.Seq2[transport.Device, error]
