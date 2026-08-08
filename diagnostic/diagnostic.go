// Package diagnostic defines the optional, redacted CTAP exchange observer.
package diagnostic

import (
	"context"
	"time"

	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/transport"
)

// Message is normalized, pretty-printed extended CBOR diagnostic notation for one side of an exchange.
type Message struct {
	Notation       string
	Bytes          int
	RedactedFields []string
	Error          string
}

// Exchange describes one completed CTAP command without retaining raw bytes.
type Exchange struct {
	StartedAt  time.Time
	Duration   time.Duration
	Command    protocol.Command
	SubCommand uint64
	Request    Message
	Response   Message
	Status     *transport.StatusCode
	Err        error
}

// Sink observes completed exchanges synchronously and has no error return.
type Sink func(context.Context, Exchange)
