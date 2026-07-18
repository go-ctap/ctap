package discover

import (
	"context"

	"github.com/go-ctap/ctap/hidproxy"
	"github.com/go-ctap/ctap/options"
	ghid "github.com/go-ctap/hid"
)

// Event reports that the set of available FIDO devices may have changed.
type Event struct {
	Err error
}

// Events watches the discovery source selected by opts for topology changes.
func Events(ctx context.Context, opts ...options.Option) (<-chan Event, error) {
	if options.NewOptions(opts...).UseNamedPipe {
		proxyEvents, err := hidproxy.Events(ctx)
		if err != nil {
			return nil, err
		}

		events := make(chan Event)
		go func() {
			defer close(events)

			for event := range proxyEvents {
				select {
				case events <- Event{Err: event.Err}:
				case <-ctx.Done():
					return
				}
			}
		}()

		return events, nil
	}

	receiver, err := ghid.Events()
	if err != nil {
		return nil, err
	}

	events := make(chan Event)
	go func() {
		defer close(events)
		defer receiver.Close()

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-receiver.Listen():
				if !ok {
					return
				}

				if event.Err != nil {
					select {
					case events <- Event{Err: event.Err}:
					case <-ctx.Done():
					}
					return
				}

				if !isFIDOEvent(event) {
					continue
				}

				select {
				case events <- Event{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return events, nil
}

func isFIDOEvent(event ghid.DeviceEvent) bool {
	if event.Type != ghid.DeviceEventConnected && event.Type != ghid.DeviceEventDisconnected {
		return false
	}

	if event.DeviceInfo == nil {
		return true
	}

	return (event.DeviceInfo.UsagePage == 0 || event.DeviceInfo.UsagePage == 0xf1d0) &&
		(event.DeviceInfo.Usage == 0 || event.DeviceInfo.Usage == 0x01)
}
