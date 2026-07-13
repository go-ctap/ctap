package ctaphid

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"

	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport"
)

func ensureDataLen(data []byte, min int) error {
	if len(data) < min {
		return ErrInvalidResponseMessage
	}
	return nil
}

func ensureResponseCID(msg Message, cid ChannelID) error {
	if len(msg) < 1 {
		return ErrInvalidResponseMessage
	}
	if msg[0].cid != cid {
		return ErrInvalidResponseMessage
	}

	return nil
}

func writeCBOR(ctx context.Context, dev Device, cid ChannelID, data []byte) (protocol.Command, error) {
	if len(data) < 1 {
		return 0, ErrInvalidRequestMessage
	}

	msg, err := NewMessage(cid, CTAPHID_CBOR, data)
	if err != nil {
		return 0, err
	}
	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return 0, err
	}
	return protocol.Command(data[0]), nil
}

func readCBORResponse(ctx context.Context, dev Device, cid ChannelID, command protocol.Command) (transport.CBORResponse, error) {
read:
	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(contextReader{ctx, dev}); err != nil {
			return transport.CBORResponse{}, err
		}

		if err := ensureResponseCID(respMsg, cid); err != nil {
			return transport.CBORResponse{}, err
		}

		var respData []byte
		for i, p := range respMsg {
			if i == 0 {
				switch p.command {
				case CTAPHID_CBOR:
					if err := ensureDataLen(p.data, 1); err != nil {
						return transport.CBORResponse{}, err
					}
				case CTAPHID_ERROR:
					if err := ensureDataLen(p.data, 1); err != nil {
						return transport.CBORResponse{}, err
					}
					return transport.CBORResponse{}, errors.New(Error(p.data[0]).String())
				case CTAPHID_KEEPALIVE:
					continue read
				default:
					return transport.CBORResponse{}, ErrUnexpectedCommand
				}
			}

			respData = slices.Concat(respData, p.data)
		}
		if err := ensureDataLen(respData, 1); err != nil {
			return transport.CBORResponse{}, err
		}

		response := transport.CBORResponse{
			StatusCode: transport.StatusCode(respData[0]),
			Data:       respData[1:],
		}

		return transport.ValidateCBORResponse(command, response)
	}
}

func initChannel(ctx context.Context, dev Device, cid ChannelID, nonce []byte) (InitResponse, error) {
	if len(nonce) != 8 {
		return InitResponse{}, ErrInvalidRequestMessage
	}

	msg, err := NewMessage(cid, CTAPHID_INIT, nonce)
	if err != nil {
		return InitResponse{}, err
	}

	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return InitResponse{}, err
	}

	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(contextReader{ctx, dev}); err != nil {
			return InitResponse{}, err
		}

		if err := ensureResponseCID(respMsg, cid); err != nil {
			return InitResponse{}, err
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_INIT:
			if err := ensureDataLen(p.data, 17); err != nil {
				return InitResponse{}, err
			}
			if subtle.ConstantTimeCompare(p.data[:8], nonce) != 1 {
				return InitResponse{}, errors.New("invalid nonce")
			}

			r := InitResponse{
				Nonce:                            p.data[:8],
				CID:                              ChannelID(p.data[8 : 8+4]),
				CTAPHIDProtocolVersionIdentifier: p.data[12],
				MajorDeviceVersion:               p.data[13],
				MinorDeviceVersion:               p.data[14],
				BuildDeviceVersion:               p.data[15],
				CapabilityFlags:                  p.data[16],
			}

			return r, nil
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return InitResponse{}, err
			}
			return InitResponse{}, errors.New(Error(p.data[0]).String())
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return InitResponse{}, ErrUnexpectedCommand
		}
	}
}

func ping(ctx context.Context, dev Device, cid ChannelID, data []byte) (PingResponse, error) {
	msg, err := NewMessage(cid, CTAPHID_PING, data)
	if err != nil {
		return PingResponse{}, err
	}

	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return PingResponse{}, err
	}

read:
	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(contextReader{ctx, dev}); err != nil {
			return PingResponse{}, err
		}

		if err := ensureResponseCID(respMsg, cid); err != nil {
			return PingResponse{}, err
		}

		var pong []byte
		for i, p := range respMsg {
			if i == 0 {
				switch p.command {
				case CTAPHID_PING:
				case CTAPHID_ERROR:
					if err := ensureDataLen(p.data, 1); err != nil {
						return PingResponse{}, err
					}
					return PingResponse{}, errors.New(Error(p.data[0]).String())
				case CTAPHID_KEEPALIVE:
					continue read
				default:
					return PingResponse{}, ErrUnexpectedCommand
				}
			}

			pong = slices.Concat(pong, p.data)
		}

		r := PingResponse{
			Bytes: pong,
		}

		return r, nil
	}
}

// vendor sends a command from the CTAPHID vendor-specific range (0x40-0x7f).
// Command values do not include INIT_PACKET_BIT; NewMessage adds that bit when
// encoding the initial HID packet.
func vendor(ctx context.Context, dev Device, cid ChannelID, command Command, data []byte) (VendorResponse, error) {
	if command < CTAPHID_VENDOR_FIRST || command > CTAPHID_VENDOR_LAST {
		return VendorResponse{}, ErrInvalidRequestMessage
	}

	msg, err := NewMessage(cid, command, data)
	if err != nil {
		return VendorResponse{}, err
	}
	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return VendorResponse{}, err
	}

read:
	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(contextReader{ctx, dev}); err != nil {
			return VendorResponse{}, err
		}
		if err := ensureResponseCID(respMsg, cid); err != nil {
			return VendorResponse{}, err
		}

		var response []byte
		for i, p := range respMsg {
			if i == 0 {
				switch p.command {
				case command:
				case CTAPHID_ERROR:
					if err := ensureDataLen(p.data, 1); err != nil {
						return VendorResponse{}, err
					}
					return VendorResponse{}, errors.New(Error(p.data[0]).String())
				case CTAPHID_KEEPALIVE:
					continue read
				default:
					return VendorResponse{}, ErrUnexpectedCommand
				}
			}
			response = append(response, p.data...)
		}

		return VendorResponse{Data: response}, nil
	}
}

func cancel(ctx context.Context, dev Device, cid ChannelID) error {
	msg, err := NewMessage(cid, CTAPHID_CANCEL, nil)
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return err
	}

	return nil
}

func wink(ctx context.Context, dev Device, cid ChannelID) error {
	msg, err := NewMessage(cid, CTAPHID_WINK, nil)
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return err
	}

	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(contextReader{ctx, dev}); err != nil {
			return err
		}

		if err := ensureResponseCID(respMsg, cid); err != nil {
			return err
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_WINK:
			return nil
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return err
			}
			return errors.New(Error(p.data[0]).String())
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return ErrUnexpectedCommand
		}
	}
}

func lock(ctx context.Context, dev Device, cid ChannelID, seconds uint8) error {
	if seconds > 10 {
		return ErrInvalidRequestMessage
	}

	msg, err := NewMessage(cid, CTAPHID_LOCK, []byte{seconds})
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(contextWriter{ctx, dev}); err != nil {
		return err
	}

	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(contextReader{ctx, dev}); err != nil {
			return err
		}

		if err := ensureResponseCID(respMsg, cid); err != nil {
			return err
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_LOCK:
			return nil
		case CTAPHID_ERROR:
			if err := ensureDataLen(p.data, 1); err != nil {
				return err
			}
			return errors.New(Error(p.data[0]).String())
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return ErrUnexpectedCommand
		}
	}
}

type contextReader struct {
	ctx context.Context
	dev Device
}

func (r contextReader) Read(p []byte) (int, error) { return r.dev.Read(r.ctx, p) }

type contextWriter struct {
	ctx context.Context
	dev Device
}

func (w contextWriter) Write(p []byte) (int, error) { return w.dev.Write(w.ctx, p) }
