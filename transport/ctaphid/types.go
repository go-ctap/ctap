package ctaphid

// Message is a sequence of packets.
type Message []*packet

const (
	hidPacketSize                = 64
	hidReportPacketSize          = hidPacketSize + 1
	initPacketHeaderSize         = 7
	continuationPacketHeaderSize = 5
	initPacketDataSize           = hidPacketSize - initPacketHeaderSize
	continuationPacketDataSize   = hidPacketSize - continuationPacketHeaderSize
)

// packet represents CTAP packet.
type packet struct {
	cid          ChannelID
	command      Command
	sequence     byte
	length       uint16
	data         []byte
	continuation bool
}

// ChannelID represents CTAP channel ID.
type ChannelID [4]byte

// BROADCAST_CID represents CTAP broadcast channel ID.
var BROADCAST_CID = ChannelID{0xff, 0xff, 0xff, 0xff}

// InitResponse represents CTAPHID_INIT (0x06) command response.
// https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-init
type InitResponse struct {
	Nonce                            []byte
	CID                              ChannelID
	CTAPHIDProtocolVersionIdentifier byte
	MajorDeviceVersion               byte
	MinorDeviceVersion               byte
	BuildDeviceVersion               byte
	CapabilityFlags                  byte
}

func (r *InitResponse) ImplementsWink() bool {
	return r.CapabilityFlags&byte(CAPABILITY_WINK) != 0
}

func (r *InitResponse) ImplementsCBOR() bool {
	return r.CapabilityFlags&byte(CAPABILITY_CBOR) != 0
}

func (r *InitResponse) NotImplementsMSG() bool {
	return r.CapabilityFlags&byte(CAPABILITY_NMSG) != 0
}

// PingResponse represents CTAPHID_PING command response.
// https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-ping
type PingResponse struct {
	Bytes []byte
}

// ErrorResponse represents CTAPHID_ERROR (0x3F) command response.
type ErrorResponse struct {
	ErrorCode Error
}

// Error returns the symbolic CTAPHID error code. ErrorCode remains the
// authoritative response byte, including for unknown and vendor-defined
// values.
func (r *ErrorResponse) Error() string {
	return r.ErrorCode.String()
}

// VendorResponse contains the opaque response payload of a CTAPHID vendor
// command.
type VendorResponse struct {
	Data []byte
}
