package ctaphid

// Command represents CTAP command.
//
//go:generate go tool stringer -type=Command,CapabilityFlag,Error,KeepaliveStatusCode -output=consts_string.go
type Command byte

const (
	CTAPHID_MSG          Command = 0x03
	CTAPHID_CBOR         Command = 0x10
	CTAPHID_INIT         Command = 0x06
	CTAPHID_PING         Command = 0x01
	CTAPHID_CANCEL       Command = 0x11
	CTAPHID_ERROR        Command = 0x3f
	CTAPHID_KEEPALIVE    Command = 0x3b
	CTAPHID_WINK         Command = 0x08
	CTAPHID_LOCK         Command = 0x04
	CTAPHID_VENDOR_FIRST Command = 0x40
	CTAPHID_VENDOR_LAST  Command = 0x7f
)

type CapabilityFlag byte

const (
	CAPABILITY_WINK CapabilityFlag = 0x01
	CAPABILITY_LOCK CapabilityFlag = 0x02
	CAPABILITY_CBOR CapabilityFlag = 0x04
	CAPABILITY_NMSG CapabilityFlag = 0x08
)

type Error byte

const (
	ERR_INVALID_CMD     Error = 0x01
	ERR_INVALID_PAR     Error = 0x02
	ERR_INVALID_LEN     Error = 0x03
	ERR_INVALID_SEQ     Error = 0x04
	ERR_MSG_TIMEOUT     Error = 0x05
	ERR_CHANNEL_BUSY    Error = 0x06
	ERR_LOCK_REQUIRED   Error = 0x0A
	ERR_INVALID_CHANNEL Error = 0x0B
	ERR_OTHER           Error = 0x7F
)

type KeepaliveStatusCode byte

const (
	STATUS_PROCESSING KeepaliveStatusCode = 1
	STATUS_UPNEEDED   KeepaliveStatusCode = 2
)

const INIT_PACKET_BIT byte = 0x80
