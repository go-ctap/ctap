package ctapble

import "github.com/telesma-app/ble"

// Command is a CTAP BLE encapsulation command or response status.
type Command byte

// CTAP 2.3, sections 11.4.4.3 and 11.4.5.1 define the names and values below.
const (
	PING      Command = 0x81
	KEEPALIVE Command = 0x82
	MSG       Command = 0x83
	CANCEL    Command = 0xbe
	ERROR     Command = 0xbf
)

// ErrorCode is an error reported by the CTAP BLE encapsulation layer.
type ErrorCode byte

const (
	ERR_INVALID_CMD ErrorCode = 0x01
	ERR_INVALID_PAR ErrorCode = 0x02
	ERR_INVALID_LEN ErrorCode = 0x03
	ERR_INVALID_SEQ ErrorCode = 0x04
	ERR_REQ_TIMEOUT ErrorCode = 0x05
	ERR_BUSY        ErrorCode = 0x06
	ERR_OTHER       ErrorCode = 0x7f
)

const (
	fidoServiceUUID16               = 0xfffd
	fido2RevisionBit           byte = 0x20
	fidoControlPointLengthSize      = 2
	minFIDOControlPointLength       = 20
	maxFIDOControlPointLength       = 512
	keepaliveDataLength             = 1
)

var (
	fidoServiceUUID                 = ble.UUID16(fidoServiceUUID16)
	fidoControlPointUUID            = ble.UUID{0xf1, 0xd0, 0xff, 0xf1, 0xde, 0xaa, 0xec, 0xee, 0xb4, 0x2f, 0xc9, 0xba, 0x7e, 0xd6, 0x23, 0xbb}
	fidoStatusUUID                  = ble.UUID{0xf1, 0xd0, 0xff, 0xf2, 0xde, 0xaa, 0xec, 0xee, 0xb4, 0x2f, 0xc9, 0xba, 0x7e, 0xd6, 0x23, 0xbb}
	fidoControlPointLengthUUID      = ble.UUID{0xf1, 0xd0, 0xff, 0xf3, 0xde, 0xaa, 0xec, 0xee, 0xb4, 0x2f, 0xc9, 0xba, 0x7e, 0xd6, 0x23, 0xbb}
	fidoServiceRevisionBitfieldUUID = ble.UUID{0xf1, 0xd0, 0xff, 0xf4, 0xde, 0xaa, 0xec, 0xee, 0xb4, 0x2f, 0xc9, 0xba, 0x7e, 0xd6, 0x23, 0xbb}
)
