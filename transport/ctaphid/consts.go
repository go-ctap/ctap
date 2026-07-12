//go:generate go run golang.org/x/tools/cmd/stringer@v0.47.0 -type=Command,StatusCode,CapabilityFlag,Error,KeepaliveStatusCode -output=consts_string.go
package ctaphid

// Command represents CTAP command.
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

type StatusCode byte

const (
	CTAP2_OK                          StatusCode = 0x00
	CTAP1_ERR_INVALID_COMMAND         StatusCode = 0x01
	CTAP1_ERR_INVALID_PARAMETER       StatusCode = 0x02
	CTAP1_ERR_INVALID_LENGTH          StatusCode = 0x03
	CTAP1_ERR_INVALID_SEQ             StatusCode = 0x04
	CTAP1_ERR_TIMEOUT                 StatusCode = 0x05
	CTAP1_ERR_CHANNEL_BUSY            StatusCode = 0x06
	CTAP1_ERR_LOCK_REQUIRED           StatusCode = 0x0A
	CTAP1_ERR_INVALID_CHANNEL         StatusCode = 0x0B
	CTAP2_ERR_CBOR_UNEXPECTED_TYPE    StatusCode = 0x11
	CTAP2_ERR_INVALID_CBOR            StatusCode = 0x12
	CTAP2_ERR_MISSING_PARAMETER       StatusCode = 0x14
	CTAP2_ERR_LIMIT_EXCEEDED          StatusCode = 0x15
	CTAP2_ERR_FP_DATABASE_FULL        StatusCode = 0x17
	CTAP2_ERR_LARGE_BLOB_STORAGE_FULL StatusCode = 0x18
	CTAP2_ERR_CREDENTIAL_EXCLUDED     StatusCode = 0x19
	CTAP2_ERR_PROCESSING              StatusCode = 0x21
	CTAP2_ERR_INVALID_CREDENTIAL      StatusCode = 0x22
	CTAP2_ERR_USER_ACTION_PENDING     StatusCode = 0x23
	CTAP2_ERR_OPERATION_PENDING       StatusCode = 0x24
	CTAP2_ERR_NO_OPERATIONS           StatusCode = 0x25
	CTAP2_ERR_UNSUPPORTED_ALGORITHM   StatusCode = 0x26
	CTAP2_ERR_OPERATION_DENIED        StatusCode = 0x27
	CTAP2_ERR_KEY_STORE_FULL          StatusCode = 0x28
	CTAP2_ERR_UNSUPPORTED_OPTION      StatusCode = 0x2B
	CTAP2_ERR_INVALID_OPTION          StatusCode = 0x2C
	CTAP2_ERR_KEEPALIVE_CANCEL        StatusCode = 0x2D
	CTAP2_ERR_NO_CREDENTIALS          StatusCode = 0x2E
	CTAP2_ERR_USER_ACTION_TIMEOUT     StatusCode = 0x2F
	CTAP2_ERR_NOT_ALLOWED             StatusCode = 0x30
	CTAP2_ERR_PIN_INVALID             StatusCode = 0x31
	CTAP2_ERR_PIN_BLOCKED             StatusCode = 0x32
	CTAP2_ERR_PIN_AUTH_INVALID        StatusCode = 0x33
	CTAP2_ERR_PIN_AUTH_BLOCKED        StatusCode = 0x34
	CTAP2_ERR_PIN_NOT_SET             StatusCode = 0x35
	CTAP2_ERR_PUAT_REQUIRED           StatusCode = 0x36
	CTAP2_ERR_PIN_POLICY_VIOLATION    StatusCode = 0x37
	RESERVED_FOR_FUTURE_USE           StatusCode = 0x38
	CTAP2_ERR_REQUEST_TOO_LARGE       StatusCode = 0x39
	CTAP2_ERR_ACTION_TIMEOUT          StatusCode = 0x3A
	CTAP2_ERR_UP_REQUIRED             StatusCode = 0x3B
	CTAP2_ERR_UV_BLOCKED              StatusCode = 0x3C
	CTAP2_ERR_INTEGRITY_FAILURE       StatusCode = 0x3D
	CTAP2_ERR_INVALID_SUBCOMMAND      StatusCode = 0x3E
	CTAP2_ERR_UV_INVALID              StatusCode = 0x3F
	CTAP2_ERR_UNAUTHORIZED_PERMISSION StatusCode = 0x40
	CTAP1_ERR_OTHER                   StatusCode = 0x7F
	CTAP2_ERR_SPEC_LAST               StatusCode = 0xDF
	CTAP2_ERR_EXTENSION_FIRST         StatusCode = 0xE0
	CTAP2_ERR_EXTENSION_LAST          StatusCode = 0xEF
	CTAP2_ERR_VENDOR_FIRST            StatusCode = 0xF0
	CTAP2_ERR_VENDOR_LAST             StatusCode = 0xFF
)

type CapabilityFlag byte

const (
	CAPABILITY_WINK CapabilityFlag = 0x01
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
