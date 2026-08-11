package ctapble

import (
	"errors"
	"fmt"
)

var (
	ErrDataTooLarge                    = errors.New("ctapble: frame data too large")
	ErrInvalidFrame                    = errors.New("ctapble: invalid frame")
	ErrUnexpectedStatus                = errors.New("ctapble: unexpected response status")
	ErrFIDOServiceNotFound             = errors.New("ctapble: primary FIDO service not found")
	ErrFIDOCharacteristicNotFound      = errors.New("ctapble: required FIDO characteristic not found")
	ErrInvalidCharacteristicProperties = errors.New("ctapble: invalid characteristic properties")
	ErrFIDO2Unsupported                = errors.New("ctapble: FIDO2 BLE revision is unsupported")
	ErrInvalidFIDOControlPointLength   = errors.New("ctapble: invalid fidoControlPointLength")
)

// ErrorResponse reports an error returned by the CTAP BLE encapsulation layer.
type ErrorResponse struct {
	ErrorCode ErrorCode
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("ctapble: encapsulation error 0x%02x", byte(e.ErrorCode))
}
