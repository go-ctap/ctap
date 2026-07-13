package ctaphid

import "errors"

var (
	ErrMessageTooLarge        = errors.New("ctaphid: message payload too large")
	ErrInvalidRequestMessage  = errors.New("ctaphid: invalid request message")
	ErrUnexpectedCommand      = errors.New("ctaphid: unexpected command")
	ErrInvalidResponseMessage = errors.New("ctaphid: invalid response message")
)
