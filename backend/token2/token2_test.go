package token2

import (
	"errors"
	"fmt"
	"testing"

	token2transport "github.com/telesma-app/ctap/transport/token2"
	"github.com/stretchr/testify/assert"
)

func TestUnsupportedCardClassification(t *testing.T) {
	assert.True(t, isUnsupportedCard(&token2transport.APDUError{SW1: 0x6a, SW2: 0x82}))
	assert.True(t, isUnsupportedCard(fmt.Errorf("select applet: %w", token2transport.ErrInvalidResponse)))
	assert.False(t, isUnsupportedCard(errors.New("PC/SC service unavailable")))
}
