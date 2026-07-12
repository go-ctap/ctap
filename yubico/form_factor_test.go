package yubico

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormFactorString(t *testing.T) {
	assert.Equal(t, "FormFactorUnknown", FormFactorUnknown.String())
	assert.Equal(t, "FormFactorUSBCNano", FormFactorUSBCNano.String())
	assert.Equal(t, "FormFactorUSBCBiometricKeychain", FormFactorUSBCBiometricKeychain.String())
}
