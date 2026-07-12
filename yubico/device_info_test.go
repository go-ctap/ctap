package yubico

import (
	"errors"
	"testing"

	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDeviceInfo(t *testing.T) {
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	payload := []byte{39,
		0x01, 2, 0x02, 0x3f,
		0x02, 4, 0x00, 0x12, 0x34, 0x56,
		0x03, 2, 0x02, 0x22,
		0x04, 1, 0x43,
		0x05, 3, 5, 7, 1,
		0x06, 2, 0x00, 0x0a,
		0x07, 1, 15,
		0x08, 1, 0x40,
		0x0a, 1, 1,
		0x20, 2, 0xaa, 0xbb,
	}
	fake := testhid.New(t, testhid.Message(cid, CommandGetDeviceInfo, payload))

	info, err := GetDeviceInfo(fake, cid)
	require.NoError(t, err)
	require.NotNil(t, info.Serial)
	assert.Equal(t, uint32(0x00123456), *info.Serial)
	assert.Equal(t, Capability(0x023f), info.SupportedUSBCapabilities)
	assert.Equal(t, FirmwareVersion{Major: 5, Minor: 7, Build: 1}, info.FirmwareVersion)
	assert.Equal(t, FormFactorUSBCKeychain, info.FormFactor)
	assert.True(t, info.IsSecurityKey)
	assert.False(t, info.IsFIPS)
	assert.True(t, info.Locked)
	assert.Equal(t, uint16(10), info.AutoEjectTimeout)
	assert.Equal(t, byte(15), info.ChallengeResponseTimeout)
	assert.Equal(t, []byte{0xaa, 0xbb}, info.UnknownFields[0x20])

	request := fake.FirstRequest(t)
	assert.Equal(t, CommandGetDeviceInfo, request.Command)
	assert.Empty(t, request.Data)
}

func TestParseDeviceInfoRejectsMalformedData(t *testing.T) {
	tests := [][]byte{
		nil,
		{2, 0x01},
		{3, 0x01, 2, 0xff},
		{4, 0x02, 1, 0xff},
		{3, 0x0a, 1, 2},
	}
	for _, data := range tests {
		_, err := ParseDeviceInfo(data)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidDeviceInfo))
	}
}

func TestParseDeviceInfoAllowsOmittedAndRepeatedFields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{8,
		0x04, 1, 0x01,
		0x04, 1, 0x03,
		0x20, 0,
	})
	require.NoError(t, err)
	assert.Equal(t, FormFactorUSBCKeychain, info.FormFactor)
	assert.Zero(t, info.FirmwareVersion)
}
