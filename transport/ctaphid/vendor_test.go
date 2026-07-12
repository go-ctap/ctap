package ctaphid_test

import (
	"testing"

	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVendorRejectsNonVendorCommand(t *testing.T) {
	_, err := ctaphid.Vendor(testhid.New(t), ctaphid.ChannelID{}, ctaphid.CTAPHID_PING, nil)
	require.ErrorIs(t, err, ctaphid.ErrInvalidRequestMessage)
}

func TestVendorReturnsCTAPHIDError(t *testing.T) {
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	fake := testhid.New(t, testhid.CTAPHIDError(cid, ctaphid.ERR_INVALID_CMD))
	_, err := ctaphid.Vendor(fake, cid, ctaphid.CTAPHID_VENDOR_FIRST, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ctaphid.ERR_INVALID_CMD.String())
}
