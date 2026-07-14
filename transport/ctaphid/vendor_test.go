package ctaphid_test

import (
	"context"
	"testing"

	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVendorRejectsNonVendorCommand(t *testing.T) {
	transport := ctaphid.NewTransport(testhid.New(t), ctaphid.ChannelID{})
	_, err := transport.Vendor(context.Background(), ctaphid.CTAPHID_PING, nil)
	require.ErrorIs(t, err, ctaphid.ErrInvalidRequestMessage)
}

func TestVendorReturnsCTAPHIDError(t *testing.T) {
	cid := ctaphid.ChannelID{1, 2, 3, 4}
	fake := testhid.New(t, testhid.CTAPHIDError(cid, ctaphid.ERR_INVALID_CMD))
	transport := ctaphid.NewTransport(fake, cid)
	_, err := transport.Vendor(context.Background(), ctaphid.CTAPHID_VENDOR_FIRST, nil)
	require.Error(t, err)

	var response *ctaphid.ErrorResponse
	require.ErrorAs(t, err, &response)
	assert.Equal(t, ctaphid.ERR_INVALID_CMD, response.ErrorCode)
	assert.EqualError(t, err, ctaphid.ERR_INVALID_CMD.String())
}
