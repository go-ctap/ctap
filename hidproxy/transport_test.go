package hidproxy

import (
	"testing"

	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitCTAPHIDAllocatesChannelAndTransfersDevice(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	cid := ctaphid.ChannelID{9, 8, 7, 6}
	response := append([]byte{}, nonce...)
	response = append(response, cid[:]...)
	response = append(response, 2, 1, 0, 0, byte(ctaphid.CAPABILITY_CBOR))
	fake := testhid.New(t, testhid.Message(
		ctaphid.BROADCAST_CID,
		ctaphid.CTAPHID_INIT,
		response,
	))

	transport, err := initCTAPHID(fake, nonce)
	require.NoError(t, err)

	request := fake.FirstRequest(t)
	assert.Equal(t, ctaphid.BROADCAST_CID, request.CID)
	assert.Equal(t, ctaphid.CTAPHID_INIT, request.Command)
	assert.Equal(t, nonce, request.Data)

	require.NoError(t, transport.Close())
	assert.True(t, fake.Closed())
}
