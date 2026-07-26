package ctaphid

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireCTAPHIDError(t testing.TB, err error, want Error) {
	t.Helper()
	require.Error(t, err)

	var response *ErrorResponse
	require.ErrorAs(t, err, &response)
	assert.Equal(t, want, response.ErrorCode)
	assert.Equal(t, byte(want), byte(response.ErrorCode))
	assert.EqualError(t, err, want.String())
}

func rawResponseMessage(t testing.TB, cid ChannelID, cmd Command, data []byte) []byte {
	t.Helper()

	msg, err := NewMessage(cid, cmd, data)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(buf)
		require.NoError(t, err)
	}
	return bytes.Clone(buf.Bytes())
}

func assertSingleReportRequest(t testing.TB, written []byte, cid ChannelID, cmd Command, data []byte) {
	t.Helper()

	require.Len(t, written, hidReportPacketSize)
	assert.Equal(t, byte(0), written[0], "report ID")

	raw := written[1:]
	assert.Equal(t, cid[:], raw[:4], "CID")
	assert.Equal(t, byte(cmd)|INIT_PACKET_BIT, raw[4], "command")
	assert.Equal(t, uint16(len(data)), binary.BigEndian.Uint16(raw[5:7]), "BCNT")
	if len(data) == 0 {
		assert.Empty(t, raw[initPacketHeaderSize:initPacketHeaderSize+len(data)])
	} else {
		assert.Equal(t, data, raw[initPacketHeaderSize:initPacketHeaderSize+len(data)])
	}
	assert.Equal(t, make([]byte, initPacketDataSize-len(data)), raw[initPacketHeaderSize+len(data):])
}

func receive[T any](t testing.TB, ch <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
		var zero T
		return zero
	}
}
