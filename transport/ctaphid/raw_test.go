package ctaphid

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessagePayloadBoundaries(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}

	for _, payloadLen := range []int{
		0,
		initPacketDataSize,
		initPacketDataSize + 1,
		7609,
	} {
		t.Run(strconv.Itoa(payloadLen), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, payloadLen)
			message, err := NewMessage(cid, CTAPHID_PING, payload)
			require.NoError(t, err)

			assert.Equal(t, cid, message.CID())
			assert.Equal(t, CTAPHID_PING, message.Command())
			assert.Equal(t, uint16(payloadLen), message.DeclaredLength())
			assert.Equal(t, payload, message.Payload())
		})
	}
}

func TestMessageOutputReportsCanBeModified(t *testing.T) {
	message, err := NewMessage(
		ChannelID{1, 2, 3, 4},
		CTAPHID_PING,
		bytes.Repeat([]byte{0xa5}, initPacketDataSize+1),
	)
	require.NoError(t, err)

	want := message.OutputReports()
	reports := message.OutputReports()
	reports[0][1] ^= 0xff
	reports[0], reports[1] = reports[1], reports[0]
	reports = reports[:1]

	assert.Equal(t, want, message.OutputReports())
}

func TestMessageOutputReportBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		payloadLen  int
		reportCount int
	}{
		{name: "empty", payloadLen: 0, reportCount: 1},
		{name: "init boundary", payloadLen: initPacketDataSize, reportCount: 1},
		{name: "first continuation", payloadLen: initPacketDataSize + 1, reportCount: 2},
		{name: "maximum", payloadLen: 7609, reportCount: 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message, err := NewMessage(
				ChannelID{1, 2, 3, 4},
				CTAPHID_PING,
				bytes.Repeat([]byte{0xa5}, tc.payloadLen),
			)
			require.NoError(t, err)

			reports := message.OutputReports()
			require.Len(t, reports, tc.reportCount)
			for _, report := range reports {
				assert.Zero(t, report[0])
			}
		})
	}
}
