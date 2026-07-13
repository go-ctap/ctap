package ctaphid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCBORSkipsKeepaliveBeforeSuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	request := []byte{byte(protocol.AuthenticatorGetInfo)}
	response := []byte{byte(ctaptransport.CTAP2_OK), 0xa1, 0x01, 0x02}
	reads := bytes.NewBuffer(nil)
	reads.Write(rawResponseMessage(t, cid, CTAPHID_KEEPALIVE, []byte{byte(STATUS_PROCESSING)}))
	reads.Write(rawResponseMessage(t, cid, CTAPHID_CBOR, response))

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}

	resp, err := CBOR(dev, cid, request)
	require.NoError(t, err)
	assert.Equal(t, ctaptransport.CTAP2_OK, resp.StatusCode)
	assert.Equal(t, response[1:], resp.Data)
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CBOR, request)
}

func TestCBORReturnsTypedCTAPError(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	request := []byte{byte(protocol.AuthenticatorGetInfo)}
	response := []byte{byte(ctaptransport.CTAP2_ERR_INVALID_CBOR)}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_CBOR, response)),
	}

	_, err := CBOR(dev, cid, request)
	require.Error(t, err)

	var ctapErr *ctaptransport.CTAPError
	require.True(t, errors.As(err, &ctapErr))
	assert.Equal(t, protocol.AuthenticatorGetInfo, ctapErr.Command)
	assert.Equal(t, ctaptransport.CTAP2_ERR_INVALID_CBOR, ctapErr.StatusCode)
	assert.Contains(t, err.Error(), "AuthenticatorGetInfo failed")
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CBOR, request)
}

func TestCBORRejectsMissingCommandByte(t *testing.T) {
	dev := &scriptedDevice{reads: bytes.NewReader(nil)}

	_, err := CBOR(dev, ChannelID{1, 2, 3, 4}, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequestMessage))
	assert.Empty(t, dev.writes.Bytes())
}

func TestInitAcceptsExtendedSuccessResponse(t *testing.T) {
	// CTAP 2.3 PS, 11.2.9.1.3: INIT response is at least 17 bytes, and
	// hosts SHALL accept longer responses for future-compatible extensions.
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	allocatedCID := ChannelID{9, 8, 7, 6}
	responseData := append([]byte{}, nonce...)
	responseData = append(responseData, allocatedCID[:]...)
	responseData = append(responseData, 2, 3, 4, 5, byte(CAPABILITY_WINK)|byte(CAPABILITY_CBOR))
	responseData = append(responseData, 0xfe, 0xed)

	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, BROADCAST_CID, CTAPHID_INIT, responseData)),
	}

	resp, err := Init(dev, BROADCAST_CID, nonce)
	require.NoError(t, err)
	assert.Equal(t, nonce, resp.Nonce)
	assert.Equal(t, allocatedCID, resp.CID)
	assert.Equal(t, byte(2), resp.CTAPHIDProtocolVersionIdentifier)
	assert.Equal(t, byte(3), resp.MajorDeviceVersion)
	assert.Equal(t, byte(4), resp.MinorDeviceVersion)
	assert.Equal(t, byte(5), resp.BuildDeviceVersion)
	assert.True(t, resp.ImplementsWink())
	assert.True(t, resp.ImplementsCBOR())
	assert.False(t, resp.NotImplementsMSG())

	assertSingleReportRequest(t, dev.writes.Bytes(), BROADCAST_CID, CTAPHID_INIT, nonce)
}

func TestInitReturnsCTAPHIDError(t *testing.T) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, BROADCAST_CID, CTAPHID_ERROR, []byte{byte(ERR_INVALID_CHANNEL)})),
	}

	_, err := Init(dev, BROADCAST_CID, nonce)
	require.Error(t, err)
	assert.EqualError(t, err, ERR_INVALID_CHANNEL.String())
	assertSingleReportRequest(t, dev.writes.Bytes(), BROADCAST_CID, CTAPHID_INIT, nonce)
}

func TestInitRejectsInvalidNonceLength(t *testing.T) {
	dev := &scriptedDevice{reads: bytes.NewReader(nil)}

	_, err := Init(dev, BROADCAST_CID, []byte{1, 2, 3, 4, 5, 6, 7})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequestMessage))
	assert.Empty(t, dev.writes.Bytes())
}

func TestPingSkipsKeepaliveBeforeSuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	ping := []byte("hello")
	reads := bytes.NewBuffer(nil)
	reads.Write(rawResponseMessage(t, cid, CTAPHID_KEEPALIVE, []byte{byte(STATUS_PROCESSING)}))
	reads.Write(rawResponseMessage(t, cid, CTAPHID_PING, ping))

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}

	resp, err := Ping(dev, cid, ping)
	require.NoError(t, err)
	assert.Equal(t, ping, resp.Bytes)
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_PING, ping)
}

func TestPingReturnsCTAPHIDError(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	ping := []byte("hello")
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_ERROR, []byte{byte(ERR_INVALID_LEN)})),
	}

	_, err := Ping(dev, cid, ping)
	require.Error(t, err)
	assert.EqualError(t, err, ERR_INVALID_LEN.String())
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_PING, ping)
}

func TestCancelWritesRequestAndDoesNotReadResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{reads: bytes.NewReader(nil)}

	err := Cancel(dev, cid)
	require.NoError(t, err)
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_CANCEL, nil)
}

func TestWinkWritesRequestAndAcceptsEmptySuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_WINK, nil)),
	}

	err := Wink(dev, cid)
	require.NoError(t, err)
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_WINK, nil)
}

func TestLockRejectsInvalidDuration(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{reads: bytes.NewReader(nil)}

	err := Lock(dev, cid, 11)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequestMessage))
	assert.Empty(t, dev.writes.Bytes())
}

func TestLockWritesDurationAndAcceptsEmptySuccessResponse(t *testing.T) {
	cid := ChannelID{1, 2, 3, 4}
	dev := &scriptedDevice{
		reads: bytes.NewReader(rawResponseMessage(t, cid, CTAPHID_LOCK, nil)),
	}

	err := Lock(dev, cid, 10)
	require.NoError(t, err)
	assertSingleReportRequest(t, dev.writes.Bytes(), cid, CTAPHID_LOCK, []byte{10})
}

func rawResponseMessage(t *testing.T, cid ChannelID, cmd Command, data []byte) []byte {
	t.Helper()

	msg, err := NewMessage(cid, cmd, data)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(buf)
		require.NoError(t, err)
	}

	return buf.Bytes()
}

func assertSingleReportRequest(t *testing.T, written []byte, cid ChannelID, cmd Command, data []byte) {
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
