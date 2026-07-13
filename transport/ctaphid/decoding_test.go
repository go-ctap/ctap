package ctaphid

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	getInfoResponseDump = "y2QaNpABawCyAYRmVTJGX1YyaEZJRE9fMl8waEZJRE9fMl8xbEZJRE9fMl8xX1BSRQKFaGNyZWRCbG9ia2NyZctkGjYAZFByb3RlY3RraG1hYy1zZWNyZXRsbGFyZ2VCbG9iS2V5bG1pblBpbkxlbmd0aANQ6rtGzOJBgL+unpbLZBo2AfptKXXPBKxicmv1YnVw9WRwbGF09GhhbHdheXNVdvRoY3JlZE1nbXT1aWF1dGhuckNmZ/VpY2xpZW50y2QaNgJQaW71amxhcmdlQmxvYnP1bnBpblV2QXV0aFRva2Vu9W9zZXRNaW5QSU5MZW5ndGj1cG1ha2VDcmVkVctkGjYDdk5vdFJxZPV1Y3JlZGVudGlhbE1nbXRQcmV2aWV39QUZCAAGggIBBwgIGGAJgmN1c2JjbmZjCoKiY2HLZBo2BGxnJmR0eXBlanB1YmxpYy1rZXmiY2FsZydkdHlwZWpwdWJsaWMta2V5CxkIAAz0DQYOGQEADxggEAYTy2QaNgWhZEZJRE8DFBkBFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

type scriptedDevice struct {
	reads  *bytes.Reader
	writes bytes.Buffer
}

func (d *scriptedDevice) Read(p []byte) (int, error) {
	return d.reads.Read(p)
}

func (d *scriptedDevice) Write(p []byte) (int, error) {
	return d.writes.Write(p)
}

func (d *scriptedDevice) Close() error { return nil }

func TestMessage_ReadFrom(t *testing.T) {
	m := new(Message)

	resp, _ := base64.StdEncoding.DecodeString(getInfoResponseDump)
	device := bytes.NewReader(resp)

	n, err := m.ReadFrom(device)
	require.NoError(t, err)

	assert.Equal(t, int64(len(resp)), n)
}

func TestMessage_ReadFromRejectsInvalidContinuationSequence(t *testing.T) {
	raw := newRawMessage(t)
	raw[hidPacketSize+4] = 1

	m := new(Message)
	_, err := m.ReadFrom(bytes.NewReader(raw))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidResponseMessage))
}

func TestMessage_ReadFromRejectsInvalidContinuationCID(t *testing.T) {
	raw := newRawMessage(t)
	raw[hidPacketSize] ^= 0xff

	m := new(Message)
	_, err := m.ReadFrom(bytes.NewReader(raw))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidResponseMessage))
}

func TestCBORRejectsUnexpectedResponseCID(t *testing.T) {
	responseCID := ChannelID{9, 9, 9, 9}
	msg, err := NewMessage(responseCID, CTAPHID_CBOR, []byte{byte(ctaptransport.CTAP2_OK)})
	require.NoError(t, err)

	reads := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(reads)
		require.NoError(t, err)
	}

	dev := &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}
	_, err = NewTransport(dev, ChannelID{1, 2, 3, 4}).CBOR(context.Background(), []byte{0x04})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidResponseMessage))
}

func newRawMessage(t *testing.T) []byte {
	t.Helper()

	msg, err := NewMessage(ChannelID{1, 2, 3, 4}, CTAPHID_CBOR, bytes.Repeat([]byte{0xaa}, initPacketDataSize+1))
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(buf)
		require.NoError(t, err)
	}

	return buf.Bytes()
}
