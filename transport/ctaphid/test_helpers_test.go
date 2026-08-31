package ctaphid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func requireCTAPHIDError(t testing.TB, err error, want Error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}

	var response *ErrorResponse
	if err := err; !errors.As(err, &response) {
		t.Fatalf("error %v does not match requested type", err)
	}
	{
		want, got := want, response.ErrorCode
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := byte(want), byte(response.ErrorCode)
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		err, want := err, want.String()
		if err == nil || err.Error() != want {
			t.Errorf("got error %v, want %q", err, want)
		}
	}
}

func rawResponseMessage(t testing.TB, cid ChannelID, cmd Command, data []byte) []byte {
	t.Helper()

	msg, err := NewMessage(cid, cmd, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	buf := bytes.NewBuffer(nil)
	for _, p := range msg {
		_, err := p.WriteTo(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	return bytes.Clone(buf.Bytes())
}

func assertSingleReportRequest(t testing.TB, written []byte, cid ChannelID, cmd Command, data []byte) {
	t.Helper()

	if got, want := len(written), hidReportPacketSize; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	{
		want, got := byte(0), written[0]
		if got != want {
			t.Errorf("got %#v, want %#v; context: %s", got, want, fmt.Sprint("report ID"))
		}
	}

	raw := written[1:]
	{
		want, got := cid[:], raw[:4]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v; context: %s", got, want, fmt.Sprint("CID"))
		}
	}
	{
		want, got := byte(cmd)|INIT_PACKET_BIT, raw[4]
		if got != want {
			t.Errorf("got %#v, want %#v; context: %s", got, want, fmt.Sprint("command"))
		}
	}
	{
		want, got := uint16(len(data)), binary.BigEndian.Uint16(raw[5:7])
		if got != want {
			t.Errorf("got %#v, want %#v; context: %s", got, want, fmt.Sprint("BCNT"))
		}
	}
	if len(data) == 0 {
		if got := raw[initPacketHeaderSize : initPacketHeaderSize+len(data)]; len(got) != 0 {
			t.Errorf("got non-empty value %#v", got)
		}
	} else {
		{
			want, got := data, raw[initPacketHeaderSize:initPacketHeaderSize+len(data)]
			if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}
		}
	}
	{
		want, got := make([]byte, initPacketDataSize-len(data)), raw[initPacketHeaderSize+len(data):]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
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
