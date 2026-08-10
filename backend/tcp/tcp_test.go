package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceReadAssemblesFragmentedReport(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	want := make([]byte, inputReportSize)
	for i := range want {
		want[i] = byte(i)
	}
	go func() {
		_, _ = peer.Write(want[:17])
		_, _ = peer.Write(want[17:])
	}()

	got := make([]byte, inputReportSize)
	n, err := device.Read(context.Background(), got)
	require.NoError(t, err)
	assert.Equal(t, inputReportSize, n)
	assert.Equal(t, want, got)
}

func TestDeviceWriteStripsReportID(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	report := make([]byte, outputReportSize)
	for i := 1; i < len(report); i++ {
		report[i] = byte(i)
	}
	got := make(chan []byte, 1)
	go func() {
		data := make([]byte, inputReportSize)
		_, _ = io.ReadFull(peer, data)
		got <- data
	}()

	n, err := device.Write(context.Background(), report)
	require.NoError(t, err)
	assert.Equal(t, outputReportSize, n)
	assert.Equal(t, report[1:], <-got)
}

func TestDeviceRejectsInvalidReportShapes(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	for _, size := range []int{0, inputReportSize - 1, inputReportSize + 1} {
		n, err := device.Read(context.Background(), make([]byte, size))
		assert.Zero(t, n)
		assert.Error(t, err)
	}
	for _, size := range []int{0, outputReportSize - 1, outputReportSize + 1} {
		n, err := device.Write(context.Background(), make([]byte, size))
		assert.Zero(t, n)
		assert.Error(t, err)
	}

	report := make([]byte, outputReportSize)
	report[0] = 1
	n, err := device.Write(context.Background(), report)
	assert.Zero(t, n)
	assert.Error(t, err)
}

func TestDeviceReadReportsShortInput(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })

	go func() {
		_, _ = peer.Write(make([]byte, inputReportSize-1))
		_ = peer.Close()
	}()

	n, err := device.Read(context.Background(), make([]byte, inputReportSize))
	assert.Equal(t, inputReportSize-1, n)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestDeviceReadCancellationLeavesConnectionReusable(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := device.Read(ctx, make([]byte, inputReportSize))
	assert.Zero(t, n)
	assert.ErrorIs(t, err, context.Canceled)

	want := bytes.Repeat([]byte{0x5a}, inputReportSize)
	go func() { _, _ = peer.Write(want) }()
	got := make([]byte, inputReportSize)
	n, err = device.Read(context.Background(), got)
	require.NoError(t, err)
	assert.Equal(t, inputReportSize, n)
	assert.Equal(t, want, got)
}

func TestDeviceReadCancellationInterruptsBlockedRead(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	n, err := device.Read(ctx, make([]byte, inputReportSize))
	assert.Zero(t, n)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestDeviceWriteCancellationLeavesConnectionReusable(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	report := make([]byte, outputReportSize)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := device.Write(ctx, report)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	readDone := make(chan error, 1)
	go func() {
		data := make([]byte, inputReportSize)
		_, err := io.ReadFull(peer, data)
		readDone <- err
	}()
	n, err := device.Write(context.Background(), report)
	require.NoError(t, err)
	assert.Equal(t, outputReportSize, n)
	require.NoError(t, <-readDone)
}

func TestDeviceWriteReportsConnectionFailure(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	require.NoError(t, peer.Close())

	_, err := device.Write(context.Background(), make([]byte, outputReportSize))
	assert.Error(t, err)
}

func TestDeviceCloseInterruptsBlockedRead(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = peer.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := device.Read(context.Background(), make([]byte, inputReportSize))
		done <- err
	}()

	require.NoError(t, device.Close())
	assert.Error(t, <-done)
}

func TestOpenAllocatesCTAPHIDChannel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		request := make([]byte, inputReportSize)
		if _, err := io.ReadFull(conn, request); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(request[:4], []byte{0xff, 0xff, 0xff, 0xff}) || request[4] != 0x86 {
			serverErr <- errors.New("unexpected CTAPHID_INIT request")
			return
		}

		response := make([]byte, inputReportSize)
		copy(response[:4], request[:4])
		response[4] = 0x86
		binary.BigEndian.PutUint16(response[5:7], 17)
		copy(response[7:15], request[7:15])
		copy(response[15:19], []byte{1, 2, 3, 4})
		copy(response[19:24], []byte{2, 1, 0, 0, 0x04})
		if _, err := conn.Write(response[:11]); err != nil {
			serverErr <- err
			return
		}
		_, err = conn.Write(response[11:])
		serverErr <- err
	}()

	transport, err := Open(context.Background(), listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, transport.Close())
	require.NoError(t, <-serverErr)
}
