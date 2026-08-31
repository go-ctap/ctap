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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := inputReportSize, n
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := want, got
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := outputReportSize, n
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := report[1:], <-got
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestDeviceRejectsInvalidReportShapes(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	for _, size := range []int{0, inputReportSize - 1, inputReportSize + 1} {
		n, err := device.Read(context.Background(), make([]byte, size))
		if got := n; !(got == 0) {
			t.Errorf("got %#v, want zero value", got)
		}
		if err == nil {
			t.Errorf("expected an error")
		}
	}
	for _, size := range []int{0, outputReportSize - 1, outputReportSize + 1} {
		n, err := device.Write(context.Background(), make([]byte, size))
		if got := n; !(got == 0) {
			t.Errorf("got %#v, want zero value", got)
		}
		if err == nil {
			t.Errorf("expected an error")
		}
	}

	report := make([]byte, outputReportSize)
	report[0] = 1
	n, err := device.Write(context.Background(), report)
	if got := n; !(got == 0) {
		t.Errorf("got %#v, want zero value", got)
	}
	if err == nil {
		t.Errorf("expected an error")
	}
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
	{
		want, got := inputReportSize-1, n
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		err, target := err, io.ErrUnexpectedEOF
		if !errors.Is(err, target) {
			t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
}

func TestDeviceReadCancellationLeavesConnectionReusable(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n, err := device.Read(ctx, make([]byte, inputReportSize))
	if got := n; !(got == 0) {
		t.Errorf("got %#v, want zero value", got)
	}
	{
		err, target := err, context.Canceled
		if !errors.Is(err, target) {
			t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}

	want := bytes.Repeat([]byte{0x5a}, inputReportSize)
	go func() { _, _ = peer.Write(want) }()
	got := make([]byte, inputReportSize)
	n, err = device.Read(context.Background(), got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := inputReportSize, n
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := want, got
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestDeviceReadCancellationInterruptsBlockedRead(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	n, err := device.Read(ctx, make([]byte, inputReportSize))
	if got := n; !(got == 0) {
		t.Errorf("got %#v, want zero value", got)
	}
	{
		err, target := err, context.DeadlineExceeded
		if !errors.Is(err, target) {
			t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}
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
	{
		err, target := err, context.DeadlineExceeded
		if !errors.Is(err, target) {
			t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
		}
	}

	readDone := make(chan error, 1)
	go func() {
		data := make([]byte, inputReportSize)
		_, err := io.ReadFull(peer, data)
		readDone <- err
	}()
	n, err := device.Write(context.Background(), report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := outputReportSize, n
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if err := <-readDone; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeviceWriteReportsConnectionFailure(t *testing.T) {
	conn, peer := net.Pipe()
	device := &Device{conn: conn}
	t.Cleanup(func() { _ = device.Close() })
	if err := peer.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := device.Write(context.Background(), make([]byte, outputReportSize))
	if err == nil {
		t.Errorf("expected an error")
	}
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

	if err := device.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := <-done; err == nil {
		t.Errorf("expected an error")
	}
}

func TestOpenAllocatesCTAPHIDChannel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
