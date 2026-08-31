package hidproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestWithContextIOInterruptsBlockedIO(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	errC := make(chan error, 1)
	go func() {
		errC <- withContextIO(ctx, conn, func() error {
			close(started)
			_, err := conn.Read(make([]byte, 1))
			return err
		})
	}()

	<-started
	cancel()

	select {
	case err := <-errC:
		{
			err, target := err, context.Canceled
			if !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("blocked I/O was not interrupted")
	}
}

func TestWithContextIOSuccessStopsCancellation(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	if err := withContextIO(ctx, conn, func() error { return nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cancel()

	writeC := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{1})
		writeC <- err
	}()

	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := <-writeC; err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
