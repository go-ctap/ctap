package hidproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("blocked I/O was not interrupted")
	}
}

func TestWithContextIOSuccessStopsCancellation(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close() })
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, withContextIO(ctx, conn, func() error { return nil }))
	cancel()

	writeC := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{1})
		writeC <- err
	}()

	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	require.NoError(t, err)
	require.NoError(t, <-writeC)
}
