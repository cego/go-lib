package serve_test

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/cego/go-lib/v2/serve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithDefaults(t *testing.T) {
	t.Run("sets defaults on empty server", func(t *testing.T) {
		result := serve.WithDefaults(&http.Server{})

		assert.Equal(t, serve.DefaultReadTimeout, result.ReadTimeout)
		assert.Equal(t, serve.DefaultWriteTimeout, result.WriteTimeout)
		assert.Equal(t, serve.DefaultIdleTimeout, result.IdleTimeout)
		assert.Equal(t, serve.DefaultReadHeaderTimeout, result.ReadHeaderTimeout)
		assert.Equal(t, serve.DefaultShutdownDelay, result.ShutdownDelay)
		assert.Equal(t, serve.DefaultDrainTimeout, result.DrainTimeout)
	})

	t.Run("preserves existing timeouts", func(t *testing.T) {
		result := serve.WithDefaults(&http.Server{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		})

		assert.Equal(t, 30*time.Second, result.ReadTimeout)
		assert.Equal(t, 60*time.Second, result.WriteTimeout)
		assert.Equal(t, serve.DefaultIdleTimeout, result.IdleTimeout)
	})
}

func TestListenAndServe_ServerError(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	_ = listener.Close()

	listener2, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = listener2.Close() }()

	srv := serve.WithDefaults(&http.Server{Addr: addr, Handler: http.NewServeMux()})
	srv.ShutdownDelay = 100 * time.Millisecond
	srv.DrainTimeout = 100 * time.Millisecond

	err = serve.ListenAndServe(context.Background(), srv, slog.Default())
	assert.Error(t, err)
}

func TestListenAndServe_GracefulShutdown(t *testing.T) {
	srv := serve.WithDefaults(&http.Server{Addr: ":0", Handler: http.NewServeMux()})
	srv.ShutdownDelay = 50 * time.Millisecond
	srv.DrainTimeout = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serve.ListenAndServe(ctx, srv, slog.Default())
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestListenAndServe_SignalShutdown(t *testing.T) {
	srv := serve.WithDefaults(&http.Server{Addr: ":0", Handler: http.NewServeMux()})
	srv.ShutdownDelay = 50 * time.Millisecond
	srv.DrainTimeout = 100 * time.Millisecond

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	done := make(chan error, 1)
	go func() {
		done <- serve.ListenAndServe(ctx, srv, slog.Default())
	}()

	time.Sleep(50 * time.Millisecond)
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestListenAndServeTLS_ServerError(t *testing.T) {
	srv := serve.WithDefaults(&http.Server{Addr: ":0", Handler: http.NewServeMux()})
	srv.ShutdownDelay = 100 * time.Millisecond
	srv.DrainTimeout = 100 * time.Millisecond

	err := serve.ListenAndServeTLS(context.Background(), srv, slog.Default(), "nonexistent.crt", "nonexistent.key")
	assert.Error(t, err)
}
