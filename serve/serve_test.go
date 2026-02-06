package serve_test

import (
	"context"
	"crypto/tls"
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
		srv := &http.Server{}
		result := serve.WithDefaults(srv)

		assert.Equal(t, serve.DefaultReadTimeout, result.ReadTimeout)
		assert.Equal(t, serve.DefaultWriteTimeout, result.WriteTimeout)
		assert.Equal(t, serve.DefaultIdleTimeout, result.IdleTimeout)
		assert.Equal(t, serve.DefaultReadHeaderTimeout, result.ReadHeaderTimeout)
		assert.NotNil(t, result.TLSConfig)
		assert.Equal(t, serve.DefaultMinVersion, result.TLSConfig.MinVersion)
		assert.Equal(t, serve.DefaultCurvePreferences, result.TLSConfig.CurvePreferences)
	})

	t.Run("preserves existing timeouts", func(t *testing.T) {
		srv := &http.Server{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		}
		result := serve.WithDefaults(srv)

		assert.Equal(t, 30*time.Second, result.ReadTimeout)
		assert.Equal(t, 60*time.Second, result.WriteTimeout)
		assert.Equal(t, serve.DefaultIdleTimeout, result.IdleTimeout)
	})

	t.Run("preserves existing TLSConfig", func(t *testing.T) {
		customCurves := []tls.CurveID{tls.X25519}
		srv := &http.Server{
			TLSConfig: &tls.Config{
				MinVersion:       tls.VersionTLS13,
				CurvePreferences: customCurves,
			},
		}
		result := serve.WithDefaults(srv)

		assert.Equal(t, uint16(tls.VersionTLS13), result.TLSConfig.MinVersion)
		assert.Equal(t, customCurves, result.TLSConfig.CurvePreferences)
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

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}

	cfg := serve.Config{
		ShutdownDelay: 100 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
	}

	err = serve.ListenAndServe(context.Background(), srv, cfg)
	assert.Error(t, err)
}

func TestListenAndServe_GracefulShutdown(t *testing.T) {
	srv := &http.Server{Addr: ":0", Handler: http.NewServeMux()}

	cfg := serve.Config{
		ShutdownDelay: 50 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serve.ListenAndServe(ctx, srv, cfg)
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

func TestListenAndServe_GracefulShutdownWithLogger(t *testing.T) {
	srv := &http.Server{Addr: ":0", Handler: http.NewServeMux()}

	cfg := serve.Config{
		ShutdownDelay: 50 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
		Logger:        slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- serve.ListenAndServe(ctx, srv, cfg)
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
	srv := &http.Server{Addr: ":0", Handler: http.NewServeMux()}

	cfg := serve.Config{
		ShutdownDelay: 50 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	done := make(chan error, 1)
	go func() {
		done <- serve.ListenAndServe(ctx, srv, cfg)
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
	srv := &http.Server{Addr: ":0", Handler: http.NewServeMux()}

	cfg := serve.Config{
		ShutdownDelay: 100 * time.Millisecond,
		DrainTimeout:  100 * time.Millisecond,
	}

	err := serve.ListenAndServeTLS(context.Background(), srv, "nonexistent.crt", "nonexistent.key", cfg)
	assert.Error(t, err)
}
