package slowdown_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/cego/go-lib/v2/slowdown"
	"github.com/stretchr/testify/assert"
)

func TestWithDefaults(t *testing.T) {
	t.Run("sets defaults on empty server", func(t *testing.T) {
		srv := &http.Server{}
		result := slowdown.WithDefaults(srv)

		assert.Equal(t, slowdown.DefaultReadTimeout, result.ReadTimeout)
		assert.Equal(t, slowdown.DefaultWriteTimeout, result.WriteTimeout)
		assert.Equal(t, slowdown.DefaultIdleTimeout, result.IdleTimeout)
		assert.Equal(t, slowdown.DefaultReadHeaderTimeout, result.ReadHeaderTimeout)
		assert.NotNil(t, result.TLSConfig)
		assert.Equal(t, slowdown.DefaultMinVersion, result.TLSConfig.MinVersion)
	})

	t.Run("preserves existing timeouts", func(t *testing.T) {
		srv := &http.Server{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		}
		result := slowdown.WithDefaults(srv)

		assert.Equal(t, 30*time.Second, result.ReadTimeout)
		assert.Equal(t, 60*time.Second, result.WriteTimeout)
		assert.Equal(t, slowdown.DefaultIdleTimeout, result.IdleTimeout)
	})

	t.Run("preserves existing TLSConfig", func(t *testing.T) {
		srv := &http.Server{
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		}
		result := slowdown.WithDefaults(srv)

		assert.Equal(t, slowdown.DefaultMinVersion, result.TLSConfig.MinVersion)
	})
}

func TestListenAndServe_ServerError(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	assert.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	srv := &http.Server{Addr: ":" + string(rune(port)), Handler: http.NewServeMux()}
	srv.Addr = listener.Addr().String()

	listener2, _ := net.Listen("tcp", srv.Addr)
	defer listener2.Close()

	cfg := slowdown.Config{
		SignalDelay:  100 * time.Millisecond,
		DrainTimeout: 100 * time.Millisecond,
	}

	err = slowdown.ListenAndServe(srv, cfg)
	assert.Error(t, err)
}

func TestListenAndServe_GracefulShutdown(t *testing.T) {
	srv := &http.Server{Addr: ":0", Handler: http.NewServeMux()}

	onSignalCalled := false
	onDrainCalled := false
	cfg := slowdown.Config{
		SignalDelay:  50 * time.Millisecond,
		DrainTimeout: 100 * time.Millisecond,
		OnSignal: func() {
			onSignalCalled = true
		},
		OnDrain: func() {
			onDrainCalled = true
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- slowdown.ListenAndServe(srv, cfg)
	}()

	time.Sleep(50 * time.Millisecond)

	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	select {
	case err := <-done:
		assert.NoError(t, err)
		assert.True(t, onSignalCalled)
		assert.True(t, onDrainCalled)
	case <-time.After(1 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestListenAndServeTLS_ServerError(t *testing.T) {
	srv := &http.Server{Addr: ":0", Handler: http.NewServeMux()}

	cfg := slowdown.Config{
		SignalDelay:  100 * time.Millisecond,
		DrainTimeout: 100 * time.Millisecond,
	}

	err := slowdown.ListenAndServeTLS(srv, "nonexistent.crt", "nonexistent.key", cfg)
	assert.Error(t, err)
}
