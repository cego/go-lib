package slowdown

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	DefaultCurvePreferences = []tls.CurveID{
		tls.CurveP256,
		tls.X25519,
	}

	DefaultCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	DefaultMinVersion        uint16 = tls.VersionTLS12
	DefaultReadTimeout              = 5 * time.Second
	DefaultWriteTimeout             = 10 * time.Second
	DefaultIdleTimeout              = 120 * time.Second
	DefaultReadHeaderTimeout        = 5 * time.Second
)

func WithDefaults(srv *http.Server) *http.Server {
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}

	srv.TLSConfig.MinVersion = DefaultMinVersion
	srv.TLSConfig.CurvePreferences = DefaultCurvePreferences
	srv.TLSConfig.CipherSuites = DefaultCipherSuites

	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = DefaultReadTimeout
	}
	if srv.ReadHeaderTimeout == 0 {
		srv.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if srv.WriteTimeout == 0 {
		srv.WriteTimeout = DefaultWriteTimeout
	}
	if srv.IdleTimeout == 0 {
		srv.IdleTimeout = DefaultIdleTimeout
	}

	return srv
}

type Config struct {
	SignalDelay  time.Duration
	DrainTimeout time.Duration
	OnSignal     func()
	OnDrain      func()
}

func ListenAndServe(srv *http.Server, cfg Config) error {
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return err
	case <-stop:
		srv.SetKeepAlivesEnabled(false)

		if cfg.OnSignal != nil {
			cfg.OnSignal()
		}

		time.Sleep(cfg.SignalDelay)

		if cfg.OnDrain != nil {
			cfg.OnDrain()
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown failed: %w", err)
		}
	}
	return nil
}

func ListenAndServeTLS(srv *http.Server, certFile, keyFile string, cfg Config) error {
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- srv.ListenAndServeTLS(certFile, keyFile)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return err
	case <-stop:
		srv.SetKeepAlivesEnabled(false)

		if cfg.OnSignal != nil {
			cfg.OnSignal()
		}

		time.Sleep(cfg.SignalDelay)

		if cfg.OnDrain != nil {
			cfg.OnDrain()
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown failed: %w", err)
		}
	}
	return nil
}
