package slowdown

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

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
