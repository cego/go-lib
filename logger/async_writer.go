package logger

import (
	"io"
	"sync"
	"sync/atomic"
)

// AsyncWriter wraps an io.Writer and drains writes on a background
// goroutine through a buffered channel. Callers on request hot paths
// don't stall on pipe backpressure when stdout's consumer (filebeat,
// the container runtime, kubectl logs) falls behind.
//
// When the buffer is full, Write drops the line and increments a
// counter exposed via Dropped(). Call Close() during shutdown to flush
// queued lines.
type AsyncWriter struct {
	w         io.Writer
	ch        chan []byte
	flushCh   chan chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	dropped   atomic.Uint64
}

// NewAsyncWriter returns an AsyncWriter that drains to w using a buffer
// of capacity queued writes. A goroutine is spawned to drain the
// buffer; call Close to stop it.
func NewAsyncWriter(w io.Writer, capacity int) *AsyncWriter {
	a := &AsyncWriter{
		w:       w,
		ch:      make(chan []byte, capacity),
		flushCh: make(chan chan struct{}),
		done:    make(chan struct{}),
	}
	go a.run()
	return a
}

func (a *AsyncWriter) run() {
	defer close(a.done)
	for {
		select {
		case buf, ok := <-a.ch:
			if !ok {
				return
			}
			_, _ = a.w.Write(buf)
		case done := <-a.flushCh:
			a.drainPending()
			close(done)
		}
	}
}

// drainPending writes everything currently queued in a.ch and returns.
// Called only from run, so there's no concurrent reader of a.ch.
func (a *AsyncWriter) drainPending() {
	for {
		select {
		case buf, ok := <-a.ch:
			if !ok {
				return
			}
			_, _ = a.w.Write(buf)
		default:
			return
		}
	}
}

// Write queues p for the drain goroutine. It never blocks: if the
// buffer is full the write is dropped and counted.
//
// slog reuses the slice it hands to handlers, so we copy before
// queueing.
func (a *AsyncWriter) Write(p []byte) (int, error) {
	if a.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case a.ch <- buf:
	default:
		a.dropped.Add(1)
	}
	return len(p), nil
}

// Dropped returns the number of writes dropped because the buffer was
// full.
func (a *AsyncWriter) Dropped() uint64 {
	return a.dropped.Load()
}

// Flush blocks until every write queued before this call has been
// written to the underlying writer. Concurrent writes that race with
// Flush make no guarantee. Safe to call from any goroutine.
func (a *AsyncWriter) Flush() {
	if a.closed.Load() {
		return
	}
	done := make(chan struct{})
	select {
	case a.flushCh <- done:
		<-done
	case <-a.done:
	}
}

// Close stops accepting writes, drains queued lines to the underlying
// writer, and stops the drain goroutine. Safe to call multiple times.
func (a *AsyncWriter) Close() error {
	a.closeOnce.Do(func() {
		a.closed.Store(true)
		close(a.ch)
	})
	<-a.done
	return nil
}
