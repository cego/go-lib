package logger_test

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/cego/go-lib/v2/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAsyncWriter(t *testing.T) {
	t.Run("forwards writes to underlying writer", func(t *testing.T) {
		var buf safeBuffer
		aw := logger.NewAsyncWriter(&buf, 16)

		n, err := aw.Write([]byte("hello\n"))
		require.NoError(t, err)
		assert.Equal(t, 6, n)

		require.NoError(t, aw.Close())
		assert.Equal(t, "hello\n", buf.String())
		assert.Equal(t, uint64(0), aw.Dropped())
	})

	t.Run("Close flushes queued writes", func(t *testing.T) {
		blocker := newBlockingWriter()
		aw := logger.NewAsyncWriter(blocker, 16)

		for i := range 5 {
			_, err := aw.Write([]byte{byte('a' + i)})
			require.NoError(t, err)
		}

		blocker.unblock()
		require.NoError(t, aw.Close())
		assert.Equal(t, "abcde", blocker.String())
	})

	t.Run("drops writes when buffer is full", func(t *testing.T) {
		blocker := newBlockingWriter()
		aw := logger.NewAsyncWriter(blocker, 2)

		// First write is consumed by the drain goroutine immediately
		// and blocks inside the underlying writer; the channel then
		// fills with two more before subsequent writes drop.
		_, _ = aw.Write([]byte("1"))
		blocker.waitForFirstWrite()
		_, _ = aw.Write([]byte("2"))
		_, _ = aw.Write([]byte("3"))
		_, _ = aw.Write([]byte("dropped-a"))
		_, _ = aw.Write([]byte("dropped-b"))

		assert.Equal(t, uint64(2), aw.Dropped())

		blocker.unblock()
		require.NoError(t, aw.Close())
	})

	t.Run("Write after Close returns ErrClosedPipe", func(t *testing.T) {
		var buf safeBuffer
		aw := logger.NewAsyncWriter(&buf, 4)
		require.NoError(t, aw.Close())

		_, err := aw.Write([]byte("nope"))
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	})

	t.Run("Flush drains pending writes without closing", func(t *testing.T) {
		var buf safeBuffer
		aw := logger.NewAsyncWriter(&buf, 16)

		for i := range 5 {
			_, err := aw.Write([]byte{byte('a' + i)})
			require.NoError(t, err)
		}

		aw.Flush()
		assert.Equal(t, "abcde", buf.String())

		_, err := aw.Write([]byte("f"))
		require.NoError(t, err)
		aw.Flush()
		assert.Equal(t, "abcdef", buf.String())

		require.NoError(t, aw.Close())
	})

	t.Run("Close is idempotent", func(t *testing.T) {
		var buf safeBuffer
		aw := logger.NewAsyncWriter(&buf, 4)
		require.NoError(t, aw.Close())
		require.NoError(t, aw.Close())
	})

	t.Run("copies caller buffer", func(t *testing.T) {
		blocker := newBlockingWriter()
		aw := logger.NewAsyncWriter(blocker, 4)

		p := []byte("first")
		_, _ = aw.Write(p)
		blocker.waitForFirstWrite()
		copy(p, "XXXXX")

		blocker.unblock()
		require.NoError(t, aw.Close())
		assert.Equal(t, "first", blocker.String())
	})
}

// safeBuffer is bytes.Buffer with a mutex so concurrent reads from the
// test goroutine and writes from the drain goroutine don't race.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// blockingWriter stalls the first Write until unblock() is called, so
// tests can deterministically fill the AsyncWriter's channel.
type blockingWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	gate    chan struct{}
	firstCh chan struct{}
	once    sync.Once
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		gate:    make(chan struct{}),
		firstCh: make(chan struct{}),
	}
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.firstCh)
		<-b.gate
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *blockingWriter) waitForFirstWrite() { <-b.firstCh }
func (b *blockingWriter) unblock()           { close(b.gate) }

func (b *blockingWriter) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
