package periodic_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cego/go-lib/v2/periodic"
	"github.com/stretchr/testify/assert"
)

func TestRun_ExecutesImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var count atomic.Int32
	go periodic.Run(ctx, time.Hour, 0, func() {
		count.Add(1)
	})

	time.Sleep(50 * time.Millisecond)
	cancel()
	assert.Equal(t, int32(1), count.Load())
}

func TestRun_ExecutesPeriodically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var count atomic.Int32
	go periodic.Run(ctx, 50*time.Millisecond, 0, func() {
		count.Add(1)
	})

	time.Sleep(200 * time.Millisecond)
	cancel()
	assert.GreaterOrEqual(t, count.Load(), int32(3))
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		periodic.Run(ctx, 50*time.Millisecond, 0, func() {})
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

func TestRun_AppliesJitter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var count atomic.Int32
	go periodic.Run(ctx, time.Hour, 200*time.Millisecond, func() {
		count.Add(1)
	})

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), count.Load())

	time.Sleep(200 * time.Millisecond)
	cancel()
	assert.Equal(t, int32(1), count.Load())
}
