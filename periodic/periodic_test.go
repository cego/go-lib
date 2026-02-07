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
	defer cancel()

	var count atomic.Int32
	periodic.Run(ctx, time.Hour, 0, func() {
		count.Add(1)
	})

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), count.Load())
}

func TestRun_ExecutesPeriodically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var count atomic.Int32
	periodic.Run(ctx, 50*time.Millisecond, 0, func() {
		count.Add(1)
	})

	time.Sleep(200 * time.Millisecond)
	assert.GreaterOrEqual(t, count.Load(), int32(3))
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var count atomic.Int32
	periodic.Run(ctx, 50*time.Millisecond, 0, func() {
		count.Add(1)
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	countAtCancel := count.Load()

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, countAtCancel, count.Load())
}

func TestRun_AppliesJitter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var count atomic.Int32
	periodic.Run(ctx, time.Hour, 200*time.Millisecond, func() {
		count.Add(1)
	})

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), count.Load())

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, int32(1), count.Load())
}

func TestRun_DoesNotBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	returned := make(chan struct{})
	go func() {
		periodic.Run(ctx, time.Hour, time.Hour, func() {})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Run blocked the caller")
	}
}
