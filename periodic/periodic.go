package periodic

import (
	"context"
	"time"
)

// Run spawns a goroutine that executes fn immediately after the jitter delay,
// then repeats it at the given interval until ctx is cancelled.
func Run(ctx context.Context, interval time.Duration, jitter time.Duration, fn func()) {
	go func() {
		if jitter > 0 {
			jitterTimer := time.NewTimer(jitter)
			defer jitterTimer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-jitterTimer.C:
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		fn()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fn()
			}
		}
	}()
}
