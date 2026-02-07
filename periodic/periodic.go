package periodic

import (
	"context"
	"time"
)

// Run executes fn immediately, then repeats it at the given interval until ctx is cancelled.
// An initial jitter delay is applied before the first execution.
func Run(ctx context.Context, interval time.Duration, jitter time.Duration, fn func()) {
	time.Sleep(jitter)

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
}
