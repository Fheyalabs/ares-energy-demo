// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"sync"
	"time"
)

// rateLimiter is a per-connection token bucket. Tokens refill at
// refillRate per second up to capacity; each accepted inbound frame
// consumes one token. When the bucket is empty the frame is dropped.
//
// A nil rateLimiter is a valid value that admits every frame, so
// callers can wire it unconditionally and treat "disabled" as the
// nil case.
type rateLimiter struct {
	mu         sync.Mutex
	capacity   float64
	refillRate float64
	tokens     float64
	lastTick   time.Time
}

// newRateLimiter returns a token bucket pre-filled to capacity. If
// rate or burst is zero or negative, returns nil — the caller treats
// this as "rate limiting disabled" and skips the check entirely.
func newRateLimiter(rate, burst float64, now time.Time) *rateLimiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return &rateLimiter{
		capacity:   burst,
		refillRate: rate,
		tokens:     burst,
		lastTick:   now,
	}
}

// Allow returns true if a token is available and consumes one, false
// otherwise. Refill is computed on every call from the elapsed time
// since the last call, so callers don't need to drive a ticker.
//
// Allow on a nil receiver returns true unconditionally.
func (rl *rateLimiter) Allow(now time.Time) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if elapsed := now.Sub(rl.lastTick).Seconds(); elapsed > 0 {
		rl.tokens += elapsed * rl.refillRate
		if rl.tokens > rl.capacity {
			rl.tokens = rl.capacity
		}
		rl.lastTick = now
	}
	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}
