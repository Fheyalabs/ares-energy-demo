// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRateLimiter_NilAlwaysAllows(t *testing.T) {
	var rl *rateLimiter
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if !rl.Allow(now) {
			t.Fatal("nil limiter must always allow")
		}
	}
}

func TestRateLimiter_DisabledOnZero(t *testing.T) {
	cases := []struct {
		name string
		rate float64
		burst float64
	}{
		{"rate=0 burst=10", 0, 10},
		{"rate=10 burst=0", 10, 0},
		{"both zero", 0, 0},
		{"negative rate", -1, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rl := newRateLimiter(tc.rate, tc.burst, time.Now()); rl != nil {
				t.Fatalf("expected nil limiter, got %+v", rl)
			}
		})
	}
}

func TestRateLimiter_BurstThenThrottle(t *testing.T) {
	// rate=10/s, burst=3 → first 3 frames pass without elapsed time;
	// the 4th drops because the bucket is empty.
	now := time.Unix(0, 0)
	rl := newRateLimiter(10, 3, now)
	if rl == nil {
		t.Fatal("expected non-nil limiter")
	}
	for i := 0; i < 3; i++ {
		if !rl.Allow(now) {
			t.Fatalf("frame %d should pass in burst", i)
		}
	}
	if rl.Allow(now) {
		t.Fatal("4th frame at t=0 should be dropped (bucket empty)")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	// rate=10/s → one token regenerates every 100ms. Start at empty,
	// advance 100ms, expect exactly one allow then a drop.
	start := time.Unix(0, 0)
	rl := newRateLimiter(10, 1, start)
	// Drain the initial burst.
	if !rl.Allow(start) {
		t.Fatal("initial token should pass")
	}
	if rl.Allow(start) {
		t.Fatal("second call at t=0 should drop")
	}
	// Advance 100ms → 1 token regenerated.
	tNow := start.Add(100 * time.Millisecond)
	if !rl.Allow(tNow) {
		t.Fatal("regenerated token should pass at t=100ms")
	}
	if rl.Allow(tNow) {
		t.Fatal("bucket should be empty again immediately after consuming")
	}
}

func TestRateLimiter_CapsAtCapacity(t *testing.T) {
	// rate=1/s, burst=2 → after 1 hour of inactivity the bucket should
	// still cap at 2 tokens, not accumulate 3600.
	start := time.Unix(0, 0)
	rl := newRateLimiter(1, 2, start)
	// Drain.
	_ = rl.Allow(start)
	_ = rl.Allow(start)
	// 1 hour later.
	future := start.Add(1 * time.Hour)
	allows := 0
	for i := 0; i < 10; i++ {
		if rl.Allow(future) {
			allows++
		}
	}
	if allows != 2 {
		t.Fatalf("capacity cap broken: got %d allows, want 2", allows)
	}
}

// fixedClock is a deterministic Clock for hub-level tests. The hub
// stamps timestamps and refills rate-limit buckets off of it.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestHub_RateLimitDropsExcessInboundFrames(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	// rate=10/s, burst=2 → the first 2 inbound frames at t=0 pass to
	// the message handler; the 3rd in the same instant is dropped.
	hub := NewHubWithOptions(clk, &AuthMiddleware{AllowDevBypass: true}, HubOptions{
		AllowAnyOrigin: true,
		InboundRate:    10,
		InboundBurst:   2,
	})

	var (
		mu   sync.Mutex
		seen []string
	)
	hub.SetMessageHandler(func(_ *Client, msg WSMessage) {
		mu.Lock()
		seen = append(seen, msg.Type)
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "alice", "")
	defer teardown()
	waitFor(t, func() bool { return hub.IsConnected("alice") }, 2*time.Second)

	send := func(typ string) {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if err := conn.WriteMessage(websocket.TextMessage,
			mustJSON(t, WSMessage{Type: typ})); err != nil {
			t.Fatalf("write %s: %v", typ, err)
		}
	}
	send("a")
	send("b")
	send("c")

	// Wait for the handler to drain 2 accepts; the 3rd should be
	// dropped and never arrive.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) >= 2
	}, 2*time.Second)

	// Give the readPump a moment to discard the 3rd frame.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 accepts, got %d: %v", len(got), got)
	}
	if got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected [a b], got %v", got)
	}
}

func TestHub_RateLimitDisabledByDefault(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	var n int
	var mu sync.Mutex
	hub.SetMessageHandler(func(_ *Client, _ WSMessage) {
		mu.Lock()
		n++
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "bob", "")
	defer teardown()
	waitFor(t, func() bool { return hub.IsConnected("bob") }, 2*time.Second)

	const N = 50
	for i := 0; i < N; i++ {
		if err := conn.WriteMessage(websocket.TextMessage,
			mustJSON(t, WSMessage{Type: "tick"})); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return n >= N
	}, 2*time.Second)
}

func mustJSON(t *testing.T, m WSMessage) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
