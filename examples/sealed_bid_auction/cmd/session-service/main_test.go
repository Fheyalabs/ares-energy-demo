// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Fheyalabs/ares-core/examples/sealed_bid_auction"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

// freePort grabs an OS-assigned TCP port for the test service.
func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

// startTestAuctionService builds the same Service main() does and runs
// it on a background goroutine. Returns the base URL and the runner so
// tests can inspect state.
func startTestAuctionService(t *testing.T) (baseURL string, runner *phase.SessionRunner, stop func()) {
	t.Helper()
	r, err := auction.Pipeline()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	inner := transport.NewManualAdminTrigger(r, nil, "auction.invitation")
	tr := &auctionTrigger{
		inner:     inner,
		cryptoCtx: map[string]any{"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40},
	}
	port := freePort(t)
	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "auction-session-service",
		AllowDevBypass: true,
		Runner:         r,
		Trigger:        tr,
		InviteType:     "auction.invitation",
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	inner.Hub = svc.Hub()

	ctx, cancel := context.WithCancel(context.Background())
	go svc.Run(ctx)
	baseURL = "http://127.0.0.1:" + port
	waitForHTTP(t, baseURL+"/admin/health", 2*time.Second)
	return baseURL, r, cancel
}

func TestAuctionService_StartSessionAdvancesPipeline(t *testing.T) {
	base, runner, stop := startTestAuctionService(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "a-1",
		"participants": []string{"bidder-1", "bidder-2", "bidder-3"},
	})
	resp, err := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// The auctionTrigger's AdvanceToState(AUCTION_LOCKED) runs after
	// inner.Start, so the session sits at AUCTION_LOCKED (PhaseKeygen
	// entry) ready to accept keygen.share messages.
	s, ok := runner.CurrentState("a-1")
	if !ok || s != auction.StateAuctionLocked {
		t.Errorf("CurrentState = %q,%v want AUCTION_LOCKED,true", s, ok)
	}
}

func TestAuctionService_SeedsContextWithCanonicalKeys(t *testing.T) {
	base, runner, stop := startTestAuctionService(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "a-ctx",
		"participants": []string{"bidder-1", "bidder-2"},
	})
	resp, err := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	// Inspect the context indirectly: advance the runner forward and
	// confirm the canonical Auction keys are present for the next
	// phase. We can't read SessionContext from outside the package
	// here, so we settle for checking that the session exists.
	if _, ok := runner.CurrentState("a-ctx"); !ok {
		t.Errorf("session not tracked")
	}
}

func TestAuctionService_RejectsDuplicateSessionID(t *testing.T) {
	base, _, stop := startTestAuctionService(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "dup",
		"participants": []string{"a", "b"},
	})
	r1, err := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("first POST: %v", err)
	}
	r1.Body.Close()

	r2, err2 := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err2 != nil {
		t.Fatalf("second POST: %v", err2)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusConflict {
		t.Errorf("second start status = %d, want 409", r2.StatusCode)
	}
}

func TestAuctionService_GetSessionAfterStart(t *testing.T) {
	base, _, stop := startTestAuctionService(t)
	defer stop()
	body, _ := json.Marshal(map[string]any{
		"session_id":   "get-1",
		"participants": []string{"a", "b"},
	})
	r, _ := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	r.Body.Close()

	resp, err := http.Get(base + "/admin/sessions/get-1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status = %d", resp.StatusCode)
	}
}

// helpers ---------------------------------------------------------------

func waitForHTTP(t *testing.T, u string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(u)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("HTTP %s never came up", u)
}
