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

	"github.com/Fheyalabs/ares-core/examples/ride_share"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	return p
}

func startTestRideShareService(t *testing.T) (string, *phase.SessionRunner, func()) {
	t.Helper()
	r, err := rideshare.Pipeline()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	inner := transport.NewManualAdminTrigger(r, nil, "ride.invitation")
	tr := &rideShareTrigger{
		inner:     inner,
		cryptoCtx: map[string]any{"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40},
	}
	port := freePort(t)
	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "rideshare-session-service",
		AllowDevBypass: true,
		Runner:         r,
		Trigger:        tr,
		InviteType:     "ride.invitation",
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	inner.Hub = svc.Hub()

	ctx, cancel := context.WithCancel(context.Background())
	go svc.Run(ctx)
	base := "http://127.0.0.1:" + port
	waitForHTTP(t, base+"/admin/health", 2*time.Second)
	return base, r, cancel
}

func TestRideShareService_AssignsRolesByOrder(t *testing.T) {
	base, runner, stop := startTestRideShareService(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "ride-1",
		"participants": []string{"rider-A", "driver-1", "driver-2", "driver-3"},
	})
	resp, err := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	s, _ := runner.CurrentState("ride-1")
	// rideShareTrigger's AdvanceToState(StateKeygen) runs after
	// inner.Start, so the session sits at StateKeygen ready to
	// receive ride.keygen.share messages.
	if s != rideshare.StateKeygen {
		t.Errorf("state = %q, want %q", s, rideshare.StateKeygen)
	}
}

func TestRideShareService_RejectsTooFewParticipants(t *testing.T) {
	base, _, stop := startTestRideShareService(t)
	defer stop()

	body, _ := json.Marshal(map[string]any{
		"session_id":   "ride-too-small",
		"participants": []string{"rider-only"},
	})
	resp, err := http.Post(base+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestRideShareService_DefaultRolesAssignsRiderAndDrivers(t *testing.T) {
	roles := defaultRoles([]string{"r", "d1", "d2"})
	if roles["r"] != "rider" {
		t.Errorf("roles[r] = %q, want rider", roles["r"])
	}
	if roles["d1"] != "driver" || roles["d2"] != "driver" {
		t.Errorf("drivers misassigned: %+v", roles)
	}
}

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
