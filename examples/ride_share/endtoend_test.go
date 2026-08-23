// SPDX-License-Identifier: Apache-2.0

package rideshare

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestEndToEnd_HandleMessageWalksThePipeline drives the ride-share
// runner through every state via HandleMessage. With Phase 4a
// accumulator wiring, each N-of-N submission round (keygen, bid,
// decrypt-partial) transitions on the last participant's message;
// pure-compute phases (Invite, Score, Settle) auto-advance through
// the runner's cascade.
func TestEndToEnd_HandleMessageWalksThePipeline(t *testing.T) {
	runner, err := Pipeline()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	const sessionID = "ride-e2e"
	participants := []string{"rider", "driver-1", "driver-2"}

	ctx, err := runner.BeginSession(sessionID, "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	ctx.Set(CtxParticipants, participants)
	ctx.Set(CtxRoles, map[string]string{
		"rider": "rider", "driver-1": "driver", "driver-2": "driver",
	})
	ctx.Set(CtxCryptoContract, map[string]any{"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40})

	if err := runner.AdvanceToState(sessionID, StateKeygen); err != nil {
		t.Fatalf("advance to KEYGEN: %v", err)
	}

	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "ride.keygen.share", p, []byte("s")); err != nil {
			t.Fatalf("keygen.share from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != StateSubmit {
		t.Fatalf("after keygen: %q want SUBMIT", s)
	}

	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "ride.bid", p, []byte("b")); err != nil {
			t.Fatalf("ride.bid from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != StateDecrypt {
		t.Fatalf("after bids+score: %q want DECRYPT", s)
	}

	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "ride.decrypt.partial", p, []byte("p")); err != nil {
			t.Fatalf("decrypt.partial from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != phase.StateNone {
		t.Fatalf("after decrypt+settle: %q want StateNone", s)
	}
	if !ctx.Has(CtxSettlement) {
		t.Errorf("PhaseSettle.Enter did not write CtxSettlement")
	}
}
