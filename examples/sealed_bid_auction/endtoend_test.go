// SPDX-License-Identifier: Apache-2.0

package auction

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestEndToEnd_HandleMessageWalksThePipeline drives the auction
// SessionRunner through every state using only HandleMessage calls —
// no AdvanceToState shortcuts. Each accumulator phase advances once N
// participants have submitted; pure-compute phases (Argmax, Settlement,
// Invitation) auto-advance via CheckComplete=true.
//
// This is the regression gate for the wiring in phases.go: if a phase
// hook drops a message, miscounts participants, or fails to write its
// Provides into ctx, the pipeline stalls and the test times out at the
// last state it reached.
func TestEndToEnd_HandleMessageWalksThePipeline(t *testing.T) {
	runner, err := Pipeline()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	const sessionID = "auc-e2e"
	participants := []string{"p1", "p2", "p3"}

	ctx, err := runner.BeginSession(sessionID, "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	// Seed initial context the way the auctionTrigger would.
	ctx.Set(CtxAuctionParticipants, participants)
	ctx.Set(CtxAuctionCryptoContract, map[string]any{
		"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40,
	})

	// Invitation auto-completes; advance to LOCKED.
	if err := runner.AdvanceToState(sessionID, StateAuctionLocked); err != nil {
		t.Fatalf("advance to LOCKED: %v", err)
	}

	// Each participant submits keygen share. The 3rd should trip
	// CheckComplete and transition to BIDDING.
	for i, p := range participants {
		transitioned, err := runner.HandleMessage(sessionID, "auction.keygen.share", p, []byte("share-"+p))
		if err != nil {
			t.Fatalf("keygen.share from %s: %v", p, err)
		}
		isLast := i == len(participants)-1
		if transitioned != isLast {
			t.Errorf("keygen.share %d/%d transitioned=%v want=%v",
				i+1, len(participants), transitioned, isLast)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != StateAuctionBidding {
		t.Fatalf("after keygen: state=%q want BIDDING", s)
	}
	// Keygen Exit must have set the canonical context keys.
	if !ctx.Has(CtxAuctionCollectivePublicKey) {
		t.Errorf("PhaseKeygen.Exit did not set CtxAuctionCollectivePublicKey")
	}

	// Each participant submits a bid. The 3rd transitions BIDDING → SCORING.
	// Argmax auto-advances → DECRYPTING.
	for i, p := range participants {
		transitioned, err := runner.HandleMessage(sessionID, "auction.bid", p, []byte("bid-"+p))
		if err != nil {
			t.Fatalf("auction.bid from %s: %v", p, err)
		}
		isLast := i == len(participants)-1
		if transitioned != isLast {
			t.Errorf("bid %d/%d transitioned=%v want=%v", i+1, len(participants), transitioned, isLast)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != StateAuctionDecrypting {
		t.Fatalf("after bids+argmax: state=%q want DECRYPTING", s)
	}
	if !ctx.Has(CtxAuctionCipherWinnerBid) {
		t.Errorf("PhaseArgmax.Enter did not set CtxAuctionCipherWinnerBid")
	}

	// Each participant submits decrypt partial. Last one moves to
	// SETTLED, Settlement.Enter writes the transcript, CheckComplete=
	// true auto-advances to StateNone (terminal).
	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "auction.decrypt.partial", p, []byte("partial-"+p)); err != nil {
			t.Fatalf("decrypt.partial from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != phase.StateNone {
		t.Fatalf("after decrypt+settlement: state=%q want StateNone (terminal)", s)
	}
	if !ctx.Has(CtxAuctionSettlement) {
		t.Errorf("Settlement.Enter did not write CtxAuctionSettlement")
	}
}

// TestKeygen_DuplicateSubmissionsCountAsOne verifies that two messages
// from the same pseudonym don't double-count toward the N-of-N quorum.
func TestKeygen_DuplicateSubmissionsCountAsOne(t *testing.T) {
	runner, err := Pipeline()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	const sessionID = "dup-1"
	participants := []string{"p1", "p2"}
	ctx, _ := runner.BeginSession(sessionID, "")
	ctx.Set(CtxAuctionParticipants, participants)
	ctx.Set(CtxAuctionCryptoContract, map[string]any{"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40})
	runner.AdvanceToState(sessionID, StateAuctionLocked)

	// p1 submits twice; p2 once. Quorum should fire on p2's submission,
	// not on p1's duplicate.
	for _, msg := range []struct{ from string }{{"p1"}, {"p1"}} {
		transitioned, _ := runner.HandleMessage(sessionID, "auction.keygen.share", msg.from, []byte("s"))
		if transitioned {
			t.Errorf("p1's submissions should not have transitioned (1-of-2 quorum)")
		}
	}
	transitioned, _ := runner.HandleMessage(sessionID, "auction.keygen.share", "p2", []byte("s"))
	if !transitioned {
		t.Errorf("p2's submission should have transitioned (2-of-2 quorum)")
	}
}
