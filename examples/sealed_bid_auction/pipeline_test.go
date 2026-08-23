// SPDX-License-Identifier: Apache-2.0

package auction

import (
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestBeginSession_InitialState: the auction session starts in
// AUCTION_INVITING with the correct SessionContext identity.
func TestBeginSession_InitialState(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	ctx, err := r.BeginSession("auction-7", "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if ctx.SessionID != "auction-7" {
		t.Errorf("ctx.SessionID = %q, want auction-7", ctx.SessionID)
	}
	s, ok := r.CurrentState("auction-7")
	// BeginSession does NOT cascade past the initial phase; the
	// trigger advances explicitly after seeding context.
	if !ok || s != StateAuctionInviting {
		t.Errorf("CurrentState = %q,%v, want %q,true", s, ok, StateAuctionInviting)
	}
}

// TestAdvanceToState_WalksFullPipeline: drive a session through
// every state with stub hooks; AdvanceToState should reach each
// one in order.
func TestAdvanceToState_WalksFullPipeline(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("walk", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	targets := []phase.SessionState{
		StateAuctionLocked,
		StateAuctionBidding,
		StateAuctionScoring,
		StateAuctionDecrypting,
		StateAuctionSettled,
	}
	for _, target := range targets {
		if err := r.AdvanceToState("walk", target); err != nil {
			t.Fatalf("AdvanceToState(%q): %v", target, err)
		}
		got, _ := r.CurrentState("walk")
		if got != target {
			t.Errorf("after AdvanceToState(%q): CurrentState = %q",
				target, got)
		}
	}
}

// TestHandleMessage_KeygenAcceptsShare: at AUCTION_LOCKED, the
// PhaseKeygen consumes "auction.keygen.share". The phase's
// CheckComplete is false (it accumulates), so the call returns
// (false, nil) and the session stays in the same state.
func TestHandleMessage_KeygenAcceptsShare(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("k", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if err := r.AdvanceToState("k", StateAuctionLocked); err != nil {
		t.Fatalf("AdvanceToState(Locked): %v", err)
	}
	transitioned, err := r.HandleMessage("k", "auction.keygen.share", "bidder-1", nil)
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if transitioned {
		t.Errorf("expected transitioned=false (PhaseKeygen CheckComplete is false)")
	}
	got, _ := r.CurrentState("k")
	if got != StateAuctionLocked {
		t.Errorf("CurrentState = %q, want %q", got, StateAuctionLocked)
	}
}

// TestHandleMessage_RejectsAuctionBidInInviting: at AUCTION_INVITING
// (PhaseInvitation, no consumed messages), every msgType must be
// rejected — including the well-formed auction.bid that's valid in
// a later state.
func TestHandleMessage_RejectsAuctionBidInInviting(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("rej", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	_, err = r.HandleMessage("rej", "auction.bid", "bidder-1", nil)
	if err == nil {
		t.Fatalf("expected auction.bid to be rejected in AUCTION_INVITING")
	}
	if !strings.Contains(err.Error(), "auction-invitation") {
		t.Errorf("error %q does not name current phase", err.Error())
	}
}

// TestHandleMessage_UntrackedSession: HandleMessage on an unknown
// session returns an error.
func TestHandleMessage_UntrackedSession(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.HandleMessage("ghost", "auction.bid", "x", nil); err == nil {
		t.Fatalf("expected HandleMessage on untracked session to fail")
	}
}

// TestEndSession releases tracker state.
func TestEndSession(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	if _, err := r.BeginSession("e", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	r.EndSession("e")
	if _, ok := r.CurrentState("e"); ok {
		t.Errorf("CurrentState should be untracked after EndSession")
	}
}

// TestConsumedMessageTypes_Coverage pins the message routing for
// the auction: keygen.share, bid, and decrypt.partial each map to
// exactly one phase.
func TestConsumedMessageTypes_Coverage(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	owner := map[string]string{}
	for _, p := range r.Phases() {
		for _, t := range p.ConsumedMessageTypes() {
			if existing, dup := owner[t]; dup && existing != p.Name() {
				panic("auction phases " + existing + " and " + p.Name() +
					" both claim message type " + t)
			}
			owner[t] = p.Name()
		}
	}
	want := map[string]string{
		"auction.keygen.share":    "auction-keygen",
		"auction.bid":             "auction-scalar-bid",
		"auction.decrypt.partial": "auction-threshold-decrypt",
	}
	for msg, phaseName := range want {
		if owner[msg] != phaseName {
			t.Errorf("message %q owned by %q, want %q", msg, owner[msg], phaseName)
		}
	}
}

// TestPhaseLifetimes confirms the auction is fully per-session
// (no cohort or persistent state).
func TestPhaseLifetimes(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	for _, p := range r.Phases() {
		if p.Lifetime() != phase.LifetimePerSession {
			t.Errorf("phase %q Lifetime=%q, want per-session",
				p.Name(), p.Lifetime())
		}
		if p.RunsAt() != phase.RunsAtInline {
			t.Errorf("phase %q RunsAt=%q, want inline",
				p.Name(), p.RunsAt())
		}
	}
}

// TestSettlementIsTerminal: PhaseSettlement.ExitState is StateNone,
// signaling end-of-pipeline.
func TestSettlementIsTerminal(t *testing.T) {
	if NewPhaseSettlement().ExitState() != phase.StateNone {
		t.Errorf("Settlement.ExitState = %q, want StateNone",
			NewPhaseSettlement().ExitState())
	}
}

// TestInvitationProvidesDepth10 pins the auction's CKKS depth at
// 10 — the headline performance claim of "shallower than Fheya's
// depth=30 cosine chain". Argmax requires depth_min=8 (validated
// at runner construction).
func TestInvitationProvidesDepth10(t *testing.T) {
	got := NewPhaseInvitation().Provides()[CtxAuctionCryptoContract]
	if got.Constraints["depth"] != 10 {
		t.Errorf("Invitation Provides depth = %v, want 10",
			got.Constraints["depth"])
	}
}

// TestMissingProducerRejected: drop PhaseScalarBid and the
// downstream Argmax requirement on CtxAuctionBids is unsatisfied.
func TestMissingProducerRejected(t *testing.T) {
	_, err := phase.Compose(
		NewPhaseInvitation(),
		NewPhaseKeygen(),
		// ScalarBid removed.
		NewPhaseArgmax(),
		NewPhaseDecrypt(),
		NewPhaseSettlement(),
	)
	if err == nil {
		t.Fatalf("expected runner to reject pipeline missing PhaseScalarBid")
	}
}

// TestDisconnectedPipelineRejected: swap two phases so their
// state chain breaks.
func TestDisconnectedPipelineRejected(t *testing.T) {
	_, err := phase.Compose(
		NewPhaseInvitation(),
		NewPhaseScalarBid(), // EntryState=BIDDING, but Invitation exits to LOCKED
		NewPhaseKeygen(),
		NewPhaseArgmax(),
		NewPhaseDecrypt(),
		NewPhaseSettlement(),
	)
	if err == nil {
		t.Fatalf("expected disconnected pipeline to be rejected")
	}
}

// TestPhaseForState_AllInlineStatesClaimed verifies every declared
// state has an owning phase, and the terminal sentinel does not.
func TestPhaseForState_AllInlineStatesClaimed(t *testing.T) {
	r, err := Pipeline()
	if err != nil {
		t.Fatalf("Pipeline: %v", err)
	}
	for _, s := range []phase.SessionState{
		StateAuctionInviting,
		StateAuctionLocked,
		StateAuctionBidding,
		StateAuctionScoring,
		StateAuctionDecrypting,
		StateAuctionSettled,
	} {
		if _, ok := r.PhaseForState(s); !ok {
			t.Errorf("PhaseForState(%q) returned no phase", s)
		}
	}
	if _, ok := r.PhaseForState(phase.StateNone); ok {
		t.Errorf("PhaseForState(StateNone) should be false")
	}
}
