// SPDX-License-Identifier: Apache-2.0

package cohort

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestCohortFormation_HandleMessageWalksThePipeline drives the
// formation runner through cohort-form → keygen → sealed via the
// accumulator path.
func TestCohortFormation_HandleMessageWalksThePipeline(t *testing.T) {
	runner, err := FormationPipeline()
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	const sessionID = "form-e2e"
	participants := []string{"m1", "m2", "m3"}

	ctx, err := runner.BeginSession(sessionID, sessionID)
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	ctx.Set(CtxParticipants, participants)

	if err := runner.AdvanceToState(sessionID, StateCohortKeygen); err != nil {
		t.Fatalf("advance to KEYGEN: %v", err)
	}
	// First N-1 shares accumulate without transitioning.
	for _, p := range participants[:len(participants)-1] {
		transitioned, err := runner.HandleMessage(sessionID, "cohort.keygen.share", p, []byte("s"))
		if err != nil {
			t.Fatalf("keygen.share from %s: %v", p, err)
		}
		if transitioned {
			t.Errorf("share from %s should not transition (not yet at quorum)", p)
		}
	}
	// The N-th share trips CheckComplete. PhaseCohortKeygen.Exit runs
	// (writing key-bundle context entries) but advance fails because
	// no phase claims COHORT_SEALED — the formation runner ends here
	// by design.  See TestCohortFormation_TerminalExitStateNotClaimed.
	_, err = runner.HandleMessage(sessionID, "cohort.keygen.share",
		participants[len(participants)-1], []byte("s"))
	if err == nil {
		t.Errorf("expected last share to surface the 'no phase claims COHORT_SEALED' error")
	}
	if !ctx.Has(CtxCollectivePK) {
		t.Errorf("PhaseCohortKeygen.Exit did not write CtxCollectivePK")
	}
	if !ctx.Has(CtxSecretShares) {
		t.Errorf("PhaseCohortKeygen.Exit did not write CtxSecretShares")
	}
}

// TestBridgedWeekly_HandleMessageWalksThePipeline runs the bridged
// formation + weekly pipeline end-to-end. After cohort keygen
// transitions to COHORT_SEALED, the bridge phase advances into
// RANKING_INVITING; participants then submit ratings and decrypt
// partials.
func TestBridgedWeekly_HandleMessageWalksThePipeline(t *testing.T) {
	r, err := phase.Compose(
		NewPhaseCohortForm(),
		NewPhaseCohortKeygen(),
		&cohortToRankingBridge{},
		NewPhaseRankingInvitation(),
		NewPhasePreSharedKeyLookup(),
		NewPhaseSubmitRating(),
		NewPhaseArgmaxScoring(),
		NewPhaseThresholdDecrypt(),
		NewPhaseSettleRanking(),
	)
	if err != nil {
		t.Fatalf("bridged: %v", err)
	}
	const sessionID = "blended"
	participants := []string{"m1", "m2", "m3"}

	ctx, err := r.BeginSession(sessionID, sessionID)
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	ctx.Set(CtxParticipants, participants)

	if err := r.AdvanceToState(sessionID, StateCohortKeygen); err != nil {
		t.Fatalf("advance to COHORT_KEYGEN: %v", err)
	}
	for _, p := range participants {
		if _, err := r.HandleMessage(sessionID, "cohort.keygen.share", p, []byte("s")); err != nil {
			t.Fatalf("keygen.share from %s: %v", p, err)
		}
	}
	// After cohort keygen, the runner cascades through the bridge
	// (no consumed types, CheckComplete=true) and through ranking
	// invitation (also pure-compute), landing at RANKING_LOCKED where
	// PreSharedKeyLookup awaits — and that phase's CheckComplete is
	// true on Enter, cascading to RANKING_BIDDING.
	if s, _ := r.CurrentState(sessionID); s != StateRankingBidding {
		t.Fatalf("after cohort keygen: %q want RANKING_BIDDING", s)
	}

	for _, p := range participants {
		if _, err := r.HandleMessage(sessionID, "ranking.rating", p, []byte("r")); err != nil {
			t.Fatalf("rating from %s: %v", p, err)
		}
	}
	// After ratings, cascade through Argmax → DECRYPT.
	if s, _ := r.CurrentState(sessionID); s != StateRankingDecrypt {
		t.Fatalf("after ratings: %q want RANKING_DECRYPT", s)
	}

	for _, p := range participants {
		if _, err := r.HandleMessage(sessionID, "ranking.decrypt.partial", p, []byte("p")); err != nil {
			t.Fatalf("decrypt.partial from %s: %v", p, err)
		}
	}
	if s, _ := r.CurrentState(sessionID); s != phase.StateNone {
		t.Fatalf("after decrypt+settle: %q want StateNone", s)
	}
	if !ctx.Has(CtxTranscript) {
		t.Errorf("PhaseSettleRanking.Enter did not write CtxTranscript")
	}
}
