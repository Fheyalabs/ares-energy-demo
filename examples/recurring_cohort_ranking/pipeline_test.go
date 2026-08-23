// SPDX-License-Identifier: Apache-2.0

package cohort

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestCohortFormation_BeginSession_InitialState verifies the
// formation runner starts in COHORT_FORMING.
func TestCohortFormation_BeginSession_InitialState(t *testing.T) {
	r, err := FormationPipeline()
	if err != nil {
		t.Fatalf("FormationPipeline: %v", err)
	}
	ctx, err := r.BeginSession("cohort-1", "cohort-1")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if ctx.CohortID != "cohort-1" {
		t.Errorf("CohortID = %q, want cohort-1", ctx.CohortID)
	}
	s, ok := r.CurrentState("cohort-1")
	if !ok || s != StateCohortForming {
		t.Errorf("CurrentState = %q,%v want %q,true", s, ok, StateCohortForming)
	}
}

// TestCohortFormation_LifetimesArePerCohort: both formation
// phases declare per-cohort lifetime so their outputs persist
// across many sessions.
func TestCohortFormation_LifetimesArePerCohort(t *testing.T) {
	if NewPhaseCohortForm().Lifetime() != phase.LifetimePerCohort {
		t.Errorf("PhaseCohortForm.Lifetime = %q, want per-cohort",
			NewPhaseCohortForm().Lifetime())
	}
	if NewPhaseCohortKeygen().Lifetime() != phase.LifetimePerCohort {
		t.Errorf("PhaseCohortKeygen.Lifetime = %q, want per-cohort",
			NewPhaseCohortKeygen().Lifetime())
	}
}

// TestCohortFormation_TerminalExitStateNotClaimed: the formation
// runner's last phase exits to COHORT_SEALED, which no later phase
// claims. AdvanceToState toward COHORT_SEALED therefore drives
// off the end and returns an error — documenting that callers
// should EndSession after keygen completes and switch to the
// weekly runner.
func TestCohortFormation_TerminalExitStateNotClaimed(t *testing.T) {
	r, err := FormationPipeline()
	if err != nil {
		t.Fatalf("FormationPipeline: %v", err)
	}
	if _, err := r.BeginSession("term", "cohort-X"); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	err = r.AdvanceToState("term", StateCohortSealed)
	if err == nil {
		t.Fatalf("expected AdvanceToState(COHORT_SEALED) to fail — no phase claims the terminal state")
	}
}

// TestWeeklyRankingSession_NotComposableStandalone is a regression
// guard pinning the contract that the weekly runner cannot be
// constructed by itself: its PreSharedKeyLookup phase requires
// CollectivePK/SecretShares/EvalKeys which no preceding phase
// in the weekly pipeline alone provides.
func TestWeeklyRankingSession_NotComposableStandalone(t *testing.T) {
	if _, err := WeeklyPipeline(); err == nil {
		t.Fatalf("expected WeeklyPipeline to be rejected without a preceding key provider")
	}
}

// TestPreSharedKeyLookup_EnterFailsWhenKeysMissing: at runtime the
// lookup phase verifies the cohort key bundle is in the
// SessionContext. With an empty context, Enter must return a
// MissingContextError.
func TestPreSharedKeyLookup_EnterFailsWhenKeysMissing(t *testing.T) {
	p := NewPhasePreSharedKeyLookup()
	ctx := phase.NewSessionContext("s1")
	err := p.Enter(ctx)
	if err == nil {
		t.Fatalf("expected Enter to fail on empty context")
	}
	var mce *phase.MissingContextError
	if !errors.As(err, &mce) {
		t.Errorf("expected MissingContextError, got %T: %v", err, err)
	}
	if mce.Phase != "ranking-key-lookup" {
		t.Errorf("MissingContextError.Phase = %q, want ranking-key-lookup", mce.Phase)
	}
}

// TestPreSharedKeyLookup_EnterFailsWhenAnyKeyMissing: pin the
// per-key error reporting. Seed two of the three keys; the third
// must be the one reported.
func TestPreSharedKeyLookup_EnterFailsWhenAnyKeyMissing(t *testing.T) {
	cases := []struct {
		name   string
		seed   []string
		expect string
	}{
		{"no PK", []string{CtxSecretShares, CtxEvalKeys}, CtxCollectivePK},
		{"no shares", []string{CtxCollectivePK, CtxEvalKeys}, CtxSecretShares},
		{"no evalkeys", []string{CtxCollectivePK, CtxSecretShares}, CtxEvalKeys},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := phase.NewSessionContext("s")
			for _, k := range c.seed {
				ctx.Set(k, []byte{0xAA})
			}
			err := NewPhasePreSharedKeyLookup().Enter(ctx)
			if err == nil {
				t.Fatalf("expected Enter to fail when %q is absent", c.expect)
			}
			var mce *phase.MissingContextError
			if !errors.As(err, &mce) {
				t.Fatalf("expected MissingContextError, got %T", err)
			}
			if mce.Key != c.expect {
				t.Errorf("missing key = %q, want %q", mce.Key, c.expect)
			}
		})
	}
}

// TestPreSharedKeyLookup_EnterSucceedsWhenSeeded: with all three
// keys seeded into the SessionContext, Enter returns nil and
// CheckComplete is immediately true (per-session cost is zero).
func TestPreSharedKeyLookup_EnterSucceedsWhenSeeded(t *testing.T) {
	p := NewPhasePreSharedKeyLookup()
	ctx := phase.NewSessionContext("s")
	ctx.Set(CtxCollectivePK, []byte{0x01})
	ctx.Set(CtxSecretShares, map[string][]byte{"x": {0x02}})
	ctx.Set(CtxEvalKeys, []byte{0x03})

	if err := p.Enter(ctx); err != nil {
		t.Fatalf("Enter: %v", err)
	}
	if !p.CheckComplete(ctx) {
		t.Errorf("CheckComplete should be true immediately")
	}
}

// TestBridgedPipeline_AdvancesEndToEnd drives the combined
// formation+weekly pipeline (with the cohort→ranking bridge) all
// the way through to the terminal RANKING_SETTLED state via
// AdvanceToState. This is the closest the framework gets to an
// end-to-end runner walk for the cohort-amortized fast path.
func TestBridgedPipeline_AdvancesEndToEnd(t *testing.T) {
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
		t.Fatalf("bridged pipeline: %v", err)
	}
	ctx, err := r.BeginSession("blend", "cohort-Z")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	// PreSharedKeyLookup checks runtime ctx — seed the keys before
	// the runner walks into RANKING_LOCKED.
	ctx.Set(CtxCollectivePK, []byte{0x01})
	ctx.Set(CtxSecretShares, map[string][]byte{"a": {0x02}})
	ctx.Set(CtxEvalKeys, []byte{0x03})

	targets := []phase.SessionState{
		StateCohortKeygen,
		StateRankingInviting,
		StateRankingLocked,
		StateRankingBidding,
		StateRankingScoring,
		StateRankingDecrypt,
		StateRankingSettled,
	}
	for _, target := range targets {
		if err := r.AdvanceToState("blend", target); err != nil {
			t.Fatalf("AdvanceToState(%q): %v", target, err)
		}
		got, _ := r.CurrentState("blend")
		if got != target {
			t.Errorf("after AdvanceToState(%q): CurrentState = %q",
				target, got)
		}
	}
}

// TestHandleMessage_RatingMessageRoutedToSubmitRating: the runner
// at RANKING_BIDDING accepts "ranking.rating" — verified by
// driving the bridged pipeline forward, seeding ctx, and sending
// the message.
func TestHandleMessage_RatingMessageRoutedToSubmitRating(t *testing.T) {
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
		t.Fatalf("bridged pipeline: %v", err)
	}
	ctx, err := r.BeginSession("rt", "cohort-Z")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	ctx.Set(CtxCollectivePK, []byte{0x01})
	ctx.Set(CtxSecretShares, map[string][]byte{"a": {0x02}})
	ctx.Set(CtxEvalKeys, []byte{0x03})

	if err := r.AdvanceToState("rt", StateRankingBidding); err != nil {
		t.Fatalf("AdvanceToState(RANKING_BIDDING): %v", err)
	}
	transitioned, err := r.HandleMessage("rt", "ranking.rating", "p1", nil)
	if err != nil {
		t.Fatalf("HandleMessage(ranking.rating): %v", err)
	}
	if transitioned {
		t.Errorf("expected transitioned=false (SubmitRating CheckComplete is false)")
	}
}

// TestPhaseConsumedMessageTypes_Coverage pins the message routing
// for the weekly pipeline.
func TestPhaseConsumedMessageTypes_Coverage(t *testing.T) {
	owner := map[string]string{}
	for _, p := range []phase.Phase{
		NewPhaseCohortKeygen(),
		NewPhaseSubmitRating(),
		NewPhaseThresholdDecrypt(),
	} {
		for _, t := range p.ConsumedMessageTypes() {
			owner[t] = p.Name()
		}
	}
	want := map[string]string{
		"cohort.keygen.share":     "cohort-keygen",
		"ranking.rating":          "ranking-submit-rating",
		"ranking.decrypt.partial": "ranking-threshold-decrypt",
	}
	for msg, name := range want {
		if owner[msg] != name {
			t.Errorf("message %q owner = %q, want %q", msg, owner[msg], name)
		}
	}
}

// TestSettleRankingIsTerminal: the last weekly phase exits to
// StateNone, signaling end-of-pipeline.
func TestSettleRankingIsTerminal(t *testing.T) {
	if NewPhaseSettleRanking().ExitState() != phase.StateNone {
		t.Errorf("SettleRanking.ExitState = %q, want StateNone",
			NewPhaseSettleRanking().ExitState())
	}
}

// TestPreSharedKeyLookupLifetime: the lookup phase is per-cohort —
// it consumes the cohort-lifetime keys, even though the
// surrounding weekly session is per-session.
func TestPreSharedKeyLookupLifetime(t *testing.T) {
	if NewPhasePreSharedKeyLookup().Lifetime() != phase.LifetimePerCohort {
		t.Errorf("PhasePreSharedKeyLookup.Lifetime = %q, want per-cohort",
			NewPhasePreSharedKeyLookup().Lifetime())
	}
}

// TestPhaseCohortKeygenContractDepth pins the cohort-keygen
// crypto contract at depth=10. ArgmaxScoring requires depth_min=8,
// which the bridged-pipeline composition validates.
func TestPhaseCohortKeygenContractDepth(t *testing.T) {
	got := NewPhaseCohortKeygen().Provides()[CtxCryptoContract]
	if got.Constraints["depth"] != 10 {
		t.Errorf("CohortKeygen Provides depth = %v, want 10",
			got.Constraints["depth"])
	}
}
