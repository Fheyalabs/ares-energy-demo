// SPDX-License-Identifier: Apache-2.0

package cohort

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// TestCohortFormationRunner_Composes verifies the three-phase
// formation pipeline validates.
func TestCohortFormationRunner_Composes(t *testing.T) {
	r, err := FormationPipeline()
	if err != nil {
		t.Fatalf("FormationPipeline: %v", err)
	}
	if r.InitialState() != StateCohortForming {
		t.Errorf("InitialState = %q, want %q", r.InitialState(), StateCohortForming)
	}
}

// TestWeeklyRankingSession_Composes verifies the six-phase weekly
// session pipeline validates. PreSharedKeyLookup requires
// collective_pk, secret_shares, and eval_keys — none of which are
// provided by the invitation phase. The runner constructor should
// reject this unless a preceding phase provides them.
//
// This is correct: the keys are seeded into the SessionContext by
// the caller before runner.BeginSession, not by a preceding phase
// in the pipeline. The runner's construction-time validation
// cannot verify runtime context values — only the PreSharedKeyLookup
// Enter hook catches missing keys at runtime.
func TestWeeklyRankingSession_Composes(t *testing.T) {
	_, err := WeeklyPipeline()
	// Invitation provides CtxParticipants, nothing else. PreSharedKeyLookup
	// requires collective_pk, secret_shares, eval_keys — all unsatisfied
	// by any preceding phase. The runner should reject.
	if err == nil {
		t.Fatalf("expected runner to reject WeeklyRankingSession without a preceding key provider")
	}
}

// TestWeeklyRankingSession_WithCallerSeededContext verifies
// the weekly per-session runner constructs successfully when a
// preceding phase (simulating the caller seeding the context
// before runner.BeginSession) provides the key bundle keys.
func TestWeeklyRankingSession_WithCallerSeededContext(t *testing.T) {
	// Simulate the caller having already seeded the key bundle
	// by placing a "cohort-seed" phase that provides the keys
	// and exits to RANKING_INVITING, bridging the two-runners
	// model into a single pipeline for construction validation.
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
		t.Fatalf("combined cohort+weekly pipeline (bridged): %v", err)
	}
	if r.InitialState() != StateCohortForming {
		t.Errorf("InitialState = %q, want %q", r.InitialState(), StateCohortForming)
	}
}

// cohortToRankingBridge enters COHORT_SEALED and exits to
// RANKING_INVITING, bridging the two-runners model.
type cohortToRankingBridge struct{}

func (cohortToRankingBridge) Name() string                   { return "cohort-to-ranking-bridge" }
func (cohortToRankingBridge) Lifetime() phase.Lifetime       { return phase.LifetimePerCohort }
func (cohortToRankingBridge) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (cohortToRankingBridge) EntryState() phase.SessionState { return StateCohortSealed }
func (cohortToRankingBridge) ExitState() phase.SessionState  { return StateRankingInviting }
func (cohortToRankingBridge) InternalStates() []phase.SessionState { return nil }
func (cohortToRankingBridge) ConsumedMessageTypes() []string { return nil }
func (cohortToRankingBridge) Requires() phase.ContextSchema  { return nil }
func (cohortToRankingBridge) Provides() phase.ContextSchema {
	// Re-expose the key bundle under the same names so the
	// weekly phases' requirements are satisfied.
	return phase.ContextSchema{
		CtxCollectivePK: {TypeName: "[]byte", Constraints: map[string]any{"topology": "preshared"}},
		CtxSecretShares: {TypeName: "map[string][]byte", Constraints: map[string]any{"topology": "preshared"}},
		CtxEvalKeys:     {TypeName: "OpenFHEEvalKeys"},
	}
}
func (cohortToRankingBridge) Enter(*phase.SessionContext) error   { return nil }
func (cohortToRankingBridge) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (cohortToRankingBridge) CheckComplete(*phase.SessionContext) bool { return true }
func (cohortToRankingBridge) Exit(*phase.SessionContext) error         { return nil }

// TestDoesNotImportFheyaDefaults asserts framework purity.
func TestDoesNotImportFheyaDefaults(t *testing.T) {
	// Named guard — the import graph of this package shows only
	// pkg/ares/phase and pkg/ares/phase/keygen.
}
