// SPDX-License-Identifier: Apache-2.0

package cohort_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	cohort "github.com/Fheyalabs/ares-core/examples/recurring_cohort_ranking"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// The cohort example splits formation and weekly ranking into two
// runners. WeeklyPipelineWithLineage (like the existing
// WeeklyPipeline) is standalone-uncomposable because
// PhasePreSharedKeyLookup requires keys that the caller seeds before
// BeginSession; so we exercise the formation pipeline's
// tamper-detection here. The same lineage protections apply to the
// weekly pipeline when called through the production bridge pattern
// (see TestWeeklyRankingSession_WithCallerSeededContext in
// runner_test.go for the bridged-compose pattern).

func TestCohortFormation_TamperedKeygenShare_DetectedByLineage(t *testing.T) {
	orchestrator, _ := sign.NewEd25519Signer()
	participant, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: participant}

	formation, err := cohort.FormationPipelineWithLineage(store, orchestrator, peers)
	if err != nil {
		t.Fatalf("FormationPipelineWithLineage: %v", err)
	}

	// PhaseCohortForm provides CtxParticipants; we need to advance
	// past it to reach PhaseCohortKeygen. The form phase doesn't
	// consume messages so the runner cascades through it on
	// BeginSession context-set + AdvanceToState... actually,
	// PhaseCohortForm produces CtxParticipants in its Enter hook,
	// which means BeginSession runs Enter but doesn't cascade past
	// the first phase per the runner contract. We need to drive
	// past form before sending the keygen share.
	if _, err := formation.BeginSession("cohort-w22", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// The "cohort.keygen.share" message arrives at PhaseCohortKeygen;
	// PhaseCohortForm is no-message so the framework needs an external
	// nudge to advance. We use AdvanceToState to drive past form.
	if err := formation.AdvanceToState("cohort-w22", "COHORT_KEYGEN"); err != nil {
		// If AdvanceToState rejects (no such state), try the canonical
		// keygen state — exact constant may differ across versions.
		t.Logf("AdvanceToState COHORT_KEYGEN: %v (continuing; framework will validate state on message arrival)", err)
	}

	// Construct a signed keygen share.
	share := map[string]string{"share_ct": hex.EncodeToString([]byte("participant-keygen-share"))}
	payload, _ := json.Marshal(share)
	node, _ := lineage.Commit("cohort-w22", "cohort-keygen", "share-participant-1", payload, nil, participant)

	// Tamper attempt.
	tampered := []byte(`{"share_ct":"deadbeef"}`)
	_, err = formation.HandleLineageMessage("cohort-w22", "cohort.keygen.share", "p1", tampered, &node)
	if err == nil {
		t.Fatal("expected tamper rejection")
	}
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "PayloadHash" {
		t.Errorf("MismatchError.Field = %q, want %q", me.Field, "PayloadHash")
	}
}

func TestCohortFormation_LineageStoreIsShareable(t *testing.T) {
	// Confirm both formation and weekly constructors accept the
	// same Store — the caller is responsible for sharing it so
	// weekly parent refs can resolve back to formation-time
	// commits.
	signer, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	store := lineage.NewInMemoryStore()

	if _, err := cohort.FormationPipelineWithLineage(store, signer, peers); err != nil {
		t.Errorf("FormationPipelineWithLineage: %v", err)
	}

	// WeeklyPipelineWithLineage is standalone-uncomposable BY DESIGN
	// (same as WeeklyPipeline) — PhasePreSharedKeyLookup's Requires
	// keys are caller-seeded. Confirm the constructor at least
	// accepts the lineage options and surfaces the same composition
	// error pattern.
	_, err := cohort.WeeklyPipelineWithLineage(store, signer, peers)
	if err == nil {
		t.Error("WeeklyPipelineWithLineage should fail standalone (matches WeeklyPipeline behavior)")
	}
}
