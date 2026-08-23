// SPDX-License-Identifier: Apache-2.0

package bounded_admission_test

import (
	"encoding/json"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/examples/bounded_admission"
)

// TestAdmissionPipeline_StubWalkToSettled verifies that the bounded-admission
// pipeline reaches StateSettled in stub mode (no real FHE) when the correct
// messages are supplied. The boundcheck phase is constructed via NewPhase
// (nil handle/fuse), so Enter and Exit are no-ops.
func TestAdmissionPipeline_StubWalkToSettled(t *testing.T) {
	runner, err := bounded_admission.PipelineWithCrypto()
	if err != nil {
		t.Fatalf("PipelineWithCrypto: %v", err)
	}

	const sessionID = "stub-admission-001"
	ctx, err := runner.BeginSession(sessionID, "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// Seed context with participants and stub crypto keys.
	participants := []string{"p0", "p1"}
	ctx.Set(defaults.CtxParticipants, participants)
	ctx.Set(boundcheck.CtxInputDim, 8)
	ctx.Set(boundcheck.CtxEvalKeyBundle, []byte("stub-ek"))
	ctx.Set(boundcheck.CtxJointPublicKey, []byte("stub-pk"))

	// Walk through PhaseInvitation (StateInviting -> StateLocked) and
	// PhaseKeygen (StateLocked -> StateSubmitting).
	if err := runner.AdvanceToState(sessionID, bounded_admission.StateSubmitting); err != nil {
		t.Fatalf("AdvanceToState(StateSubmitting): %v", err)
	}

	// Verify we are in the expected state.
	state, ok := runner.CurrentState(sessionID)
	if !ok {
		t.Fatal("session not found after AdvanceToState")
	}
	if state != bounded_admission.StateSubmitting {
		t.Fatalf("expected StateSubmitting, got %s", state)
	}

	// Send MsgInput for each participant to trigger SubmitInput quorum.
	encPayload := `{"enc_x":"deadbeef"}`
	for _, p := range participants {
		_, err := runner.HandleMessage(sessionID, bounded_admission.MsgInput, p, []byte(encPayload))
		if err != nil {
			t.Fatalf("HandleMessage(%s, MsgInput): %v", p, err)
		}
	}

	// After the last MsgInput, SubmitInput.CheckComplete fires -> Exit ->
	// boundcheck.Enter (stub mode, no-op) -> cascade stops because
	// boundcheck consumes MsgBoundPartial. The session should now be at
	// StateChecking.
	state, ok = runner.CurrentState(sessionID)
	if !ok {
		t.Fatal("session not found after SubmitInput quorum")
	}
	if state != bounded_admission.StateChecking {
		t.Fatalf("expected StateChecking after SubmitInput, got %s", state)
	}

	// Send MsgBoundPartial for each participant. Each payload is a JSON
	// map[string][]byte covering both checked parties (required by the
	// boundcheck phase's quorum-merge logic).
	partialMap := map[string][]byte{
		"p0": []byte("partial-blob-p0"),
		"p1": []byte("partial-blob-p1"),
	}
	partialPayload, err := json.Marshal(partialMap)
	if err != nil {
		t.Fatalf("marshal partial map: %v", err)
	}
	for _, p := range participants {
		_, err := runner.HandleMessage(sessionID, boundcheck.MsgBoundPartial, p, partialPayload)
		if err != nil {
			t.Fatalf("HandleMessage(%s, MsgBoundPartial): %v", p, err)
		}
	}

	// After the last MsgBoundPartial, boundcheck.CheckComplete fires ->
	// boundcheck.Exit (stub, returns nil) -> PhaseSettle.Enter ->
	// PhaseSettle.Exit (terminal, ExitState=StateNone). The session ends
	// at StateNone, which means the pipeline ran to completion.
	state, ok = runner.CurrentState(sessionID)
	if !ok {
		t.Fatal("session not found after boundcheck completion")
	}
	if state != phase.StateNone {
		t.Fatalf("expected StateNone after pipeline completion, got %s", state)
	}

	// Verify that CtxAdmissionResults was populated by PhaseSettle.
	// In stub mode with no violations, the result map is empty.
	sctx := runner.SessionContext(sessionID)
	if sctx == nil {
		t.Fatal("session context is nil after completion")
	}
	if !sctx.Has(bounded_admission.CtxAdmissionResults) {
		t.Fatal("CtxAdmissionResults not set after PhaseSettle")
	}
}
