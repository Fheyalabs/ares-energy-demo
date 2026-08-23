// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestRunner_VerifyFailure_FiresFailureHook(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	var fired []phase.LineageFailureEvent
	hook := func(ev phase.LineageFailureEvent) {
		fired = append(fired, ev)
	}

	collector := &recordingPhase{name: "p1", entry: "S1", exit: phase.StateNone, consumes: []string{"test.frame"}}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{collector},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
		phase.WithLineageFailureHook(hook),
	)
	runner.BeginSession("sess-1", "")

	original := []byte("original")
	node, _ := lineage.Commit("sess-1", collector.Name(), "test-role", original, nil, signer)

	// Tamper: submit modified bytes.
	_, err := runner.HandleLineageMessage("sess-1", "test.frame", "p_remote", []byte("tampered"), &node)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if len(fired) == 0 {
		t.Fatal("LineageFailureHook never fired")
	}
	if fired[0].Kind != "mismatch-confirmed" {
		t.Errorf("Kind = %q, want %q", fired[0].Kind, "mismatch-confirmed")
	}
	if fired[0].SessionID != "sess-1" {
		t.Errorf("SessionID = %q, want %q", fired[0].SessionID, "sess-1")
	}
}

func TestRunner_BuildMismatchClaim_SignedAndAttributable(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	runner, _ := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "p", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	runner.BeginSession("sess-1", "")

	mismatchErr := &lineage.MismatchError{Field: "PayloadHash", NodeHash: lineage.NodeRef{0x01}}
	claim, err := runner.BuildMismatchClaim("sess-1", "phase-x", "role-y", mismatchErr)
	if err != nil {
		t.Fatalf("BuildMismatchClaim: %v", err)
	}
	if claim.Role != "mismatch-claim" {
		t.Errorf("Role = %q, want %q", claim.Role, "mismatch-claim")
	}
	if claim.PhaseID != "phase-x" {
		t.Errorf("PhaseID = %q, want %q", claim.PhaseID, "phase-x")
	}
	if len(claim.Signature) == 0 {
		t.Error("mismatch claim is unsigned")
	}
	// Claim must verify under the local signer's pubkey.
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	if err := lineage.Verify(claim, []byte(mismatchErr.Error()), verifiers); err != nil {
		t.Errorf("mismatch claim does not verify: %v", err)
	}
}

func TestRunner_ReportFalseLineageClaim_FiresHook(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	var captured []phase.LineageFailureEvent
	hook := func(ev phase.LineageFailureEvent) {
		captured = append(captured, ev)
	}

	runner, _ := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "n", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
		phase.WithLineageFailureHook(hook),
	)
	runner.BeginSession("sess-1", "")

	wrongClaim, _ := runner.BuildMismatchClaim("sess-1", "phase-x", "role-y",
		&lineage.MismatchError{Field: "PayloadHash"})
	runner.ReportFalseLineageClaim("sess-1", wrongClaim)

	if len(captured) == 0 {
		t.Fatal("hook never fired for false claim")
	}
	if captured[0].Kind != "mismatch-false-claim" {
		t.Errorf("Kind = %q, want %q", captured[0].Kind, "mismatch-false-claim")
	}
}

func TestRunner_HookPanic_Recovered(t *testing.T) {
	// A buggy hook that panics must not crash the runner.
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	panicHook := func(ev phase.LineageFailureEvent) {
		panic("intentional test panic")
	}

	runner, _ := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "n", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
		phase.WithLineageFailureHook(panicHook),
	)
	runner.BeginSession("sess-1", "")

	claim, _ := runner.BuildMismatchClaim("sess-1", "p", "r", &lineage.MismatchError{Field: "test"})
	// Should return cleanly even though the hook panics.
	runner.ReportFalseLineageClaim("sess-1", claim)
}
