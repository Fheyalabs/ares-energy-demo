// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestMismatchClaim_VerifiableByAnyParty(t *testing.T) {
	// A mismatch claim produced by party A must be re-verifiable
	// by party B using A's pubkey. This is the cross-verification
	// step that distinguishes confirmed mismatches from false
	// claims.
	signerA, _ := sign.NewEd25519Signer()
	signerB, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peersA := map[string]sign.Signer{sign.Ed25519Algorithm: signerA}

	runnerA, _ := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "n", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signerA),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peersA),
	)
	runnerA.BeginSession("sess-1", "")

	mismatchErr := &lineage.MismatchError{
		Field:    "PayloadHash",
		NodeHash: lineage.NodeRef{0x01, 0x02, 0x03},
	}
	claim, err := runnerA.BuildMismatchClaim("sess-1", "phase-1c", "profile-ct", mismatchErr)
	if err != nil {
		t.Fatalf("BuildMismatchClaim: %v", err)
	}

	// Party B verifies A's claim using A's pubkey from B's verifier set.
	bVerifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signerA}
	if err := lineage.Verify(claim, []byte(mismatchErr.Error()), bVerifiers); err != nil {
		t.Errorf("party B cannot verify party A's mismatch claim: %v", err)
	}

	// And: swap producer pubkey to a different party's; verification
	// must fail.
	claim.Producer = signerB.PublicKey()
	wrongVerifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signerB}
	if err := lineage.Verify(claim, []byte(mismatchErr.Error()), wrongVerifiers); err == nil {
		t.Error("expected verification failure with wrong producer pubkey on claim")
	}
}

func TestMismatchClaim_FalseFraming_DeliveredViaHook(t *testing.T) {
	// Scenario: party A broadcasts a mismatch claim on a node that
	// other parties cross-verify and find valid. The hook fires
	// with Kind="mismatch-false-claim" attributing A.
	//
	// The transport-layer cross-verification dance is not in scope
	// for the framework unit tests; this test confirms the hook
	// delivery path itself: ReportFalseLineageClaim drives the
	// hook with the right structured event.
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
	if captured[0].Attributee == "" {
		t.Error("Attributee not populated; F-49 collateral applies to nobody")
	}
}
