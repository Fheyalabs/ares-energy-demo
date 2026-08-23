// SPDX-License-Identifier: Apache-2.0

// This file exercises the full Phase 1 lineage API (Commit, Store,
// Verify) end-to-end so we know the package is self-consistent
// before the runner integration in Phase 2.

package lineage_test

import (
	"context"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestPhase1_HappyPath_TwoPhasesOneStore(t *testing.T) {
	// Simulate two phases: Phase 1b commits a profile ciphertext;
	// Phase 1c commits a norm ciphertext that depends on it.
	// Verifier (acting as a third party) confirms both nodes
	// verify and the parent ref resolves in the store.

	clientSigner, _ := sign.NewEd25519Signer()
	serverSigner, _ := sign.NewEd25519Signer()
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: clientSigner}
	// (One verifier is enough; both signers use ed25519. Verifier
	// uses node.Producer to pick the pubkey, not a per-party
	// signer instance.)

	store := lineage.NewInMemoryStore()
	ctx := context.Background()

	// Phase 1b: client P_i commits enc_ei_session_i.
	profilePayload := []byte("enc_ei_session_p_i bytes")
	profileNode, err := lineage.Commit(
		"sess-1", "phase-1b-encrypted-submit", "profile-ct-p_i",
		profilePayload, nil, clientSigner,
	)
	if err != nil {
		t.Fatalf("Commit phase 1b: %v", err)
	}
	if err := store.Append(ctx, profileNode); err != nil {
		t.Fatalf("Append phase 1b: %v", err)
	}

	// Phase 1c: server commits enc_norm_i, declaring profileNode
	// as parent.
	normPayload := []byte("enc_norm_p_i bytes")
	normNode, err := lineage.Commit(
		"sess-1", "phase-1c-ares-nc", "norm-ct-p_i",
		normPayload,
		[]lineage.DAGNode{profileNode},
		serverSigner,
	)
	if err != nil {
		t.Fatalf("Commit phase 1c: %v", err)
	}
	if err := store.Append(ctx, normNode); err != nil {
		t.Fatalf("Append phase 1c: %v", err)
	}

	// Verify both nodes against their original payloads.
	if err := lineage.Verify(profileNode, profilePayload, verifiers); err != nil {
		t.Errorf("Verify profile node: %v", err)
	}
	if err := lineage.Verify(normNode, normPayload, verifiers); err != nil {
		t.Errorf("Verify norm node: %v", err)
	}

	// Confirm normNode's parent ref resolves in the store.
	if len(normNode.Parents) != 1 {
		t.Fatalf("normNode has %d parents, want 1", len(normNode.Parents))
	}
	parent, err := store.Get(ctx, normNode.Parents[0])
	if err != nil {
		t.Fatalf("parent ref does not resolve: %v", err)
	}
	if parent.Hash != profileNode.Hash {
		t.Errorf("resolved parent hash = %x, want %x", parent.Hash, profileNode.Hash)
	}
	if parent.Role != "profile-ct-p_i" {
		t.Errorf("resolved parent role = %q, want %q", parent.Role, "profile-ct-p_i")
	}
}

func TestPhase1_H2_StyleTampering_Detected(t *testing.T) {
	// The H2 attack: server tries to use a tampered ciphertext at
	// Phase 1c while the Phase 1b commit was made on the
	// original. The verifier hashes the tampered bytes and
	// compares to the Phase 1b PayloadHash — they don't match,
	// Verify catches it.

	clientSigner, _ := sign.NewEd25519Signer()
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: clientSigner}

	original := []byte("enc_ei_session original")
	profileNode, _ := lineage.Commit(
		"sess", "phase-1b", "profile-ct",
		original, nil, clientSigner,
	)

	// Server tampers: feed verifier the same node but different bytes.
	tampered := []byte("enc_ei_session +Enc(delta)")
	err := lineage.Verify(profileNode, tampered, verifiers)
	if err == nil {
		t.Fatal("H2-style tampering not detected")
	}
}
