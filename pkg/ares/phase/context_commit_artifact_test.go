// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestSessionContext_CommitArtifact_ComposeWith_NodeHasParentsAndIsInStore
// verifies that CommitArtifact on a ComposeWith-built runner produces a
// DAGNode whose Parents set matches the supplied parents, and that the node
// is retrievable from the store via LineageDAG.
func TestSessionContext_CommitArtifact_ComposeWith_NodeHasParentsAndIsInStore(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	runner, err := phase.ComposeWith(
		[]phase.Phase{noopPhase{name: "p1", entry: "S1", exit: phase.StateNone}},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	ctx, err := runner.BeginSession("sess-ca", "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	// Build two synthetic parent nodes by committing them to the store
	// directly (simulating prior phase outputs).
	parent1, err := lineage.Commit("sess-ca", "phase-a", "output-a", []byte("parent payload 1"), nil, signer)
	if err != nil {
		t.Fatalf("Commit parent1: %v", err)
	}
	parent2, err := lineage.Commit("sess-ca", "phase-b", "output-b", []byte("parent payload 2"), nil, signer)
	if err != nil {
		t.Fatalf("Commit parent2: %v", err)
	}

	artifactPayload := []byte("artifact payload")
	parents := []lineage.DAGNode{parent1, parent2}

	node, err := ctx.CommitArtifact("test-phase", "test-role", artifactPayload, parents)
	if err != nil {
		t.Fatalf("CommitArtifact: %v", err)
	}

	// Parents must match the supplied parent hashes (as a set).
	if len(node.Parents) != len(parents) {
		t.Fatalf("node.Parents length = %d, want %d", len(node.Parents), len(parents))
	}
	wantParents := map[lineage.NodeRef]bool{
		parent1.Hash: true,
		parent2.Hash: true,
	}
	for _, ref := range node.Parents {
		if !wantParents[ref] {
			t.Errorf("unexpected parent ref %x in node.Parents", ref)
		}
	}

	// The node must be retrievable from LineageDAG.
	found := false
	for n := range ctx.LineageDAG() {
		if n.Hash == node.Hash {
			found = true
			break
		}
	}
	if !found {
		t.Error("CommitArtifact node not found via ctx.LineageDAG()")
	}
}

// TestSessionContext_CommitArtifact_Compose_ReturnsErrPermanent verifies that
// CommitArtifact returns an error wrapping ErrPermanent when called on a
// Compose-built (non-lineage) runner.
func TestSessionContext_CommitArtifact_Compose_ReturnsErrPermanent(t *testing.T) {
	runner, err := phase.Compose(noopPhase{name: "p1", entry: "S1", exit: phase.StateNone})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	ctx, err := runner.BeginSession("sess-ca-noop", "")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	_, commitErr := ctx.CommitArtifact("test-phase", "test-role", []byte("payload"), nil)
	if commitErr == nil {
		t.Fatal("expected error from CommitArtifact on Compose-built runner; got nil")
	}
	if !errors.Is(commitErr, phase.ErrPermanent) {
		t.Errorf("expected errors.Is(err, ErrPermanent); got: %v", commitErr)
	}
}
