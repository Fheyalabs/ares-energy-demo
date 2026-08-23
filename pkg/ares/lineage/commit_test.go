// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"bytes"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestCommit_ProducesWellFormedNode(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("test payload")
	node, err := lineage.Commit(
		"sess-1", "phase-1b", "profile-ct-p_i",
		payload,
		nil, // no parents (genesis-style node)
		signer,
	)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// PayloadHash must match SHA-256(payload).
	want := lineage.HashPayload(payload)
	if node.PayloadHash != want {
		t.Errorf("PayloadHash = %x, want %x", node.PayloadHash, want)
	}
	// Producer must equal signer's public key.
	if !bytes.Equal(node.Producer, signer.PublicKey()) {
		t.Errorf("Producer != signer pubkey")
	}
	// Algorithm must match.
	if node.Algorithm != signer.Algorithm() {
		t.Errorf("Algorithm = %q, want %q", node.Algorithm, signer.Algorithm())
	}
	// Signature must verify against signer's pubkey on canonical
	// signing message.
	msg := lineage.SigningMessage(node.Hash, "sess-1", "phase-1b", "profile-ct-p_i")
	if err := signer.Verify(signer.PublicKey(), msg, node.Signature); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestCommit_WithParents_StoresParentsCanonically(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	parentNodes := []lineage.DAGNode{
		mustCommit(t, signer, "sess", "phase-prev", "input-a", []byte("a"), nil),
		mustCommit(t, signer, "sess", "phase-prev", "input-b", []byte("b"), nil),
	}
	node, err := lineage.Commit(
		"sess", "phase-cur", "output", []byte("payload"),
		parentNodes, signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Parents) != 2 {
		t.Fatalf("Parents len = %d, want 2", len(node.Parents))
	}
	// Parents are sorted canonically; reordered input should produce
	// the same Hash.
	reordered, _ := lineage.Commit(
		"sess", "phase-cur", "output", []byte("payload"),
		[]lineage.DAGNode{parentNodes[1], parentNodes[0]},
		signer,
	)
	if node.Hash != reordered.Hash {
		t.Errorf("Hash differs under parent reordering: %x vs %x", node.Hash, reordered.Hash)
	}
}

func TestCommit_NilSigner_Errors(t *testing.T) {
	_, err := lineage.Commit("s", "p", "r", []byte("x"), nil, nil)
	if err == nil {
		t.Fatal("expected error on nil signer")
	}
}

func mustCommit(t *testing.T, signer sign.Signer, sessionID, phaseID, role string, payload []byte, parents []lineage.DAGNode) lineage.DAGNode {
	t.Helper()
	n, err := lineage.Commit(sessionID, phaseID, role, payload, parents, signer)
	if err != nil {
		t.Fatalf("mustCommit: %v", err)
	}
	return n
}
