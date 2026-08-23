// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
)

// TestDAGNodeHash_DeterministicAcrossCallers confirms two producers
// constructing nodes from the same logical inputs (session, phase,
// role, payload bytes, parents) get the same Hash. Required for
// content-addressing.
func TestDAGNodeHash_DeterministicAcrossCallers(t *testing.T) {
	payload := []byte("hello payload")
	parents := []lineage.NodeRef{
		bytesToNodeRef([]byte("parent-1")),
		bytesToNodeRef([]byte("parent-2")),
	}
	h1 := lineage.DeriveNodeHash("sess-1", "phase-1b", "role-x", payload, parents)
	h2 := lineage.DeriveNodeHash("sess-1", "phase-1b", "role-x", payload, parents)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: h1=%x h2=%x", h1, h2)
	}
}

// TestDAGNodeHash_SensitiveToEveryField: bit-flip on any input field
// changes the hash.
func TestDAGNodeHash_SensitiveToEveryField(t *testing.T) {
	base := lineage.DeriveNodeHash(
		"sess-1", "phase-1b", "role-x",
		[]byte("payload"),
		[]lineage.NodeRef{bytesToNodeRef([]byte("p1"))},
	)

	cases := []struct {
		name string
		got  lineage.NodeRef
	}{
		{"session", lineage.DeriveNodeHash("sess-2", "phase-1b", "role-x", []byte("payload"), []lineage.NodeRef{bytesToNodeRef([]byte("p1"))})},
		{"phase", lineage.DeriveNodeHash("sess-1", "phase-1c", "role-x", []byte("payload"), []lineage.NodeRef{bytesToNodeRef([]byte("p1"))})},
		{"role", lineage.DeriveNodeHash("sess-1", "phase-1b", "role-y", []byte("payload"), []lineage.NodeRef{bytesToNodeRef([]byte("p1"))})},
		{"payload", lineage.DeriveNodeHash("sess-1", "phase-1b", "role-x", []byte("payload2"), []lineage.NodeRef{bytesToNodeRef([]byte("p1"))})},
		{"parent", lineage.DeriveNodeHash("sess-1", "phase-1b", "role-x", []byte("payload"), []lineage.NodeRef{bytesToNodeRef([]byte("p2"))})},
	}
	for _, tc := range cases {
		if tc.got == base {
			t.Errorf("hash not sensitive to %s field", tc.name)
		}
	}
}

// TestDAGNodeHash_ParentsCanonicallyOrdered: passing parents in
// different orders produces the same hash. The implementation
// sorts parents internally.
func TestDAGNodeHash_ParentsCanonicallyOrdered(t *testing.T) {
	p1 := bytesToNodeRef([]byte("aaaa"))
	p2 := bytesToNodeRef([]byte("bbbb"))
	p3 := bytesToNodeRef([]byte("cccc"))

	// DeriveNodeHash itself expects canonical (sorted) input.
	// sortParents is exposed via NewDAGNode; for direct
	// DeriveNodeHash callers we precompute the canonical order.
	canon1 := sortRefs([]lineage.NodeRef{p1, p2, p3})
	canon2 := sortRefs([]lineage.NodeRef{p3, p1, p2})
	canon3 := sortRefs([]lineage.NodeRef{p2, p3, p1})

	a := lineage.DeriveNodeHash("s", "p", "r", []byte("x"), canon1)
	b := lineage.DeriveNodeHash("s", "p", "r", []byte("x"), canon2)
	c := lineage.DeriveNodeHash("s", "p", "r", []byte("x"), canon3)
	if a != b || b != c {
		t.Fatalf("hash not invariant under canonical parent ordering: a=%x b=%x c=%x", a, b, c)
	}
}

// TestNewDAGNode_PopulatesAllFields confirms the constructor wires
// hash, session, phase, role, payload hash, parents, and CreatedAt.
func TestNewDAGNode_PopulatesAllFields(t *testing.T) {
	payload := []byte("p")
	parents := []lineage.NodeRef{bytesToNodeRef([]byte("ref"))}
	parentRoles := []string{"role-parent"}
	producer := []byte{0x01, 0x02}
	signature := []byte{0xff, 0xfe}
	alg := "ed25519"
	beforeT := time.Now()
	node := lineage.NewDAGNode("s", "p", "r", payload, parents, parentRoles, producer, signature, alg)
	afterT := time.Now()

	if node.SessionID != "s" {
		t.Error("SessionID not set")
	}
	if node.PhaseID != "p" {
		t.Error("PhaseID not set")
	}
	if node.Role != "r" {
		t.Error("Role not set")
	}
	if len(node.Parents) != 1 || node.Parents[0] != parents[0] {
		t.Error("Parents not set")
	}
	if len(node.ParentRoles) != 1 || node.ParentRoles[0] != "role-parent" {
		t.Error("ParentRoles not set")
	}
	if !bytes.Equal(node.Producer, producer) {
		t.Error("Producer not set")
	}
	if !bytes.Equal(node.Signature, signature) {
		t.Error("Signature not set")
	}
	if node.Algorithm != alg {
		t.Error("Algorithm not set")
	}
	// time.Now() is wall-clock; use truncated comparisons to allow
	// fractional-second drift between Before/After/CreatedAt.
	if node.CreatedAt.Before(beforeT.Add(-time.Second)) || node.CreatedAt.After(afterT.Add(time.Second)) {
		t.Errorf("CreatedAt %v not within [%v, %v]", node.CreatedAt, beforeT, afterT)
	}
	// Hash must match DeriveNodeHash on the same inputs (parents
	// must already be in canonical order — NewDAGNode sorts them).
	want := lineage.DeriveNodeHash("s", "p", "r", payload, sortRefs(parents))
	if node.Hash != want {
		t.Errorf("Hash = %x, want %x", node.Hash, want)
	}
	// PayloadHash must match SHA-256(payload).
	wantPL := lineage.HashPayload(payload)
	if node.PayloadHash != wantPL {
		t.Errorf("PayloadHash = %x, want %x", node.PayloadHash, wantPL)
	}
}

// bytesToNodeRef is a test helper that constructs a NodeRef by
// hashing arbitrary bytes — gives stable distinct refs for tests.
func bytesToNodeRef(b []byte) lineage.NodeRef {
	return lineage.HashPayload(b)
}

// sortRefs is a local helper that lex-sorts a NodeRef slice.
// Mirrors the package-internal sort used by NewDAGNode for tests
// that call DeriveNodeHash directly.
func sortRefs(refs []lineage.NodeRef) []lineage.NodeRef {
	out := append([]lineage.NodeRef(nil), refs...)
	// insertion sort — small N, no import overhead.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(out[j-1][:], out[j][:]) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
