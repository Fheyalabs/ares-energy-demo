// SPDX-License-Identifier: Apache-2.0

// This file is an integration test for the SC-10 H2 close. It
// simulates Phase 1b (a non-initiator submits an encrypted
// profile) and Phase 2 (gated on a "ready" signal so the test can
// tamper between phases) through the runner's auto-wrap dispatch.
// A server-side tamper between the two phases is detected via a
// severed parent chain in the resulting score node.

package phase_test

import (
	"context"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestH2_NoTamper_ParentChainResolves(t *testing.T) {
	// Sanity-check: in the absence of tampering, Phase 2's score
	// node WILL have one parent pointing at Phase 1b's profile
	// node.
	clientSigner, _ := sign.NewEd25519Signer()
	serverSigner, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: clientSigner}

	phase1b := &profileSubmitPhase{name: "phase-1b", entry: "S1", exit: "S2"}
	phase2 := &gatedScoringPhase{name: "phase-2", entry: "S2", exit: phase.StateNone}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{phase1b, phase2},
		phase.WithSigner(serverSigner),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	runner.BeginSession("sess-honest", "")

	// Submit Phase 1b profile.
	original := []byte("honest profile bytes")
	pNode, _ := lineage.Commit("sess-honest", phase1b.Name(), "CtxProfileBytes", original, nil, clientSigner)
	if _, err := runner.HandleLineageMessage("sess-honest", "fheya.phase1b.profile", "p_i", original, &pNode); err != nil {
		t.Fatalf("phase 1b: %v", err)
	}

	// Drive Phase 2 with a "ready" signal.
	ready := []byte("ready")
	rNode, _ := lineage.Commit("sess-honest", phase2.Name(), "phase2-ready-signal", ready, nil, clientSigner)
	if _, err := runner.HandleLineageMessage("sess-honest", "phase2.ready", "p_i", ready, &rNode); err != nil {
		t.Fatalf("phase 2 ready: %v", err)
	}

	var scoreNode *lineage.DAGNode
	for n, err := range store.WalkSession(context.Background(), "sess-honest") {
		if err != nil {
			t.Fatalf("WalkSession: %v", err)
		}
		if n.PhaseID == "phase-2" && n.Role == "CtxScoreBytes" {
			n := n
			scoreNode = &n
			break
		}
	}
	if scoreNode == nil {
		t.Fatal("Phase 2 did not produce a score node")
	}
	if len(scoreNode.Parents) != 1 {
		t.Errorf("honest score node has %d parents, want 1", len(scoreNode.Parents))
	}
}

func TestH2_TamperBetweenPhases_SeversParentChain(t *testing.T) {
	// The H2 attack: a malicious server tampers with the in-context
	// bytes between Phase 1b cascading complete and Phase 2 firing.
	// Phase 2's auto-commit looks up the actual context bytes'
	// PayloadHash; the tampered bytes don't match Phase 1b's
	// committed hash, so no parent edge is emitted. A verifier
	// downstream can spot the severed lineage chain.
	clientSigner, _ := sign.NewEd25519Signer()
	serverSigner, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: clientSigner}

	phase1b := &profileSubmitPhase{name: "phase-1b", entry: "S1", exit: "S2"}
	phase2 := &gatedScoringPhase{name: "phase-2", entry: "S2", exit: phase.StateNone}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{phase1b, phase2},
		phase.WithSigner(serverSigner),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	runner.BeginSession("sess-h2", "")

	original := []byte("enc_ei_session_p_i original bytes")
	pNode, _ := lineage.Commit("sess-h2", phase1b.Name(), "CtxProfileBytes", original, nil, clientSigner)
	if _, err := runner.HandleLineageMessage("sess-h2", "fheya.phase1b.profile", "p_i", original, &pNode); err != nil {
		t.Fatalf("phase 1b honest submission: %v", err)
	}

	// Server tampers with in-context bytes between Phase 1b cascade
	// and Phase 2 firing.
	ctx := runner.SessionContext("sess-h2")
	if ctx == nil {
		t.Fatal("SessionContext for sess-h2 not found")
	}
	ctx.Set("CtxProfileBytes", []byte("TAMPERED bytes"))

	// Drive Phase 2; auto-commit will resolve parents against the
	// tampered (now-divergent) bytes.
	ready := []byte("ready")
	rNode, _ := lineage.Commit("sess-h2", phase2.Name(), "phase2-ready-signal", ready, nil, clientSigner)
	if _, err := runner.HandleLineageMessage("sess-h2", "phase2.ready", "p_i", ready, &rNode); err != nil {
		t.Fatalf("phase 2 ready: %v", err)
	}

	var scoreNode *lineage.DAGNode
	for n, err := range store.WalkSession(context.Background(), "sess-h2") {
		if err != nil {
			t.Fatalf("WalkSession: %v", err)
		}
		if n.PhaseID == "phase-2" && n.Role == "CtxScoreBytes" {
			n := n
			scoreNode = &n
			break
		}
	}
	if scoreNode == nil {
		t.Fatal("Phase 2 did not produce a lineage node")
	}
	if len(scoreNode.Parents) != 0 {
		t.Errorf("score node has %d parents; tamper should have severed the lineage chain (no PayloadHash match in store)",
			len(scoreNode.Parents))
	}
}

// profileSubmitPhase: consumes "fheya.phase1b.profile" frames;
// stores the inbound payload at CtxProfileBytes.
type profileSubmitPhase struct {
	name        string
	entry, exit phase.SessionState
	seen        bool
}

func (p *profileSubmitPhase) Name() string                                                    { return p.name }
func (p *profileSubmitPhase) Lifetime() phase.Lifetime                                        { return phase.LifetimePerSession }
func (p *profileSubmitPhase) RunsAt() phase.RunsAt                                            { return phase.RunsAtInline }
func (p *profileSubmitPhase) EntryState() phase.SessionState                                  { return p.entry }
func (p *profileSubmitPhase) ExitState() phase.SessionState                                   { return p.exit }
func (p *profileSubmitPhase) ConsumedMessageTypes() []string                                  { return []string{"fheya.phase1b.profile"} }
func (p *profileSubmitPhase) InternalStates() []phase.SessionState                            { return nil }
func (p *profileSubmitPhase) Requires() phase.ContextSchema                                   { return nil }
func (p *profileSubmitPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{"CtxProfileBytes": {TypeName: "[]byte"}}
}
func (p *profileSubmitPhase) Enter(*phase.SessionContext) error                               { return nil }
func (p *profileSubmitPhase) OnMessage(ctx *phase.SessionContext, _, _ string, payload []byte) error {
	ctx.Set("CtxProfileBytes", payload)
	p.seen = true
	return nil
}
func (p *profileSubmitPhase) CheckComplete(*phase.SessionContext) bool                        { return p.seen }
func (p *profileSubmitPhase) Exit(*phase.SessionContext) error                                { return nil }

// gatedScoringPhase reads CtxProfileBytes, then emits CtxScoreBytes
// as a deterministic function only when a "phase2.ready" message
// arrives. The gate lets tests tamper with context bytes between
// Phase 1b cascade and Phase 2 auto-commit.
type gatedScoringPhase struct {
	name        string
	entry, exit phase.SessionState
	ready       bool
}

func (p *gatedScoringPhase) Name() string                                                    { return p.name }
func (p *gatedScoringPhase) Lifetime() phase.Lifetime                                        { return phase.LifetimePerSession }
func (p *gatedScoringPhase) RunsAt() phase.RunsAt                                            { return phase.RunsAtInline }
func (p *gatedScoringPhase) EntryState() phase.SessionState                                  { return p.entry }
func (p *gatedScoringPhase) ExitState() phase.SessionState                                   { return p.exit }
func (p *gatedScoringPhase) ConsumedMessageTypes() []string                                  { return []string{"phase2.ready"} }
func (p *gatedScoringPhase) InternalStates() []phase.SessionState                            { return nil }
func (p *gatedScoringPhase) Requires() phase.ContextSchema {
	return phase.ContextSchema{"CtxProfileBytes": {TypeName: "[]byte", Required: true}}
}
func (p *gatedScoringPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{"CtxScoreBytes": {TypeName: "[]byte"}}
}
func (p *gatedScoringPhase) Enter(*phase.SessionContext) error                               { return nil }
func (p *gatedScoringPhase) OnMessage(ctx *phase.SessionContext, _, _ string, _ []byte) error {
	in, _ := ctx.Get("CtxProfileBytes")
	if b, ok := in.([]byte); ok {
		ctx.Set("CtxScoreBytes", b) // identity score for test purposes
	}
	p.ready = true
	return nil
}
func (p *gatedScoringPhase) CheckComplete(*phase.SessionContext) bool                        { return p.ready }
func (p *gatedScoringPhase) Exit(*phase.SessionContext) error                                { return nil }
