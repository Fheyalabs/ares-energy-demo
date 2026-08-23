// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestHandleLineageMessage_VerifiesBeforeOnMessage(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	collector := &recordingPhase{name: "p1", entry: "S1", exit: phase.StateNone, consumes: []string{"test.frame"}}
	runner, err := phase.ComposeWith(
		[]phase.Phase{collector},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	if _, err := runner.BeginSession("sess-1", ""); err != nil {
		t.Fatalf("BeginSession: %v", err)
	}

	payload := []byte("expected payload")
	node, _ := lineage.Commit("sess-1", collector.Name(), "test-role", payload, nil, signer)

	if _, err := runner.HandleLineageMessage("sess-1", "test.frame", "p_remote", payload, &node); err != nil {
		t.Fatalf("HandleLineageMessage happy path: %v", err)
	}
	if !collector.sawMessage {
		t.Error("OnMessage was not called")
	}
}

func TestHandleLineageMessage_TamperedPayload_AbortsBeforeOnMessage(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	collector := &recordingPhase{name: "p1", entry: "S1", exit: phase.StateNone, consumes: []string{"test.frame"}}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{collector},
		phase.WithSigner(signer),
		phase.WithStore(store),
		phase.WithPeerVerifiers(peers),
	)
	runner.BeginSession("sess-1", "")

	original := []byte("original")
	node, _ := lineage.Commit("sess-1", collector.Name(), "test-role", original, nil, signer)

	// Submit tampered bytes; verifier hashes tampered, compares to
	// node.PayloadHash (which is the hash of original) → mismatch.
	_, err := runner.HandleLineageMessage("sess-1", "test.frame", "p_remote", []byte("tampered"), &node)
	if err == nil {
		t.Fatal("expected verification failure")
	}
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Errorf("expected *MismatchError wrapped in returned error, got %T: %v", err, err)
	}
	if collector.sawMessage {
		t.Error("OnMessage was called despite verification failure")
	}
}

func TestHandleLineageMessage_MissingLineage_RejectedOnLineageEnabledRunner(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	collector := &recordingPhase{name: "p1", entry: "S1", exit: phase.StateNone, consumes: []string{"test.frame"}}
	runner, _ := phase.ComposeWith(
		[]phase.Phase{collector},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peers),
	)
	runner.BeginSession("sess-1", "")

	_, err := runner.HandleLineageMessage("sess-1", "test.frame", "p_remote", []byte("p"), nil)
	if err == nil {
		t.Fatal("expected rejection for nil lineage on ComposeWith runner")
	}
}

func TestHandleLineageMessage_ComposeBuiltRunner_FallsThroughToLegacy(t *testing.T) {
	// A runner built with Compose (lineage-disabled) should
	// transparently forward to HandleMessage even if the caller
	// passes a non-nil lineage node — useful for transport layers
	// that don't yet distinguish runner kinds.
	collector := &recordingPhase{name: "p1", entry: "S1", exit: phase.StateNone, consumes: []string{"test.frame"}}
	runner, _ := phase.Compose(collector)
	runner.BeginSession("sess-1", "")

	// Even a nil lineage node should be tolerated on Compose runners.
	if _, err := runner.HandleLineageMessage("sess-1", "test.frame", "p_remote", []byte("payload"), nil); err != nil {
		t.Fatalf("Compose-built runner rejected nil lineage: %v", err)
	}
	if !collector.sawMessage {
		t.Error("legacy fall-through did not dispatch to OnMessage")
	}
}

// recordingPhase records whether OnMessage was called.
type recordingPhase struct {
	name        string
	entry, exit phase.SessionState
	consumes    []string
	sawMessage  bool
}

func (p *recordingPhase) Name() string                                                    { return p.name }
func (p *recordingPhase) Lifetime() phase.Lifetime                                        { return phase.LifetimePerSession }
func (p *recordingPhase) RunsAt() phase.RunsAt                                            { return phase.RunsAtInline }
func (p *recordingPhase) EntryState() phase.SessionState                                  { return p.entry }
func (p *recordingPhase) ExitState() phase.SessionState                                   { return p.exit }
func (p *recordingPhase) ConsumedMessageTypes() []string                                  { return p.consumes }
func (p *recordingPhase) InternalStates() []phase.SessionState                            { return nil }
func (p *recordingPhase) Requires() phase.ContextSchema                                   { return nil }
func (p *recordingPhase) Provides() phase.ContextSchema                                   { return nil }
func (p *recordingPhase) Enter(*phase.SessionContext) error                               { return nil }
func (p *recordingPhase) OnMessage(*phase.SessionContext, string, string, []byte) error  { p.sawMessage = true; return nil }
func (p *recordingPhase) CheckComplete(*phase.SessionContext) bool                        { return p.sawMessage }
func (p *recordingPhase) Exit(*phase.SessionContext) error                                { return nil }
