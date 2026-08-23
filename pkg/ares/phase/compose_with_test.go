// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestComposeWith_MissingSigner_FailsFast(t *testing.T) {
	// ComposeWith without WithSigner must reject at construction
	// time, not at first verification attempt.
	phases := []phase.Phase{noopPhase{name: "p1", entry: "S1", exit: phase.StateNone}}
	_, err := phase.ComposeWith(phases)
	if err == nil {
		t.Fatal("expected error on missing Signer")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "signer") {
		t.Errorf("error message should mention signer: %v", err)
	}
}

func TestComposeWith_HappyPath_DefaultsStoreToInMemory(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	phases := []phase.Phase{noopPhase{name: "p1", entry: "S1", exit: phase.StateNone}}
	runner, err := phase.ComposeWith(phases,
		phase.WithSigner(signer),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	if runner == nil {
		t.Fatal("returned nil runner")
	}
}

func TestComposeWith_ExplicitStore_Used(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	store := lineage.NewInMemoryStore()
	phases := []phase.Phase{noopPhase{name: "p1", entry: "S1", exit: phase.StateNone}}
	runner, err := phase.ComposeWith(phases,
		phase.WithSigner(signer),
		phase.WithStore(store),
	)
	if err != nil {
		t.Fatalf("ComposeWith: %v", err)
	}
	if runner == nil {
		t.Fatal("returned nil runner")
	}
}

func TestComposeWith_MultiParty_RequiresPeerVerifiers(t *testing.T) {
	// A phase that consumes WS messages → multi-party pipeline →
	// must have WithPeerVerifiers populated.
	signer, _ := sign.NewEd25519Signer()
	consumer := noopPhase{
		name:     "p1",
		entry:    "S1",
		exit:     phase.StateNone,
		consumes: []string{"test.frame"},
	}
	_, err := phase.ComposeWith(
		[]phase.Phase{consumer},
		phase.WithSigner(signer),
		// PeerVerifiers omitted
	)
	if err == nil {
		t.Fatal("expected error: multi-party pipeline without WithPeerVerifiers")
	}
	if !strings.Contains(err.Error(), "PeerVerifiers") {
		t.Errorf("error message should mention PeerVerifiers: %v", err)
	}
}

func TestComposeWith_MultiParty_HappyPath(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	consumer := noopPhase{
		name:     "p1",
		entry:    "S1",
		exit:     phase.StateNone,
		consumes: []string{"test.frame"},
	}
	runner, err := phase.ComposeWith(
		[]phase.Phase{consumer},
		phase.WithSigner(signer),
		phase.WithPeerVerifiers(peers),
	)
	if err != nil {
		t.Fatalf("ComposeWith multi-party: %v", err)
	}
	if runner == nil {
		t.Fatal("returned nil runner")
	}
}

// noopPhase is a minimal Phase impl for ComposeWith / runner tests.
type noopPhase struct {
	name        string
	entry, exit phase.SessionState
	consumes    []string
}

func (p noopPhase) Name() string                                                   { return p.name }
func (p noopPhase) Lifetime() phase.Lifetime                                       { return phase.LifetimePerSession }
func (p noopPhase) RunsAt() phase.RunsAt                                           { return phase.RunsAtInline }
func (p noopPhase) EntryState() phase.SessionState                                 { return p.entry }
func (p noopPhase) ExitState() phase.SessionState                                  { return p.exit }
func (p noopPhase) ConsumedMessageTypes() []string                                 { return p.consumes }
func (p noopPhase) InternalStates() []phase.SessionState                           { return nil }
func (p noopPhase) Requires() phase.ContextSchema                                  { return nil }
func (p noopPhase) Provides() phase.ContextSchema                                  { return nil }
func (p noopPhase) Enter(*phase.SessionContext) error                              { return nil }
func (p noopPhase) OnMessage(*phase.SessionContext, string, string, []byte) error { return nil }
func (p noopPhase) CheckComplete(*phase.SessionContext) bool                       { return true }
func (p noopPhase) Exit(*phase.SessionContext) error                               { return nil }
