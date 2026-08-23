// SPDX-License-Identifier: Apache-2.0

package keygen

import (
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// TestSinglePartyKeygen_RejectedByThresholdDecrypt verifies the
// composition-time topology guard: SinglePartyKeygenPhase tags its
// secret_shares as topology=single_party, but Phase3ThresholdDecrypt
// requires topology=threshold. Compose must reject this mismatch so
// an app author can't accidentally wire a server-trusted keygen into
// a pipeline whose decrypt phase assumes threshold semantics.
func TestSinglePartyKeygen_RejectedByThresholdDecrypt(t *testing.T) {
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewSinglePartyKeygen(),
		stubArcPhase("post-keygen", defaults.StateGossip, defaults.StateScoring, nil, nil),
		stubArcPhase("score", defaults.StateScoring, defaults.StateDecrypting,
			phase.ContextSchema{defaults.CtxEvalKeys: {TypeName: "OpenFHEEvalKeys", Required: true}},
			phase.ContextSchema{defaults.CtxResultCiphertext: {TypeName: "[]byte"}},
		),
		defaults.NewPhase3ThresholdDecrypt(),
		stubArcPhase("settle", defaults.StateBroadcasting, phase.StateNone, nil, nil),
	)
	if err == nil {
		t.Fatalf("expected Compose to reject single_party keygen feeding threshold decrypt")
	}
	if !strings.Contains(err.Error(), "topology") {
		t.Errorf("expected topology error, got: %v", err)
	}
}

// TestSinglePartyKeygen_ComposesWithoutThresholdDecrypt verifies the
// happy path: single-party keygen works fine in pipelines that don't
// include the threshold-decrypt phase (e.g., a server-trusted auction
// where the auctioneer decrypts unilaterally).
func TestSinglePartyKeygen_ComposesWithoutThresholdDecrypt(t *testing.T) {
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewSinglePartyKeygen(),
		stubArcPhase("score", defaults.StateGossip, defaults.StateScoring, nil, nil),
		stubArcPhase("settle", defaults.StateScoring, phase.StateNone, nil, nil),
	)
	if err != nil {
		t.Fatalf("expected single-party pipeline without threshold decrypt to compose, got: %v", err)
	}
}

// TestPlaintextKeygen_RejectsThresholdDecrypt verifies that pairing
// PlaintextKeygen (provides secret_shares as []byte, not a per-
// participant map) with Phase3ThresholdDecrypt (which expects
// map[string][]byte) is caught at construction time by the type
// constraint check.
func TestPlaintextKeygen_RejectsThresholdDecrypt(t *testing.T) {
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewPlaintextKeygen(),
		stubArcPhase("score", defaults.StateGossip, defaults.StateDecrypting,
			nil,
			phase.ContextSchema{defaults.CtxResultCiphertext: {TypeName: "[]byte"}},
		),
		defaults.NewPhase3ThresholdDecrypt(),
	)
	if err == nil {
		t.Fatalf("expected constructor to reject plaintext keygen + threshold decrypt (secret_shares type mismatch)")
	}
	if !strings.Contains(err.Error(), "secret_shares") {
		t.Errorf("expected error about secret_shares type mismatch, got: %v", err)
	}
}

// TestPlaintextKeygen_ComposesIntoMinimalRunner verifies the
// shortest valid plaintext pipeline (invitation + keygen) composes
// without errors.
func TestPlaintextKeygen_ComposesIntoMinimalRunner(t *testing.T) {
	r, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewPlaintextKeygen(),
	)
	if err != nil {
		t.Fatalf("plaintext keygen + invitation: %v", err)
	}
	if r.InitialState() != defaults.StateInviting {
		t.Errorf("plaintext pipeline initial state: %q, want INVITING",
			r.InitialState())
	}
}

// TestPreSharedKeygen_RequiresPriorContext verifies PreSharedKeygen
// fails composition when no preceding phase has provided the key
// bundle into context.
func TestPreSharedKeygen_RequiresPriorContext(t *testing.T) {
	_, err := phase.Compose(
		defaults.NewPhase1aSessionInitiation(),
		NewPreSharedKeygen(),
		stubArcPhase("score", defaults.StateGossip, defaults.StateDecrypting,
			phase.ContextSchema{
				defaults.CtxCollectivePublicKey: {TypeName: "[]byte", Required: true},
				defaults.CtxCryptoContract:      {TypeName: "OpenFHEContract", Required: true},
			},
			phase.ContextSchema{defaults.CtxResultCiphertext: {TypeName: "[]byte"}},
		),
		defaults.NewPhase3ThresholdDecrypt(),
	)
	if err == nil {
		t.Fatalf("expected constructor to reject PreSharedKeygen without a preceding context-providing phase")
	}
	ok := strings.Contains(err.Error(), defaults.CtxCollectivePublicKey) ||
		strings.Contains(err.Error(), defaults.CtxSecretShares) ||
		strings.Contains(err.Error(), defaults.CtxEvalKeys) ||
		strings.Contains(err.Error(), defaults.CtxCryptoContract)
	if !ok {
		t.Errorf("expected error about one of [collective_pk, secret_shares, eval_keys, crypto_ctx], got: %v", err)
	}
}

// TestPreSharedKeygen_WithCohortContextSeed verifies that a pipeline
// where a non-inline registration-time phase provides the key bundle
// composes successfully.
func TestPreSharedKeygen_WithCohortContextSeed(t *testing.T) {
	// Pre-shared keys ARE threshold-shaped; the cohort-formation
	// phase that generated them tags topology=threshold so downstream
	// threshold-decrypt phases compose.
	cohortPhase := &staticProviderPhase{
		name:   "cohort-keygen",
		runsAt: phase.RunsAtRegistration,
		provides: phase.ContextSchema{
			ctxCollectivePublicKey: {TypeName: "[]byte", Constraints: map[string]any{"topology": "threshold"}},
			ctxSecretShares:        {TypeName: "map[string][]byte", Constraints: map[string]any{"topology": "threshold"}},
			ctxEvalKeys:            {TypeName: "OpenFHEEvalKeys"},
			ctxCryptoContract:      {TypeName: "OpenFHEContract", Constraints: map[string]any{"depth": 30, "ring_dim": 4096, "scaling_mod_size": 50}},
		},
	}
	_, err := phase.Compose(
		cohortPhase,
		defaults.NewPhase1aSessionInitiation(),
		NewPreSharedKeygen(),
		stubArcPhase("score", defaults.StateGossip, defaults.StateDecrypting,
			phase.ContextSchema{
				defaults.CtxCollectivePublicKey: {TypeName: "[]byte", Required: true},
				defaults.CtxEvalKeys:            {TypeName: "OpenFHEEvalKeys", Required: true},
				defaults.CtxCryptoContract:      {TypeName: "OpenFHEContract", Required: true},
			},
			phase.ContextSchema{defaults.CtxResultCiphertext: {TypeName: "[]byte"}},
		),
		defaults.NewPhase3ThresholdDecrypt(),
	)
	if err != nil {
		t.Fatalf("expected cohort-keygen + PreSharedKeygen pipeline to validate, got: %v", err)
	}
}

// TestPreSharedKeygen_EnterFailsOnMissingKeys verifies the runtime
// guard: Enter returns an error when the required keys are not in
// the context.
func TestPreSharedKeygen_EnterFailsOnMissingKeys(t *testing.T) {
	p := NewPreSharedKeygen()
	ctx := phase.NewSessionContext("test-session")
	err := p.Enter(ctx)
	if err == nil {
		t.Fatalf("expected Enter to fail on empty context")
	}
	if !strings.Contains(err.Error(), "keygen-preshared") &&
		!strings.Contains(err.Error(), ctxCollectivePublicKey) &&
		!strings.Contains(err.Error(), "not set") {
		t.Errorf("unexpected error: %v", err)
	}
}

// staticProviderPhase is a non-inline phase that provides a fixed
// set of context keys and does nothing else.
type staticProviderPhase struct {
	name     string
	runsAt   phase.RunsAt
	provides phase.ContextSchema
}

func (s *staticProviderPhase) Name() string                         { return s.name }
func (s *staticProviderPhase) Lifetime() phase.Lifetime             { return phase.LifetimePerCohort }
func (s *staticProviderPhase) RunsAt() phase.RunsAt                 { return s.runsAt }
func (s *staticProviderPhase) EntryState() phase.SessionState       { return phase.StateNone }
func (s *staticProviderPhase) ExitState() phase.SessionState        { return phase.StateNone }
func (s *staticProviderPhase) InternalStates() []phase.SessionState { return nil }
func (s *staticProviderPhase) ConsumedMessageTypes() []string       { return nil }
func (s *staticProviderPhase) Requires() phase.ContextSchema        { return nil }
func (s *staticProviderPhase) Provides() phase.ContextSchema        { return s.provides }
func (s *staticProviderPhase) Enter(*phase.SessionContext) error    { return nil }
func (s *staticProviderPhase) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (s *staticProviderPhase) CheckComplete(*phase.SessionContext) bool { return true }
func (s *staticProviderPhase) Exit(*phase.SessionContext) error         { return nil }

// stubArcPhase returns a no-op inline phase owning entry → exit with
// the given requires/provides. Used to fill state arcs in test
// pipelines without pulling in app-specific phase implementations.
func stubArcPhase(name string, entry, exit phase.SessionState, req, prov phase.ContextSchema) phase.Phase {
	return &arcStub{name: name, entry: entry, exit: exit, requires: req, provides: prov}
}

type arcStub struct {
	name             string
	entry, exit      phase.SessionState
	requires, provides phase.ContextSchema
}

func (a *arcStub) Name() string                         { return a.name }
func (a *arcStub) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (a *arcStub) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (a *arcStub) EntryState() phase.SessionState       { return a.entry }
func (a *arcStub) ExitState() phase.SessionState        { return a.exit }
func (a *arcStub) InternalStates() []phase.SessionState { return nil }
func (a *arcStub) ConsumedMessageTypes() []string       { return nil }
func (a *arcStub) Requires() phase.ContextSchema        { return a.requires }
func (a *arcStub) Provides() phase.ContextSchema        { return a.provides }
func (a *arcStub) Enter(*phase.SessionContext) error    { return nil }
func (a *arcStub) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (a *arcStub) CheckComplete(*phase.SessionContext) bool { return true }
func (a *arcStub) Exit(*phase.SessionContext) error         { return nil }
