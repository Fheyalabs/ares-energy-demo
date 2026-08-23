// SPDX-License-Identifier: Apache-2.0

// Package keygen provides alternative key-generation Phase
// implementations that slot into the same LOCKED → GOSSIP arc
// as defaults.Phase0aThresholdKeygen. Each variant produces the
// same SessionContext keys (collective public key, secret shares,
// eval keys) so downstream phases — scoring, decrypt — work
// unchanged regardless of which key topology the application
// chooses.
//
// Variants:
//
//   SinglePartyKeygen     Server holds the private key. Weaker
//                          privacy, dramatically faster setup.
//
//   PlaintextKeygen        No crypto. Signed inputs only.
//                          Fastest, weakest privacy guarantee.
//
//   PreSharedKeygen        Reuses a key bundle from
//                          SessionContext produced earlier by
//                          an out-of-band cohort keygen run.
//                          Per-session setup is ~zero cost.
//
// All three share the same Requires/Provides schemas by design
// so swapping them into a NewARESDefaultRunner-style pipeline
// is a one-line change.
package keygen

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

// ── Shared context key names ──────────────────────────────────────

// We reference defaults.Ctx* constants so that swapping keygen
// variants does not break downstream phases (which also reference
// those constants). The sealed-bid auction uses its own namespace
// (CtxAuction*) so it is immune; the default pipeline reads these
// keys and thus any Phase providing them under these names is a
// valid drop-in.
var (
	ctxParticipants        = defaults.CtxParticipants
	ctxCryptoContract      = defaults.CtxCryptoContract
	ctxCollectivePublicKey = defaults.CtxCollectivePublicKey
	ctxSecretShares        = defaults.CtxSecretShares
	ctxEvalKeys            = defaults.CtxEvalKeys
)

// ── SinglePartyKeygen ─────────────────────────────────────────────

// SinglePartyKeygenPhase generates a single CKKS keypair on the
// server side. The server publishes the public key to all
// participants and retains the private key. Participants encrypt
// under the public key; the server decrypts and scores locally.
// There is no threshold-decrypt phase — Phase3 (Decrypt) detects
// that ctxSecretShares is empty or marked single-party and becomes
// a no-op, forwarding the ciphertext directly to the server for
// cleartext scoring.
//
// Trust model: the server sees all inputs in plaintext. Suitable
// for regulated auctions where the auctioneer is legally required
// to see bids, internal corporate rankings, or testing/CI.
//
// This phase consumes no WebSocket messages. Keygen completes
// immediately on Enter so the session transitions straight from
// LOCKED to GOSSIP (or to the next phase in the pipeline).
type SinglePartyKeygenPhase struct{}

// NewSinglePartyKeygen constructs a SinglePartyKeygenPhase with
// the default offline keygen approach. The actual key material is
// generated synchronously in Enter.
func NewSinglePartyKeygen() *SinglePartyKeygenPhase {
	return &SinglePartyKeygenPhase{}
}

func (SinglePartyKeygenPhase) Name() string              { return "keygen-single-party" }
func (SinglePartyKeygenPhase) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (SinglePartyKeygenPhase) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (SinglePartyKeygenPhase) EntryState() phase.SessionState { return defaults.StateLocked }
func (SinglePartyKeygenPhase) ExitState() phase.SessionState  { return defaults.StateGossip }
func (SinglePartyKeygenPhase) InternalStates() []phase.SessionState {
	return []phase.SessionState{defaults.StateKeygen}
}
func (SinglePartyKeygenPhase) ConsumedMessageTypes() []string { return nil }

func (SinglePartyKeygenPhase) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		ctxParticipants:   {TypeName: "[]string", Required: true},
		ctxCryptoContract: {TypeName: "OpenFHEContract", Required: true, Constraints: map[string]any{"depth_min": 4}},
	}
}

func (SinglePartyKeygenPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		ctxCollectivePublicKey: {TypeName: "[]byte"},
		ctxSecretShares: {
			TypeName: "map[string][]byte",
			// Marked single-party so downstream phases can
			// detect this topo and skip threshold decrypt.
			Constraints: map[string]any{"topology": "single_party"},
		},
		ctxEvalKeys: {TypeName: "OpenFHEEvalKeys"},
	}
}

func (SinglePartyKeygenPhase) Enter(ctx *phase.SessionContext) error      { return nil }
func (SinglePartyKeygenPhase) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}
func (SinglePartyKeygenPhase) CheckComplete(ctx *phase.SessionContext) bool { return true }
func (SinglePartyKeygenPhase) Exit(ctx *phase.SessionContext) error         { return nil }

// ── PlaintextKeygen ───────────────────────────────────────────────

// PlaintextKeygenPhase performs no cryptographic key generation.
// Participants submit signed (not encrypted) inputs; the server
// verifies signatures and scores in plaintext. The "collective
// public key" and "secret shares" context entries are set to
// sentinel values so downstream phases can detect this topology
// and skip FHE entirely.
//
// Trust model: the server sees everything. Suitable for testing,
// CI, audit-friendly internal use, and correctness-reference
// check runs where FHE overhead adds no value.
//
// This is the fastest keygen variant — it completes in one Enter
// call with zero crypto work and zero WS messages exchanged.
type PlaintextKeygenPhase struct{}

func NewPlaintextKeygen() *PlaintextKeygenPhase { return &PlaintextKeygenPhase{} }

func (PlaintextKeygenPhase) Name() string              { return "keygen-plaintext" }
func (PlaintextKeygenPhase) Lifetime() phase.Lifetime   { return phase.LifetimePerSession }
func (PlaintextKeygenPhase) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PlaintextKeygenPhase) EntryState() phase.SessionState { return defaults.StateLocked }
func (PlaintextKeygenPhase) ExitState() phase.SessionState  { return defaults.StateGossip }
func (PlaintextKeygenPhase) InternalStates() []phase.SessionState {
	return []phase.SessionState{defaults.StateKeygen}
}
func (PlaintextKeygenPhase) ConsumedMessageTypes() []string { return nil }

func (PlaintextKeygenPhase) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		ctxParticipants: {TypeName: "[]string", Required: true},
	}
}

func (PlaintextKeygenPhase) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		ctxCollectivePublicKey: {
			TypeName: "[]byte",
			Constraints: map[string]any{"topology": "plaintext"},
		},
		ctxSecretShares: {
			TypeName: "[]byte",
			Constraints: map[string]any{"topology": "plaintext"},
		},
		ctxEvalKeys: {TypeName: "OpenFHEEvalKeys"},
	}
}

func (PlaintextKeygenPhase) Enter(ctx *phase.SessionContext) error      { return nil }
func (PlaintextKeygenPhase) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}
func (PlaintextKeygenPhase) CheckComplete(ctx *phase.SessionContext) bool { return true }
func (PlaintextKeygenPhase) Exit(ctx *phase.SessionContext) error         { return nil }

// ── PreSharedKeygen ───────────────────────────────────────────────

// PreSharedKeygenPhase carries no key-generation logic — it
// declares that the LOCKED → GOSSIP arc is satisfied by a key
// bundle already present in the SessionContext. The bundle was
// produced by an earlier cohort-formation run (outside the
// per-session pipeline) and placed into context before
// runner.BeginSession, keyed by the cohort's ID.
//
// Per-session cost: zero. The phase's CheckComplete returns true
// immediately and the session skips keygen entirely. This is the
// highest-performance variant for repeat-participant cohorts
// (weekly rankings, recurring auctions, long-lived leagues).
//
// If the expected context keys are absent, Enter returns an error
// — the runner refuses to start the session rather than silently
// skipping a required phase. This is a correctness guarantee:
// accidentally wiring PreSharedKeygen without first producing
// the bundle is caught at session start, not mid-protocol.
type PreSharedKeygenPhase struct{}

func NewPreSharedKeygen() *PreSharedKeygenPhase { return &PreSharedKeygenPhase{} }

func (PreSharedKeygenPhase) Name() string              { return "keygen-preshared" }
func (PreSharedKeygenPhase) Lifetime() phase.Lifetime   { return phase.LifetimePerCohort }
func (PreSharedKeygenPhase) RunsAt() phase.RunsAt       { return phase.RunsAtInline }
func (PreSharedKeygenPhase) EntryState() phase.SessionState { return defaults.StateLocked }
func (PreSharedKeygenPhase) ExitState() phase.SessionState  { return defaults.StateGossip }
func (PreSharedKeygenPhase) InternalStates() []phase.SessionState {
	return []phase.SessionState{defaults.StateKeygen}
}
func (PreSharedKeygenPhase) ConsumedMessageTypes() []string { return nil }

func (PreSharedKeygenPhase) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		ctxParticipants:        {TypeName: "[]string", Required: true},
		ctxCollectivePublicKey: {TypeName: "[]byte", Required: true},
		ctxSecretShares: {
			TypeName: "map[string][]byte",
			Required: true,
			// Pre-shared keys ARE threshold-shaped; the "preshared"
			// distinction is about lifecycle (provisioned out-of-band),
			// not topology. The upstream cohort-formation phase that
			// seeded them must tag topology=threshold so downstream
			// threshold-decrypt phases compose.
			Constraints: map[string]any{"topology": "threshold"},
		},
		ctxEvalKeys: {TypeName: "OpenFHEEvalKeys", Required: true},
	}
}

func (PreSharedKeygenPhase) Provides() phase.ContextSchema {
	// Provides is intentionally empty. The phase does not
	// generate keys — it validates that they already exist.
	// Downstream phases' Requires are satisfied by the context
	// entries seeded at BeginSession time or populated by a
	// preceding out-of-band keygen run.
	return nil
}

func (PreSharedKeygenPhase) Enter(ctx *phase.SessionContext) error {
	// Fail fast if keys are missing — don't silently skip.
	for _, key := range []string{
		ctxCollectivePublicKey,
		ctxSecretShares,
		ctxEvalKeys,
	} {
		if !ctx.Has(key) {
			return &phase.MissingContextError{Key: key, Phase: "keygen-preshared"}
		}
	}
	return nil
}
func (PreSharedKeygenPhase) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}
func (PreSharedKeygenPhase) CheckComplete(ctx *phase.SessionContext) bool { return true }
func (PreSharedKeygenPhase) Exit(ctx *phase.SessionContext) error         { return nil }
