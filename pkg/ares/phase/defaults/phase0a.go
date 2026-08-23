// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase0aThresholdKeygen is ARES v2.4 §"Phase 0a — Per-Session
// Threshold Key Generation". N participants perform a chained
// multiparty CKKS keygen producing the collective public key, each
// participant's secret share, and the joint evaluation keys
// (eval-mult, eval-sum) needed for Phase 2 homomorphic operations.
//
// The phase owns the LOCKED → GOSSIP arc and consumes the key-generation
// messages. Inside the phase the engine drives the internal
// keygen-share / eval-round1 / eval-round2 sub-flow; from the
// framework's perspective those are accumulation events within one
// arc. When all participants have submitted their final shares and
// the orchestrator has assembled the joint material, CheckComplete
// returns true and the phase transitions to Phase G (Gossip).
//
// Alternative implementations of this phase shape:
//   - Phase0aPersistentKeygen: same Provides, but RunsAtRegistration
//     and LifetimePerCohort — the key bundle is generated once at
//     cohort formation, the per-session pipeline skips Phase0a
//     entirely (the runner detects the satisfied context).
//   - Phase0aSinglePartyKeygen: server generates a single keypair,
//     hands the public key to participants. No threshold decrypt
//     downstream. Weaker privacy but vastly faster.
//   - Phase0aPlaintextKeygen: no-op. Inputs are signed, not
//     encrypted.
type Phase0aThresholdKeygen struct{}

func NewPhase0aThresholdKeygen() *Phase0aThresholdKeygen {
	return &Phase0aThresholdKeygen{}
}

func (Phase0aThresholdKeygen) Name() string                   { return "phase-0a-threshold-keygen" }
func (Phase0aThresholdKeygen) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase0aThresholdKeygen) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase0aThresholdKeygen) EntryState() phase.SessionState { return StateLocked }
func (Phase0aThresholdKeygen) ExitState() phase.SessionState  { return StateGossip }

// InternalStates declares that Phase 0a covers the engine's KEYGEN
// sub-state in addition to its LOCKED EntryState. The legacy ARES
// engine moves LOCKED → KEYGEN on the first KeyShareSubmitted and
// then accumulates remaining shares + eval-round-1 + eval-round-2
// within KEYGEN before transitioning to GOSSIP on KeygenComplete.
// The framework folds that whole sequence into one logical phase;
// declaring KEYGEN as internal here lets the SessionRunner's
// PhaseForState lookup and AdvanceToState walker recognize KEYGEN
// as "still inside Phase 0a" instead of a missing state.
func (Phase0aThresholdKeygen) InternalStates() []phase.SessionState {
	return []phase.SessionState{StateKeygen}
}

func (Phase0aThresholdKeygen) ConsumedMessageTypes() []string {
	// keygen.share carries both the PK-only (Phase A) and PK+eval
	// (Phase B) variants from the two-phase keygen split landed in
	// commit 93ecadb. The phase implementation distinguishes them
	// by inspecting payload fields; the WS routing only cares
	// about the type string.
	//
	// keygen.eval_round1 is the intermediate evaluation-key contribution.
	// keygen.eval_share is the eval-round-2 final share each
	// participant emits after the server broadcasts
	// keygen.eval_round1_complete. All eval shares for the session
	// belong to this same phase — they accumulate inside the
	// LOCKED → GOSSIP arc, transitioning out only when the
	// orchestrator has fused the round-2 shares into the joint
	// evaluation keys.
	return []string{"keygen.share", "keygen.eval_round1", "keygen.eval_share"}
}

func (Phase0aThresholdKeygen) Requires() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {
			TypeName: "[]string",
			Required: true,
		},
		CtxCryptoContract: {
			TypeName: "OpenFHEContract",
			Required: true,
			Constraints: map[string]any{
				"depth_min": 4,
			},
		},
	}
}

func (Phase0aThresholdKeygen) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxCollectivePublicKey: {
			TypeName:    "[]byte",
			Constraints: map[string]any{"topology": "threshold"},
		},
		CtxSecretShares: {
			TypeName:    "map[string][]byte",
			Constraints: map[string]any{"topology": "threshold"},
		},
		CtxEvalKeys: {
			TypeName: "OpenFHEEvalKeys",
		},
	}
}

func (Phase0aThresholdKeygen) Enter(ctx *phase.SessionContext) error { return nil }
func (Phase0aThresholdKeygen) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}
func (Phase0aThresholdKeygen) CheckComplete(ctx *phase.SessionContext) bool { return false }
func (Phase0aThresholdKeygen) Exit(ctx *phase.SessionContext) error         { return nil }
