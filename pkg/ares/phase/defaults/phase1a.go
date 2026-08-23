// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase1aSessionInitiation is ARES v2.4 §"Phase 1a — Session
// Initiation". The coordinator selects N eligible participants from
// the queue, builds the session record, emits `session.invitation`
// to each, and waits for the locked acknowledgement before
// transitioning out of INVITING. In the framework the phase owns
// the INVITING → LOCKED arc and produces the participant list plus
// the crypto contract (parameters every later phase needs).
//
// Today's implementation lives in internal/engine/coordinator.go;
// the body of this phase is a placeholder until the logic port.
type Phase1aSessionInitiation struct{}

func NewPhase1aSessionInitiation() *Phase1aSessionInitiation {
	return &Phase1aSessionInitiation{}
}

func (Phase1aSessionInitiation) Name() string                   { return "phase-1a-session-initiation" }
func (Phase1aSessionInitiation) Lifetime() phase.Lifetime       { return phase.LifetimePerSession }
func (Phase1aSessionInitiation) RunsAt() phase.RunsAt           { return phase.RunsAtInline }
func (Phase1aSessionInitiation) EntryState() phase.SessionState { return StateInviting }
func (Phase1aSessionInitiation) ExitState() phase.SessionState  { return StateLocked }

// ConsumedMessageTypes covers participant acceptances. After the
// coordinator broadcasts `session.invitation`, each invited
// participant replies with `session.accept` over the WebSocket; the
// session leaves INVITING for LOCKED when every participant has
// accepted.
func (Phase1aSessionInitiation) ConsumedMessageTypes() []string {
	return []string{"session.accept"}
}
func (Phase1aSessionInitiation) InternalStates() []phase.SessionState { return nil }

func (Phase1aSessionInitiation) Requires() phase.ContextSchema { return nil }

func (Phase1aSessionInitiation) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		CtxParticipants: {
			TypeName: "[]string",
			Required: false,
		},
		CtxCryptoContract: {
			TypeName: "OpenFHEContract",
			Required: false,
			// Default contract emitted by Phase 1a is depth=30,
			// ring_dim=4096 is a reasonable starting point for a unit-norm profile vector. Apps with
			// different scoring circuits override this phase to
			// emit different contract parameters.
			Constraints: map[string]any{
				"depth":            30,
				"ring_dim":         4096,
				"scaling_mod_size": 50,
			},
		},
	}
}

func (Phase1aSessionInitiation) Enter(ctx *phase.SessionContext) error      { return nil }
func (Phase1aSessionInitiation) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}
func (Phase1aSessionInitiation) CheckComplete(ctx *phase.SessionContext) bool { return true }
func (Phase1aSessionInitiation) Exit(ctx *phase.SessionContext) error         { return nil }
