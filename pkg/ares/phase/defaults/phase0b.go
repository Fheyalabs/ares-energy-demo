// SPDX-License-Identifier: Apache-2.0

package defaults

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

// Phase0bRegistration is the registration-time phase from ARES v2.4
// §"Phase 0b — Registration". A participant registers with the
// session service one time, producing a long-lived pseudonym, the
// participant's long-term key (lk_pub), device public key, blind
// credential, and uniqueness nullifier. This phase runs outside any
// session — it is invoked over HTTP rather than through the
// SessionRunner's inline state machine.
//
// In the framework abstraction this is a non-inline phase
// (RunsAt=Registration, EntryState=StateNone). The runner does not
// route WebSocket messages here. A registration driver in the
// session-service binary instantiates the phase, drives its Enter
// hook with a request-derived SessionContext, and writes the
// resulting identity record into a participant store. Subsequent
// per-session SessionContexts carry the participant's identity in
// from that store rather than being produced by this phase
// per-session.
type Phase0bRegistration struct{}

// NewPhase0bRegistration constructs the default registration phase
// with empty configuration. App authors that need to customize
// credential validation (for example a blind-signature credential
// vs an HMAC-shaped invite credential) should compose this phase's
// hooks with their own validator.
func NewPhase0bRegistration() *Phase0bRegistration {
	return &Phase0bRegistration{}
}

func (Phase0bRegistration) Name() string                   { return "phase-0b-registration" }
func (Phase0bRegistration) Lifetime() phase.Lifetime       { return phase.LifetimePersistent }
func (Phase0bRegistration) RunsAt() phase.RunsAt           { return phase.RunsAtRegistration }
func (Phase0bRegistration) EntryState() phase.SessionState { return phase.StateNone }
func (Phase0bRegistration) ExitState() phase.SessionState  { return phase.StateNone }
func (Phase0bRegistration) ConsumedMessageTypes() []string       { return nil }
func (Phase0bRegistration) InternalStates() []phase.SessionState { return nil }

func (Phase0bRegistration) Requires() phase.ContextSchema { return nil }

// Provides emits the participant identity record (pseudonym, lk_pub,
// device_pk, credential, nullifier) into the context. Downstream
// per-session phases read this record indirectly via the
// SessionContext seeded by the runner from the participant store —
// they don't co-locate in the same context object as the
// registration call.
func (Phase0bRegistration) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		"participant_identity": {TypeName: "ParticipantIdentity"},
	}
}

// Enter is the registration handler. Today's implementation lives in
// internal/auth and the /v2/register HTTP handler; in the framework
// the binary delegates here. The follow-on logic port wires this
// hook to the existing handler. For now the hook is a no-op
// placeholder so the abstraction compiles and composes.
func (Phase0bRegistration) Enter(ctx *phase.SessionContext) error {
	return nil
}

func (Phase0bRegistration) OnMessage(ctx *phase.SessionContext, msgType, from string, payload []byte) error {
	return nil
}

func (Phase0bRegistration) CheckComplete(ctx *phase.SessionContext) bool {
	return true
}

func (Phase0bRegistration) Exit(ctx *phase.SessionContext) error {
	return nil
}
