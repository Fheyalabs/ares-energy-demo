// SPDX-License-Identifier: Apache-2.0

// Package phase defines the core abstractions for composing ARES sessions
// out of pluggable units of work. A SessionRunner is a list of Phases;
// each Phase declares the session state it owns, the WebSocket message
// types it consumes, the SessionContext keys it reads and produces, and
// when its work happens in the session lifecycle. The state machine that
// drives an ARES session is derived from the registered phase list, not
// hardcoded.
//
// This package is intended to be the public API surface of the ARES
// framework. Application authors build a SessionRunner with the default
// phases shipped here, with custom phases, or with mixes of both, then
// hand the runner to a session-service binary that wires it into the
// WebSocket transport and artifact store.
//
// This file defines the small typed enums and schema shapes that the
// Phase interface references. Nothing here imports the existing
// internal/engine packages — phase is the new abstraction layer; the
// existing engine will be re-expressed in terms of it in a follow-on
// task.
package phase

// Lifetime declares how long a phase's outputs persist relative to a
// session. Phases with non-per-session lifetimes can be skipped by the
// runner when their outputs are already in the SessionContext.
type Lifetime string

const (
	// LifetimePerSession is the default. Outputs are scoped to one
	// session and discarded at session end.
	LifetimePerSession Lifetime = "per-session"

	// LifetimePerCohort scopes outputs to a long-lived cohort of the
	// same N participants. A cohort key bundle, for example, can be
	// generated once at cohort formation and reused across many
	// session runs.
	LifetimePerCohort Lifetime = "per-cohort"

	// LifetimePersistent scopes outputs to the participant or to the
	// service itself, surviving across many cohorts and sessions.
	LifetimePersistent Lifetime = "persistent"
)

// RunsAt declares when a phase executes within the participant or
// session lifecycle.
type RunsAt string

const (
	// RunsAtRegistration runs once when the participant joins the
	// service (or the cohort forms). Useful for amortizing heavy work
	// that does not need to be repeated per session.
	RunsAtRegistration RunsAt = "registration"

	// RunsAtSessionStart runs once at the start of a session, before
	// any inline phase. Useful for per-session setup that cannot be
	// amortized.
	RunsAtSessionStart RunsAt = "session-start"

	// RunsAtInline runs during the session, gated by entry state and
	// consumed message types. Most ARES phases run inline.
	RunsAtInline RunsAt = "inline"
)

// SessionState is the type for session state labels. Phases declare
// their EntryState (the state they handle) and ExitState (the state
// they transition to on completion). The runner builds a state machine
// from these declarations.
type SessionState string

// StateNone is the sentinel used by phases that do not participate in
// the inline state machine (for example, registration-time phases).
const StateNone SessionState = ""

// ContextSchema declares the typed shape of SessionContext keys a phase
// reads or produces. The runner uses this for compatibility validation
// at registration time: if phase B requires key K with constraint C but
// no preceding phase produces K satisfying C, the runner refuses to
// start.
//
// Schemas are intentionally loose at this layer — keys are string-named
// and values are described by a free-form ContextKeyType. Concrete
// applications attach typed accessors on top.
type ContextSchema map[string]ContextKeyType

// ContextKeyType describes one ContextSchema entry. TypeName is a
// human-readable identifier (for example "OpenFHEContract" or
// "[]byte"); Constraints carries phase-specific minimums and shape
// requirements that the runner can compare structurally.
type ContextKeyType struct {
	// TypeName is the Go-level type name (or any stable identifier)
	// the producer commits to write into the context under this key.
	TypeName string

	// Required indicates whether the consumer can proceed without
	// this key being present. Producers always treat their entries
	// as required-to-emit; the flag only applies on the consumer
	// side.
	Required bool

	// Constraints is a free-form map of constraint-name to expected
	// value. For example a scoring phase may declare
	// {"depth_min": 20} for the "crypto_ctx" key it consumes; a
	// keygen phase may declare {"depth": 30} for the same key it
	// produces. The runner cross-references them at startup.
	Constraints map[string]any

	// NoLineage opts this context key out of SC-10 ciphertext
	// lineage when the runner is constructed via
	// phase.ComposeWith. Default false means lineage IS enforced.
	// Set true for ephemeral or public values that need not be
	// cryptographically bound (e.g. heartbeat flags, public
	// broadcast constants). Auditable from one place: grep
	// "NoLineage: true" across the codebase finds every escape
	// hatch. Compose-built runners ignore the field entirely
	// (legacy lineage-disabled path).
	NoLineage bool
}
