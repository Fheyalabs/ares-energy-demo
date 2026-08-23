// SPDX-License-Identifier: Apache-2.0

package phase

// Phase is the abstract unit of session work. A SessionRunner composes
// a list of Phases and drives them in order; each Phase owns one
// session state, the WebSocket message types associated with that
// state, and the work that transitions the session to the next state.
//
// Implementations should be stateless across sessions: per-session
// state lives in the SessionContext passed to each hook. Phase value
// itself holds only configuration (parameters, registered handlers,
// crypto-context bounds) — the runner shares one Phase instance across
// every session that uses it.
//
// The lifecycle for a per-session inline phase is:
//
//	1. SessionRunner enters the phase's EntryState. Runner calls Enter.
//	2. For each WebSocket message of a type listed in ConsumedMessageTypes,
//	   the runner calls OnMessage.
//	3. After each OnMessage call, the runner asks CheckComplete whether
//	   the phase has accumulated enough to transition.
//	4. When CheckComplete returns true, the runner calls Exit (which
//	   writes the phase's Provides into the SessionContext) and then
//	   transitions the session to ExitState.
//
// Phases with RunsAt != RunsAtInline have a simplified lifecycle: the
// runner (or a separate registration-time driver) invokes Enter, the
// phase does its work synchronously or asynchronously and writes its
// outputs to the context, and Exit is called. EntryState and ExitState
// are StateNone in that case.
type Phase interface {
	// Name returns a stable identifier for this phase. Used in logs,
	// diagnostics, and the derived state-machine label. Must be
	// unique within a SessionRunner.
	Name() string

	// Lifetime declares how long this phase's outputs persist.
	Lifetime() Lifetime

	// RunsAt declares when this phase executes.
	RunsAt() RunsAt

	// EntryState is the session state that triggers this phase's
	// inline execution. StateNone for non-inline phases.
	EntryState() SessionState

	// ExitState is the state the session transitions to when this
	// phase completes. StateNone for non-inline phases or for the
	// terminal phase of a runner.
	ExitState() SessionState

	// InternalStates returns sub-states that the phase covers
	// internally without advancing. Some protocols use multiple
	// fine-grained engine states for one logical phase — for
	// example ARES has LOCKED ("ready to start keygen") and
	// KEYGEN ("accumulating shares") as distinct sub-states of
	// the single keygen phase. The framework runner treats
	// EntryState plus every value in InternalStates as
	// "still inside this phase" for state-lookup and
	// AdvanceToState purposes. Returning nil is fine for phases
	// without sub-states.
	InternalStates() []SessionState

	// ConsumedMessageTypes lists the WebSocket message types this
	// phase handles via OnMessage. The runner routes inbound
	// messages by intersecting current-phase consumption with the
	// message type. Empty for phases that do not consume WS
	// messages (for example, server-side compute phases driven by
	// the orchestrator).
	ConsumedMessageTypes() []string

	// Requires returns the SessionContext keys this phase reads.
	// The runner verifies that some preceding phase in the runner
	// produces every required key with constraints that satisfy
	// this phase's expectations.
	Requires() ContextSchema

	// Provides returns the SessionContext keys this phase writes
	// during Enter, OnMessage, or Exit. The runner uses these to
	// build the chain of context dependencies.
	Provides() ContextSchema

	// Enter is called once when the session enters this phase's
	// EntryState (or, for non-inline phases, when the phase is
	// dispatched). Use it to read Requires from ctx and prepare
	// internal state. Returning an error aborts the session.
	Enter(ctx *SessionContext) error

	// OnMessage is called once per inbound WebSocket message whose
	// type is in ConsumedMessageTypes and whose session_id matches
	// ctx.SessionID. The from string carries the sender's pseudonym
	// and payload is the raw JSON body. Implementations should
	// accumulate state in ctx (or in a phase-local map keyed by
	// SessionID for short-lived bookkeeping) and not block on
	// network calls; spawn goroutines for any blocking work.
	OnMessage(ctx *SessionContext, msgType string, from string, payload []byte) error

	// CheckComplete returns true when the phase's accumulated state
	// is sufficient to transition. Called after every OnMessage. A
	// phase that completes without any messages (for example, a
	// pure compute phase triggered in Enter) returns true on the
	// very first check.
	CheckComplete(ctx *SessionContext) bool

	// Exit is called once when CheckComplete first returns true.
	// Use it to write final outputs into ctx (the Provides keys)
	// and to release any in-phase resources. Returning an error
	// aborts the session.
	Exit(ctx *SessionContext) error
}
