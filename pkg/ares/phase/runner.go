// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// SessionRunner composes a list of Phases into one session pipeline.
// The runner derives the session state machine from the registered
// phase list (no hardcoded transitions), routes inbound WebSocket
// messages to whichever phase declares interest in the current state,
// and drives each phase through its Enter / OnMessage / Exit
// lifecycle.
//
// One SessionRunner instance is shared across every concurrent
// session using the same pipeline; per-session state lives in the
// SessionContext, not on the runner. The runner is safe for
// concurrent use by many goroutines, one per active session.
//
// Construction is via Compose, which validates the phase
// list before returning. A misconfigured pipeline (missing required
// context, duplicate names, ambiguous entry states, unsatisfiable
// constraint chain) returns an error immediately so misconfigurations
// fail fast at service startup rather than at session start.
type SessionRunner struct {
	phases          []Phase
	byName          map[string]Phase
	byEntryState    map[SessionState]Phase
	byInternalState map[SessionState]Phase

	// initialState is the EntryState of the first inline phase.
	initialState SessionState

	mu       sync.RWMutex
	sessions map[string]*sessionTracker

	// Lineage state (populated by ComposeWith via attachLineage;
	// nil for Compose-built runners, which skip lineage and behave
	// identically to v0.3.x).
	lineageStore       lineage.Store
	lineageSigner      sign.Signer
	lineageVerifiers   map[string]sign.Signer
	lineageFailureHook LineageFailureFn
}

// attachLineage stashes lineage state on the runner for use by the
// auto-wrap dispatch hooks. Called by ComposeWith. The hooks
// themselves (pre-OnMessage verification in HandleLineageMessage,
// post-Exit auto-commit in commitPhaseOutputs) land in
// runner_lineage.go.
func (r *SessionRunner) attachLineage(
	store lineage.Store,
	signer sign.Signer,
	verifiers map[string]sign.Signer,
	hook LineageFailureFn,
) {
	r.lineageStore = store
	r.lineageSigner = signer
	r.lineageVerifiers = verifiers
	r.lineageFailureHook = hook
}

// sessionTracker keeps the per-session, per-runner state needed to
// dispatch messages and drive transitions. It is internal to the
// runner; phases see only the SessionContext.
type sessionTracker struct {
	ctx     *SessionContext
	state   SessionState
	current Phase
	entered bool // whether Enter has been called for current
}

// Compose constructs a runner over the given ordered phase
// list. The order matters: it defines the canonical pipeline
// execution sequence used to derive the state machine and to validate
// that each phase's Requires are satisfied by some preceding phase's
// Provides.
//
// Use ComposeWith(...) instead when SC-10 ciphertext lineage is
// required. Compose-built runners emit v1 wire frames without
// Lineage and skip the auto-commit / verify-before-dispatch flow.
//
// Validation rules enforced here:
//   - Phase names are unique within the runner.
//   - Every inline phase's Requires keys are produced by some
//     preceding phase (inline or non-inline).
//   - Producer Constraints satisfy consumer Constraints. The default
//     rule is structural equality on each constraint key; numeric
//     constraints follow the convention "<name>_min" on consumers vs
//     "<name>" on producers (consumer requires producer's value >=
//     consumer's minimum).
//   - Inline phases form a chain: ExitState of phase k equals
//     EntryState of phase k+1 (in inline order). The terminal inline
//     phase may have ExitState = StateNone.
//
// Returns an error wrapped with ErrPermanent for any validation
// failure. Apps should fail-fast on Compose errors (config bug,
// no retry possible).
func Compose(phases ...Phase) (*SessionRunner, error) {
	if len(phases) == 0 {
		return nil, fmt.Errorf("%w: Compose needs at least one phase", ErrPermanent)
	}

	r := &SessionRunner{
		phases:          append([]Phase(nil), phases...),
		byName:          make(map[string]Phase, len(phases)),
		byEntryState:    make(map[SessionState]Phase),
		byInternalState: make(map[SessionState]Phase),
		sessions:        make(map[string]*sessionTracker),
	}

	provided := make(map[string]ContextKeyType)

	var prevInline Phase
	for _, p := range phases {
		name := p.Name()
		if name == "" {
			return nil, fmt.Errorf("%w: Compose: phase has empty Name() (index %d in pipeline)", ErrPermanent, len(r.byName))
		}
		if _, dup := r.byName[name]; dup {
			return nil, fmt.Errorf("%w: Compose: duplicate phase name %q", ErrPermanent, name)
		}
		r.byName[name] = p

		if err := validateRequires(name, p.Requires(), provided); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrPermanent, err)
		}
		for k, t := range p.Provides() {
			provided[k] = t
		}

		if p.RunsAt() == RunsAtInline {
			entry := p.EntryState()
			if entry == StateNone {
				return nil, fmt.Errorf("%w: phase %q: inline phase needs an EntryState", ErrPermanent, name)
			}
			if existing, ok := r.byEntryState[entry]; ok {
				return nil, fmt.Errorf("%w: phase: entry state %q claimed by both %q and %q", ErrPermanent, entry, existing.Name(), name)
			}
			r.byEntryState[entry] = p

			for _, sub := range p.InternalStates() {
				if sub == StateNone {
					return nil, fmt.Errorf("%w: phase %q: InternalStates contains StateNone", ErrPermanent, name)
				}
				if sub == entry {
					return nil, fmt.Errorf("%w: phase %q: InternalStates duplicates EntryState %q", ErrPermanent, name, sub)
				}
				if existing, ok := r.byEntryState[sub]; ok {
					return nil, fmt.Errorf("%w: phase %q: internal state %q is also EntryState of %q", ErrPermanent, name, sub, existing.Name())
				}
				if existing, ok := r.byInternalState[sub]; ok {
					return nil, fmt.Errorf("%w: phase %q: internal state %q is also an internal state of %q", ErrPermanent, name, sub, existing.Name())
				}
				r.byInternalState[sub] = p
			}

			if prevInline == nil {
				r.initialState = entry
			} else if prevInline.ExitState() != entry {
				return nil, fmt.Errorf("%w: phase: %q.ExitState=%q but %q.EntryState=%q — pipeline is not connected",
					ErrPermanent, prevInline.Name(), prevInline.ExitState(), name, entry)
			}
			prevInline = p
		} else {
			// Non-inline phases must not declare states. They run
			// out of band; their outputs flow through context.
			if p.EntryState() != StateNone || p.ExitState() != StateNone {
				return nil, fmt.Errorf("%w: phase %q: non-inline phases must have StateNone for entry and exit", ErrPermanent, name)
			}
		}
	}

	return r, nil
}

func validateRequires(phaseName string, reqs ContextSchema, provided map[string]ContextKeyType) error {
	for key, want := range reqs {
		got, ok := provided[key]
		if !ok {
			if want.Required {
				return fmt.Errorf("phase %q: requires context key %q but no preceding phase provides it", phaseName, key)
			}
			continue
		}
		if want.TypeName != "" && got.TypeName != "" && want.TypeName != got.TypeName {
			return fmt.Errorf("phase %q: context key %q has provided type %q, required type %q",
				phaseName, key, got.TypeName, want.TypeName)
		}
		if err := checkConstraints(phaseName, key, want.Constraints, got.Constraints); err != nil {
			return err
		}
	}
	return nil
}

// checkConstraints applies the "<name>_min" / "<name>" numeric
// convention plus structural equality on other keys.
func checkConstraints(phaseName, key string, want, got map[string]any) error {
	for cname, cval := range want {
		if cname == "" {
			continue
		}
		if minName := cname; len(minName) > 4 && minName[len(minName)-4:] == "_min" {
			producerKey := minName[:len(minName)-4]
			gv, ok := got[producerKey]
			if !ok {
				return fmt.Errorf("phase %q: context key %q requires minimum %s but producer omits %s",
					phaseName, key, cname, producerKey)
			}
			ok, err := atLeast(gv, cval)
			if err != nil {
				return fmt.Errorf("phase %q: context key %q constraint %s: %w", phaseName, key, cname, err)
			}
			if !ok {
				return fmt.Errorf("phase %q: context key %q requires %s=%v but producer provides %s=%v",
					phaseName, key, cname, cval, producerKey, gv)
			}
			continue
		}
		gv, ok := got[cname]
		if !ok {
			return fmt.Errorf("phase %q: context key %q requires constraint %s but producer omits it",
				phaseName, key, cname)
		}
		if !equalConstraint(gv, cval) {
			return fmt.Errorf("phase %q: context key %q constraint %s: producer=%v, required=%v",
				phaseName, key, cname, gv, cval)
		}
	}
	return nil
}

func atLeast(a, b any) (bool, error) {
	af, aok := asFloat(a)
	bf, bok := asFloat(b)
	if !aok || !bok {
		return false, fmt.Errorf("non-numeric values %v (%T) vs %v (%T)", a, a, b, b)
	}
	return af >= bf, nil
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	default:
		return 0, false
	}
}

func equalConstraint(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// Phases returns a snapshot of the runner's phase list in order.
func (r *SessionRunner) Phases() []Phase {
	return append([]Phase(nil), r.phases...)
}

// InitialState returns the EntryState of the first inline phase.
// Sessions begin in this state.
func (r *SessionRunner) InitialState() SessionState {
	return r.initialState
}

// PhaseForState returns the inline phase that owns the given session
// state — either as its EntryState or as one of its declared
// InternalStates. The second return value is false when no inline
// phase claims the state (typically the terminal "done" state).
func (r *SessionRunner) PhaseForState(s SessionState) (Phase, bool) {
	if p, ok := r.byEntryState[s]; ok {
		return p, true
	}
	if p, ok := r.byInternalState[s]; ok {
		return p, true
	}
	return nil, false
}

// BeginSession creates a tracker for a new session, places it in the
// initial state, and calls Enter on the first inline phase. Returns
// the SessionContext so the caller can seed cohort-lifetime context
// values before any messages arrive.
//
// Load-bearing behavior: BeginSession does NOT cascade past the
// initial phase even if that phase's CheckComplete returns true.
// This is intentional — the typical caller (a SessionTrigger
// implementation) needs to ctx.Set canonical context entries
// AFTER BeginSession returns and BEFORE the second phase's Enter
// runs (because Enter-time validation patterns like
// PhasePreSharedKeyLookup check runtime ctx for required keys).
// Use AdvanceToState(...) to walk into the first
// message-consuming phase once the trigger has seeded its
// context.
//
// Errors:
//   - ErrPermanent: empty sessionID; session already active.
//   - ErrFrameworkBug: no phase claims the runner's initialState
//     (indicates a Compose() / ComposeWith() bug, since both
//     constructors set initialState from a phase's EntryState).
//   - phase.Enter pass-through (the first phase's own error).
func (r *SessionRunner) BeginSession(sessionID, cohortID string) (*SessionContext, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: BeginSession requires non-empty sessionID", ErrPermanent)
	}
	r.mu.Lock()
	if _, exists := r.sessions[sessionID]; exists {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: BeginSession: session %q is already active", ErrPermanent, sessionID)
	}
	ctx := NewSessionContext(sessionID)
	ctx.CohortID = cohortID
	ctx.lineageStore = r.lineageStore   // nil for Compose-built runners
	ctx.lineageSigner = r.lineageSigner // nil for Compose-built runners
	first, ok := r.byEntryState[r.initialState]
	if !ok {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: BeginSession: no phase claims initial state %q", ErrFrameworkBug, r.initialState)
	}
	tracker := &sessionTracker{
		ctx:     ctx,
		state:   r.initialState,
		current: first,
	}
	r.sessions[sessionID] = tracker
	r.mu.Unlock()

	if err := first.Enter(ctx); err != nil {
		r.mu.Lock()
		delete(r.sessions, sessionID)
		r.mu.Unlock()
		return nil, fmt.Errorf("phase %q: Enter: %w", first.Name(), err)
	}
	r.mu.Lock()
	tracker.entered = true
	r.mu.Unlock()
	// Note: BeginSession does NOT cascade past the initial phase even
	// if its CheckComplete is true. Callers (typically a SessionTrigger
	// implementation) seed canonical context entries via ctx.Set after
	// BeginSession returns, and then call AdvanceToState to walk into
	// the first message-consuming phase. Cascading here would call
	// the second phase's Enter before the trigger seeded context, which
	// breaks Enter-time validation patterns like
	// PhasePreSharedKeyLookup that check runtime ctx for required keys.
	return ctx, nil
}

// HandleMessage routes an inbound WS message to the current phase for
// the named session. Returns (transitioned, error). When transitioned
// is true, the session's state has advanced and the next phase's
// Enter has been called.
//
// Use HandleLineageMessage instead for runners built with
// ComposeWith(...) — HandleMessage on a lineage-enabled runner
// works (legacy passthrough) but skips lineage verification.
//
// Errors:
//   - ErrPermanent: session not active; current phase does not
//     consume msgType in its current state.
//   - phase.{OnMessage,Exit,Enter} pass-through: the phase's own
//     errors bubble up unwrapped (apps classify per their own
//     contract).
//   - ErrFrameworkBug: cascade hop limit exceeded (pipeline cycle),
//     or no phase claims a downstream state.
func (r *SessionRunner) HandleMessage(sessionID, msgType, from string, payload []byte) (bool, error) {
	r.mu.RLock()
	tracker, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if !ok {
		return false, fmt.Errorf("%w: HandleMessage: session %q is not active", ErrPermanent, sessionID)
	}
	current := tracker.current
	if !phaseConsumes(current, msgType) {
		return false, fmt.Errorf("%w: phase %q: does not consume message type %q in state %q",
			ErrPermanent, current.Name(), msgType, tracker.state)
	}
	if err := current.OnMessage(tracker.ctx, msgType, from, payload); err != nil {
		return false, fmt.Errorf("phase %q: OnMessage: %w", current.Name(), err)
	}
	if !current.CheckComplete(tracker.ctx) {
		return false, nil
	}
	return r.advance(tracker)
}

// advance runs Exit on the current phase, advances to the next phase
// in the pipeline (if any), and runs that phase's Enter. After Enter
// it cascades: if the new phase's CheckComplete returns true with no
// messages consumed (a pure-compute phase, or one whose work is done
// in Enter), advance continues through it. This keeps pure-compute
// phases like Argmax from stalling the session — they declare
// CheckComplete=true and the runner walks past them on the same call.
// Caller holds no locks on entry.
func (r *SessionRunner) advance(tracker *sessionTracker) (bool, error) {
	hopCap := len(r.phases) + 1
	for hop := 0; hop < hopCap; hop++ {
		current := tracker.current
		if err := current.Exit(tracker.ctx); err != nil {
			return false, fmt.Errorf("phase %q: Exit: %w", current.Name(), err)
		}
		if err := r.commitPhaseOutputsIfEnabled(current, tracker.ctx); err != nil {
			return false, fmt.Errorf("phase %q: lineage commit: %w", current.Name(), err)
		}
		next := current.ExitState()
		if next == StateNone {
			r.mu.Lock()
			tracker.state = StateNone
			tracker.current = nil
			r.mu.Unlock()
			return true, nil
		}
		r.mu.RLock()
		nextPhase, ok := r.byEntryState[next]
		r.mu.RUnlock()
		if !ok {
			return false, fmt.Errorf("%w: no phase claims state %q (ExitState of %q)", ErrFrameworkBug, next, current.Name())
		}
		r.mu.Lock()
		tracker.state = next
		tracker.current = nextPhase
		tracker.entered = false
		r.mu.Unlock()
		if err := nextPhase.Enter(tracker.ctx); err != nil {
			return false, fmt.Errorf("phase %q: Enter: %w", nextPhase.Name(), err)
		}
		r.mu.Lock()
		tracker.entered = true
		r.mu.Unlock()
		// Cascade: if this phase consumes no messages and its
		// CheckComplete fires immediately on Enter, walk past it.
		// Phases that consume messages stop the cascade — they must
		// wait for OnMessage to flip CheckComplete.
		if len(nextPhase.ConsumedMessageTypes()) > 0 {
			return true, nil
		}
		if !nextPhase.CheckComplete(tracker.ctx) {
			return true, nil
		}
	}
	return false, fmt.Errorf("%w: cascade hop limit exceeded (>%d hops); pipeline likely has a cycle", ErrFrameworkBug, hopCap)
}

// AdvanceToState walks the runner's tracked session forward until
// the current phase's EntryState equals the target, calling Exit
// on each completed phase and Enter on each newly-entered phase.
// Use it when an external authority (e.g., the legacy engine) has
// already advanced the session and the runner needs to catch up
// to maintain a parallel view.
//
// Special cases:
//   - target == current state: no-op, returns nil.
//   - target is an InternalState of the current phase: no-op,
//     returns nil (handles coarse-phase / fine-state mismatches
//     like LOCKED → KEYGEN where KEYGEN is internal to Phase 0a).
//   - target == StateNone: rejected. Runners advance forward
//     through declared states only; the terminal cascade to
//     StateNone happens automatically when a phase with
//     ExitState=StateNone fires its Exit. Callers wanting to end
//     a session should EndSession(sessionID) explicitly.
//
// Errors:
//   - ErrPermanent: session not active; target is unreachable
//     (no phase walks to it, or target is "behind" — runners never
//     rewind).
//   - ErrFrameworkBug: cascade hop limit exceeded (pipeline cycle);
//     no phase claims a downstream state declared by a phase's
//     ExitState.
//   - phase.{Exit,Enter} pass-through.
//   - Lineage commit errors during Exit pass through wrapped with
//     ErrFrameworkBug (the auto-commit hook should never fail
//     legitimately; failures indicate a Store or Signer bug).
func (r *SessionRunner) AdvanceToState(sessionID string, target SessionState) error {
	r.mu.RLock()
	tracker, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: AdvanceToState: session %q is not active", ErrPermanent, sessionID)
	}
	if tracker.state == target {
		return nil
	}
	// If target is an internal state of the current phase, the
	// session is still inside this phase — no advancement
	// required. This handles ARES's LOCKED → KEYGEN sub-state
	// (KEYGEN is internal to Phase 0a) and any other
	// coarse-phase / fine-state mismatches.
	if tracker.current != nil {
		for _, sub := range tracker.current.InternalStates() {
			if sub == target {
				return nil
			}
		}
	}
	// Walk forward at most len(phases) hops to avoid infinite
	// loops if the chain has cycles (shouldn't, but defensive).
	for hop := 0; hop < len(r.phases)+1; hop++ {
		if tracker.state == target {
			return nil
		}
		current := tracker.current
		if current == nil {
			return fmt.Errorf("%w: AdvanceToState: session %q has no current phase but target %q not reached", ErrFrameworkBug, sessionID, target)
		}
		// Exit current and step to next.
		if err := current.Exit(tracker.ctx); err != nil {
			return fmt.Errorf("phase %q: Exit during AdvanceToState: %w", current.Name(), err)
		}
		if err := r.commitPhaseOutputsIfEnabled(current, tracker.ctx); err != nil {
			return fmt.Errorf("phase %q: lineage commit during AdvanceToState: %w", current.Name(), err)
		}
		next := current.ExitState()
		if next == StateNone {
			// Reached the terminal phase but never saw target.
			return fmt.Errorf("%w: AdvanceToState: session %q reached terminal phase %q without entering target %q",
				ErrPermanent, sessionID, current.Name(), target)
		}
		r.mu.RLock()
		nextPhase, ok := r.byEntryState[next]
		r.mu.RUnlock()
		if !ok {
			return fmt.Errorf("%w: AdvanceToState: no phase claims state %q", ErrFrameworkBug, next)
		}
		r.mu.Lock()
		tracker.state = next
		tracker.current = nextPhase
		tracker.entered = false
		r.mu.Unlock()
		if err := nextPhase.Enter(tracker.ctx); err != nil {
			return fmt.Errorf("phase %q: Enter during AdvanceToState: %w", nextPhase.Name(), err)
		}
		r.mu.Lock()
		tracker.entered = true
		r.mu.Unlock()
	}
	return fmt.Errorf("%w: AdvanceToState: hop limit exceeded for session %q (target %q); pipeline likely has a cycle",
		ErrFrameworkBug, sessionID, target)
}

// EndSession releases the runner's tracking for the given session.
// Callers should call this when the session terminates (gracefully or
// otherwise) to release the SessionContext for garbage collection.
func (r *SessionRunner) EndSession(sessionID string) {
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

// CurrentState returns the active SessionState for sessionID, plus a
// boolean indicating whether the session is being tracked.
func (r *SessionRunner) CurrentState(sessionID string) (SessionState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.sessions[sessionID]
	if !ok {
		return StateNone, false
	}
	return t.state, true
}

// SessionContext returns the SessionContext for sessionID, or nil if
// the session is not tracked. The returned context is the live object
// that phases read and write — callers must not mutate it concurrently
// with the runner's dispatch.
func (r *SessionRunner) SessionContext(sessionID string) *SessionContext {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.sessions[sessionID]
	if !ok {
		return nil
	}
	return t.ctx
}

// SessionContextKeys returns the named session-context entries for
// sessionID. Only keys listed in `names` are returned; if a key is
// absent from the context it is omitted from the result. Returns nil
// if the session is not tracked.
func (r *SessionRunner) SessionContextKeys(sessionID string, names []string) map[string]string {
	ctx := r.SessionContext(sessionID)
	if ctx == nil {
		return nil
	}
	out := make(map[string]string, len(names))
	for _, k := range names {
		v, ok := ctx.Get(k)
		if !ok {
			continue
		}
		switch val := v.(type) {
		case []byte:
			out[k] = hex.EncodeToString(val)
		case string:
			out[k] = val
		case map[string]any:
			b, err := json.Marshal(val)
			if err == nil {
				out[k] = string(b)
			}
		default:
			out[k] = fmt.Sprintf("%v", val)
		}
	}
	return out
}

func phaseConsumes(p Phase, msgType string) bool {
	for _, t := range p.ConsumedMessageTypes() {
		if t == msgType {
			return true
		}
	}
	return false
}
