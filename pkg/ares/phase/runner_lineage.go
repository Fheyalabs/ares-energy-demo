// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
)

// hookPanicLog is the destination for fireFailureHook's recover()
// reports. Default os.Stderr; tests can override via
// SetHookPanicLog.
var hookPanicLog io.Writer = os.Stderr

// SetHookPanicLog overrides the destination fireFailureHook writes to
// when an app-level LineageFailureFn panics. Default is os.Stderr.
// Pass io.Discard to silence (production deployments that pipe panics
// through their own observability stack may prefer that). Pass a
// *bytes.Buffer in tests to capture and assert on the log line.
//
// Returns the previous writer so callers can restore it.
//
// NOT goroutine-safe — call during process init, before sessions are
// started. The runner doesn't take a lock to read it.
func SetHookPanicLog(w io.Writer) io.Writer {
	prev := hookPanicLog
	hookPanicLog = w
	return prev
}

// HandleLineageMessage routes an inbound message through SC-10
// verification before dispatching it to the phase's OnMessage. The
// transport layer should call this method (rather than the legacy
// HandleMessage) for runners constructed via ComposeWith.
//
// Verification steps (in order):
//  1. Pipeline is lineage-enabled (r.lineageStore != nil); otherwise
//     fall through to legacy HandleMessage.
//  2. lineageNode is non-nil (v2 frames must carry Lineage).
//  3. lineage.Verify(node, payload, r.lineageVerifiers) succeeds.
//  4. Parent refs resolve in r.lineageStore.
//  5. r.lineageStore.Append succeeds (or returns ErrNodeExists,
//     which is idempotent and OK).
//
// Any failure aborts BEFORE Phase.OnMessage is called and (when a
// failure hook is registered) fires LineageFailureEvent with
// Kind="mismatch-confirmed". The mismatch broadcast frame
// construction is in BuildMismatchClaim (Task 18).
func (r *SessionRunner) HandleLineageMessage(
	sessionID, msgType, from string,
	payload []byte,
	lineageNode *lineage.DAGNode,
) (bool, error) {
	if r.lineageStore == nil {
		// Compose-built runner; fall through to legacy path.
		return r.HandleMessage(sessionID, msgType, from, payload)
	}
	if lineageNode == nil {
		return false, fmt.Errorf("%w: HandleLineageMessage requires non-nil lineage node (v2 frame)", ErrPermanent)
	}

	// Verify the node against the payload.
	verifyErr := lineage.Verify(*lineageNode, payload, r.lineageVerifiers)
	if verifyErr == nil {
		// Parent ref check (cannot be done inside Verify, which
		// operates on a single node in isolation).
		ctx := context.Background()
		for i, parent := range lineageNode.Parents {
			if _, err := r.lineageStore.Get(ctx, parent); err != nil {
				verifyErr = &lineage.MismatchError{
					Field:    "ParentRef",
					Expected: parent[:],
					Got:      []byte(fmt.Sprintf("parent[%d] not in store: %v", i, err)),
					NodeHash: lineageNode.Hash,
				}
				break
			}
		}
	}

	if verifyErr != nil {
		// Fire structured failure event for the consuming app.
		r.fireFailureHook(LineageFailureEvent{
			Kind:       "mismatch-confirmed",
			SessionID:  sessionID,
			PhaseID:    lineageNode.PhaseID,
			Role:       lineageNode.Role,
			Attributee: string(lineageNode.Producer),
			DAGNodes:   []lineage.DAGNode{*lineageNode},
		})
		return false, fmt.Errorf("%w: HandleLineageMessage: session %q phase %q role %q: %w",
			ErrAppAttributable, sessionID, lineageNode.PhaseID, lineageNode.Role, verifyErr)
	}

	// Verified; persist (idempotent on ErrNodeExists).
	if err := r.lineageStore.Append(context.Background(), *lineageNode); err != nil && !errors.Is(err, lineage.ErrNodeExists) {
		return false, fmt.Errorf("%w: HandleLineageMessage: store.Append for phase %q role %q: %w",
			ErrFrameworkBug, lineageNode.PhaseID, lineageNode.Role, err)
	}

	// Dispatch to phase code.
	return r.HandleMessage(sessionID, msgType, from, payload)
}

// fireFailureHook invokes the registered LineageFailureFn (if any)
// with a structured event.
//
// Defensive against:
//   - nil hooks (no-op if WithLineageFailureHook was not set);
//   - hook panics (recover() catches; the runner does not crash).
//
// When the hook panics the recovered value is logged to the
// hook-panic writer (default os.Stderr; override via
// SetHookPanicLog) with the session/phase/role/kind context so the
// misbehavior is observable at runtime instead of being silently
// swallowed. The hook is app code; a panic indicates a bug in the
// consuming application, not in the framework.
func (r *SessionRunner) fireFailureHook(ev LineageFailureEvent) {
	if r.lineageFailureHook == nil {
		return
	}
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(hookPanicLog,
				"phase: LineageFailureHook panic; session=%q phase=%q role=%q kind=%q: %v\n",
				ev.SessionID, ev.PhaseID, ev.Role, ev.Kind, rec)
		}
	}()
	r.lineageFailureHook(ev)
}

// BuildMismatchClaim constructs a signed DAGNode representing a
// lineage.mismatch broadcast frame. The claim's payload is the
// stringified mismatch error (for forensic legibility); parents
// are empty (the original commit ref is encoded in the
// MismatchError.NodeHash for audit but not as a DAG parent — the
// claim stands on its own as a signed assertion).
//
// Parameters:
//   - sessionID: the session whose lineage was disputed.
//   - phaseID:   the phase of the disputed commit. Stored on the
//     claim DAGNode's PhaseID field.
//   - role:      the role label of the disputed commit. Currently
//     accepted for API symmetry with the disputed commit's
//     construction but NOT propagated to the claim's DAGNode —
//     the claim's Role is hardcoded to "mismatch-claim" so
//     receivers can distinguish a claim from a real commit. A
//     v0.5.0 follow-up may either embed `role` in the payload or
//     deprecate the parameter.
//   - mismatchErr: the underlying lineage error. Its Error()
//     string becomes the DAGNode's payload bytes.
//
// Transport layer wraps the returned DAGNode in a WSMessage of
// type "lineage.mismatch" and broadcasts to all session
// participants for re-verification.
//
// Returns ErrPermanent if called on a Compose-built (non-lineage)
// runner.
func (r *SessionRunner) BuildMismatchClaim(sessionID, phaseID, role string, mismatchErr error) (lineage.DAGNode, error) {
	if r.lineageSigner == nil {
		return lineage.DAGNode{}, fmt.Errorf(
			"%w: BuildMismatchClaim requires lineage-enabled runner (build via ComposeWith, not Compose)",
			ErrPermanent)
	}
	_ = role // see godoc — currently informational; reserved for v0.5.0.
	payload := []byte(mismatchErr.Error())
	return lineage.Commit(sessionID, phaseID, "mismatch-claim", payload, nil, r.lineageSigner)
}

// ReportFalseLineageClaim is invoked by the transport layer when
// cross-verification of a mismatch claim concludes the claim was
// unjustified (the original commit verifies cleanly against the
// payload other parties received). Fires the LineageFailureFn
// hook with Kind="mismatch-false-claim" attributing the claimant.
//
// claim is the signed DAGNode the claimant broadcast.
func (r *SessionRunner) ReportFalseLineageClaim(sessionID string, claim lineage.DAGNode) {
	r.fireFailureHook(LineageFailureEvent{
		Kind:       "mismatch-false-claim",
		SessionID:  sessionID,
		PhaseID:    claim.PhaseID,
		Role:       claim.Role,
		Attributee: string(claim.Producer),
		DAGNodes:   []lineage.DAGNode{claim},
	})
}

// commitPhaseOutputsIfEnabled is invoked by the runner's advance
// loop after Phase.Exit completes successfully. No-op for
// Compose-built runners (lineageStore == nil). For
// ComposeWith-built runners, iterates the phase's Provides schema
// and auto-commits each output key whose declared value is []byte
// and is not marked NoLineage.
//
// Non-[]byte values are skipped silently — apps wanting to commit
// struct types must serialize to []byte themselves before
// ctx.Set. This keeps v0.4.0 framework scope narrow; structured
// auto-serialization is a future enhancement.
//
// Parents are resolved by inspecting Phase.Requires: each
// required key whose current value in ctx is []byte and which has
// a corresponding lineage node in the store contributes a parent
// ref.
func (r *SessionRunner) commitPhaseOutputsIfEnabled(p Phase, ctx *SessionContext) error {
	if r.lineageStore == nil {
		return nil
	}
	parents, err := r.resolveParents(p, ctx)
	if err != nil {
		return err
	}
	for key, kt := range p.Provides() {
		if kt.NoLineage {
			continue
		}
		raw, ok := ctx.Get(key)
		if !ok {
			continue
		}
		payload, ok := raw.([]byte)
		if !ok {
			// Non-byte output; skip auto-commit.
			continue
		}
		node, err := lineage.Commit(
			ctx.SessionID,
			p.Name(),
			key, // role = context key name
			payload,
			parents,
			r.lineageSigner,
		)
		if err != nil {
			return fmt.Errorf("%w: lineage.Commit for phase %q output %q: %w", ErrFrameworkBug, p.Name(), key, err)
		}
		if err := r.lineageStore.Append(context.Background(), node); err != nil && !errors.Is(err, lineage.ErrNodeExists) {
			return fmt.Errorf("%w: lineage.Store.Append for phase %q output %q: %w", ErrFrameworkBug, p.Name(), key, err)
		}
	}
	return nil
}

// resolveParents builds the parent DAGNode list for a phase about
// to commit. For each key in p.Requires(): if the key's current
// context value is []byte, hash it and look up a matching node in
// the store; if found, include as parent. Missing matches are not
// errors (the producer of the input may be on a different runner;
// lineage chains across boundaries are app-layer concerns for
// v0.4.0).
func (r *SessionRunner) resolveParents(p Phase, ctx *SessionContext) ([]lineage.DAGNode, error) {
	var parents []lineage.DAGNode
	for key := range p.Requires() {
		raw, ok := ctx.Get(key)
		if !ok {
			continue
		}
		payload, ok := raw.([]byte)
		if !ok {
			continue
		}
		hash := lineage.HashPayload(payload)
		// Walk the session to find a node whose PayloadHash matches.
		// O(N) per resolve — fine for v0.4.0 typical N≤6 sessions; an
		// index by PayloadHash is a v0.5.0 optimization if profiling
		// shows it.
		for node, err := range r.lineageStore.WalkSession(context.Background(), ctx.SessionID) {
			if err != nil {
				return nil, err
			}
			if node.PayloadHash == hash {
				parents = append(parents, node)
				break
			}
		}
	}
	return parents, nil
}
