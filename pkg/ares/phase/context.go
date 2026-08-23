// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// SessionContext is the typed bag of state shared across phases of one
// session run. Each phase declares which keys it reads (Requires) and
// produces (Provides) via ContextSchema; the runner verifies the
// declarations are satisfied before invoking the phase.
//
// SessionContext is concurrency-safe for use by phases that spawn
// goroutines internally. The runner itself drives one phase at a time
// for a given session, so cross-phase races are not expected — the
// lock here is defensive for in-phase parallelism (for example a
// keygen phase that fans out chunked artifact uploads).
type SessionContext struct {
	// SessionID identifies the session this context belongs to. It is
	// set once when the runner constructs the context and never
	// changes.
	SessionID string

	// CohortID, when non-empty, identifies the long-lived cohort
	// this session belongs to. Cohort-lifetime context entries are
	// indexed by this value at the runner-or-service level so that
	// many sessions can share them. An empty CohortID means the
	// session is one-off and per-cohort phases degrade to
	// per-session.
	CohortID string

	mu     sync.RWMutex
	values map[string]any

	// lineageStore is set by ComposeWith-built runners during
	// BeginSession; nil for Compose-built runners. The runner
	// injects this so LineageDAG() can return per-session nodes
	// without phases needing to import the runner package.
	lineageStore lineage.Store

	// lineageSigner is injected by the runner alongside lineageStore
	// for ComposeWith-built runners; nil for Compose-built runners.
	// Used by CommitArtifact to sign phase outputs with explicit
	// parent edges.
	lineageSigner sign.Signer
}

// NewSessionContext returns a SessionContext for the given session.
func NewSessionContext(sessionID string) *SessionContext {
	return &SessionContext{
		SessionID: sessionID,
		values:    make(map[string]any),
	}
}

// LineageDAG returns an iterator over all DAGNodes committed for
// this session. Returns an empty iterator if lineage is disabled
// (Compose-built runners). Read-only; mutating the store directly
// is not supported via this accessor.
//
// Useful for apps that want to inspect the chain mid-session or
// persist a snapshot to their own audit store.
func (c *SessionContext) LineageDAG() iter.Seq[lineage.DAGNode] {
	return func(yield func(lineage.DAGNode) bool) {
		if c.lineageStore == nil {
			return
		}
		for node, err := range c.lineageStore.WalkSession(context.Background(), c.SessionID) {
			if err != nil {
				return
			}
			if !yield(node) {
				return
			}
		}
	}
}

// CommitArtifact commits payload as a lineage DAG node with the given
// explicit parents, signed by the runner's signer, and appends it to
// the session store. Use it for a phase output whose lineage parents
// are not its Requires keys — e.g. a node assembled from accumulated
// messages, where the framework's Requires-based auto-commit cannot
// infer the parents. Returns ErrPermanent on a non-lineage (Compose)
// runner.
func (c *SessionContext) CommitArtifact(phaseID, role string, payload []byte, parents []lineage.DAGNode) (lineage.DAGNode, error) {
	if c.lineageStore == nil || c.lineageSigner == nil {
		return lineage.DAGNode{}, fmt.Errorf("%w: CommitArtifact requires a lineage-enabled runner (build via ComposeWith)", ErrPermanent)
	}
	node, err := lineage.Commit(c.SessionID, phaseID, role, payload, parents, c.lineageSigner)
	if err != nil {
		return lineage.DAGNode{}, fmt.Errorf("%w: CommitArtifact: %w", ErrFrameworkBug, err)
	}
	if err := c.lineageStore.Append(context.Background(), node); err != nil && !errors.Is(err, lineage.ErrNodeExists) {
		return lineage.DAGNode{}, fmt.Errorf("%w: CommitArtifact store.Append: %w", ErrFrameworkBug, err)
	}
	return node, nil
}

// Get returns the value stored under key and a boolean indicating
// whether the key was present.
func (c *SessionContext) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.values[key]
	return v, ok
}

// Set stores value under key, overwriting any previous value. Phases
// should only Set keys they declared in their Provides schema.
func (c *SessionContext) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = value
}

// Update applies fn to the current value under key atomically, storing
// fn's return value back at the same key. Useful for read-modify-write
// patterns (e.g. accumulating per-sender submissions) that would race if
// implemented as separate Get + Set calls, since the WebSocket hub can
// invoke OnMessage concurrently for messages from different participants.
//
// fn receives the current value (nil if absent) and returns the updated
// value. fn must not call other SessionContext methods on c (it would
// deadlock).
func (c *SessionContext) Update(key string, fn func(current any) any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = fn(c.values[key])
}

// Has returns true if key has been set.
func (c *SessionContext) Has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.values[key]
	return ok
}

// Keys returns a snapshot of the currently-set context keys, in no
// particular order. Useful for diagnostics and runner introspection.
func (c *SessionContext) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.values))
	for k := range c.values {
		out = append(out, k)
	}
	return out
}

// MustGet returns the value stored under key, or panics if the key is
// missing or the stored value does not assert to T. Phases that
// declared the key in their Requires schema can use MustGet because
// the runner refuses to start phases with unsatisfied requirements.
//
// Implemented as a free function rather than a method because Go does
// not allow parameterized methods.
func MustGet[T any](c *SessionContext, key string) T {
	v, ok := c.Get(key)
	if !ok {
		panic(fmt.Sprintf("phase: required context key %q is not set", key))
	}
	typed, ok := v.(T)
	if !ok {
		panic(fmt.Sprintf("phase: context key %q has type %T, expected %T", key, v, *new(T)))
	}
	return typed
}

// MissingContextError is returned by a phase when context keys it
// requires are absent at Enter time. The runner treats this as a
// session-start failure (does not proceed past Enter).
type MissingContextError struct {
	Key   string
	Phase string
}

// Error implements the error interface. Format:
//
//	phase: <Phase> requires context key <Key> which is not set
//
// Apps catching this via errors.As(err, &mce) can branch on the
// missing key name (e.g. to inject a default or trigger a recovery
// fetch). Phases returning this from Enter abort the session;
// returning it from other hooks is a phase-bug pattern (the runner
// won't restart the phase).
func (e *MissingContextError) Error() string {
	return "phase: " + e.Phase + " requires context key " + e.Key + " which is not set"
}

// TryGet returns the typed value stored under key together with a
// boolean indicating whether the key was present and assignable to T.
func TryGet[T any](c *SessionContext, key string) (T, bool) {
	var zero T
	v, ok := c.Get(key)
	if !ok {
		return zero, false
	}
	typed, ok := v.(T)
	if !ok {
		return zero, false
	}
	return typed, true
}
