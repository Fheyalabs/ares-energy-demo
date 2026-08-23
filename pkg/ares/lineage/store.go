// SPDX-License-Identifier: Apache-2.0

package lineage

import (
	"context"
	"iter"
)

// Store is the persistence interface for the lineage DAG. The
// framework ships InMemoryStore as the default; applications can
// substitute Postgres/Redis/S3-backed implementations for
// forensic-grade audit, regulatory retention, or future analytics
// layers (e.g. ProvSQL-style provenance polynomials over the same
// committed nodes).
//
// Implementations must be safe for concurrent use across many
// in-flight phase dispatches.
type Store interface {
	// Append adds node to the store. Returns ErrNodeExists if
	// node.Hash is already present (the store is content-addressed
	// and idempotent on identical content; the error is
	// informational for callers that care about novelty).
	Append(ctx context.Context, node DAGNode) error

	// Get retrieves a node by content hash. Returns
	// ErrNodeNotFound if the hash is not present.
	Get(ctx context.Context, hash NodeRef) (DAGNode, error)

	// WalkSession returns an iterator over all nodes belonging to
	// sessionID. Iteration order is implementation-defined;
	// callers that need a canonical order should sort the
	// results. Implementations may stream lazily.
	WalkSession(ctx context.Context, sessionID string) iter.Seq2[DAGNode, error]
}
