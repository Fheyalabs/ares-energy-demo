// SPDX-License-Identifier: Apache-2.0

// Package lineage implements the session-rooted Merkle DAG that
// underlies SC-10 (Ciphertext Lineage Primitive) in ARES Protocol
// Specification v2.5.
//
// Each phase output is a DAGNode whose hash binds (session_id,
// phase_id, role, payload_hash, parent_refs); each node is signed by
// its producer using a pluggable Signer (see pkg/ares/sign).
// Applications opt out specific outputs via phase.ContextKeyType's
// NoLineage field; otherwise the framework auto-commits Provides
// outputs and auto-verifies inbound messages.
//
// The Store interface persists nodes; InMemoryStore is the default
// implementation. Applications can swap in Postgres/Redis/S3-backed
// implementations for forensic-grade audit.
package lineage
