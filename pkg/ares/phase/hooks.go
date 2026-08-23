// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
)

// LineageFailureFn is the callback signature for
// WithLineageFailureHook.
type LineageFailureFn func(ev LineageFailureEvent)

// LineageFailureEvent describes a lineage failure the runner
// surfaces to the consuming application. Two kinds are defined in
// v0.4.0:
//
//   - "mismatch-confirmed": a verification failure was independently
//     re-verified by other parties; the producer is attributed.
//   - "mismatch-false-claim": a party broadcast a lineage.mismatch
//     frame that other parties refuted; the claimant is attributed
//     (F-49-style collateral applies in consuming apps).
type LineageFailureEvent struct {
	Kind       string
	SessionID  string
	PhaseID    string
	Role       string

	// Attributee is the public key bytes of the party held
	// responsible — the producer for mismatch-confirmed, the
	// claimant for mismatch-false-claim. Stringified pubkey
	// bytes; application looks up the matching party identity.
	Attributee string

	// DAGNodes carries the relevant nodes for forensic audit:
	// the original commit, the mismatch claim, any cross-verify
	// records. Format depends on Kind.
	DAGNodes []lineage.DAGNode
}
