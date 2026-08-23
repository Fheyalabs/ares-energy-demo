// SPDX-License-Identifier: Apache-2.0

package phase

import "errors"

// Sentinel errors that classify framework failures by attribution
// and retryability.
//
// Every error returned from a public framework method
// (SessionRunner.HandleMessage, HandleLineageMessage,
// AdvanceToState, etc.) is wrapped with exactly one of these
// sentinels via fmt.Errorf("%w: ...", ErrXxx, ...). Consuming
// applications branch retry / penalty / report-bug policy via
// errors.Is(err, phase.ErrXxx) without string-matching error
// messages.
//
// Domain-specific error types (lineage.MismatchError,
// lineage.ErrNodeNotFound, etc.) remain accessible via errors.As
// — the sentinel categorizes; the typed error carries the
// forensic detail. A single err can satisfy both
// errors.Is(err, ErrAppAttributable) and
// errors.As(err, &mismatchErr).
//
// Adding a new category is a breaking-grade change for consumers
// that exhaustively switch on these — choose carefully.
var (
	// ErrTransient signals a failure that is expected to succeed
	// on retry: backend unreachable, lock contention, transient
	// network error, helper subprocess restart in progress.
	// Consuming apps should back off and retry the same operation.
	ErrTransient = errors.New("phase: transient failure (retryable)")

	// ErrPermanent signals a failure attributable to configuration,
	// schema violation, or invariant breach — the same operation
	// will not succeed on retry without intervention. Examples:
	// missing required context key, ComposeWith without a Signer,
	// AdvanceToState targeting a state no phase claims.
	// Consuming apps should fail-fast (not retry) and surface for
	// operator attention.
	ErrPermanent = errors.New("phase: permanent failure (config or invariant)")

	// ErrAppAttributable signals a failure caused by a specific
	// counterparty in the session: a tampered payload, a refuted
	// mismatch claim, a malformed commit, a signature failure on
	// inbound lineage. The error chain carries the structured
	// detail (typically a *lineage.MismatchError accessible via
	// errors.As). Consuming apps use this to drive penalty logic
	// (Fheya brownie deductions, exclusion-list additions) without
	// having to string-match the underlying error.
	ErrAppAttributable = errors.New("phase: app-attributable failure")

	// ErrFrameworkBug signals an unexpected internal condition the
	// framework couldn't recover from: nil-pointer in runner state
	// that should be unreachable, broken invariant in lineage
	// resolution, panic recovered in a place that shouldn't panic.
	// Apps should surface this prominently (it indicates a bug in
	// ARES-core, not in the consumer) and not silently recover.
	ErrFrameworkBug = errors.New("phase: framework bug")
)
