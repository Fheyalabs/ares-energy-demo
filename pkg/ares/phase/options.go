// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// ComposeOption configures a SessionRunner constructed via
// ComposeWith. Use the With* helpers; the underlying type is
// intentionally opaque so future additions don't break call sites.
type ComposeOption func(*runnerOpts)

// runnerOpts collects ComposeWith options before SessionRunner
// construction.
type runnerOpts struct {
	store         lineage.Store
	signer        sign.Signer
	peerVerifiers map[string]sign.Signer
	failureHook   LineageFailureFn
}

// WithStore sets the lineage.Store backing the runner's auto-commit.
// Default (when omitted): lineage.NewInMemoryStore().
func WithStore(s lineage.Store) ComposeOption {
	return func(o *runnerOpts) { o.store = s }
}

// WithSigner sets the local party's Signer for producing commits.
// REQUIRED for ComposeWith; the runner rejects construction
// without it.
func WithSigner(s sign.Signer) ComposeOption {
	return func(o *runnerOpts) { o.signer = s }
}

// WithPeerVerifiers populates the runner's map of known verifiers
// keyed by signature algorithm. The framework uses these to check
// inbound DAGNode signatures (the producer's pubkey lives on the
// node itself; the verifier instance just provides the
// scheme-specific Verify implementation).
//
// REQUIRED for multi-party pipelines (any phase that consumes WS
// messages from senders other than the local party).
func WithPeerVerifiers(v map[string]sign.Signer) ComposeOption {
	return func(o *runnerOpts) { o.peerVerifiers = v }
}

// WithLineageFailureHook registers a callback the runner invokes
// when a lineage verification fails or a mismatch is broadcast.
// The hook receives a structured LineageFailureEvent describing
// what failed and who is attributed; the consuming application
// applies whatever penalty its policy dictates (e.g. brownie
// deduction in Fheya).
//
// Hook is fire-and-forget — must not block on network or other
// long operations; spawn a goroutine if needed.
//
// Panic handling: the runner recovers from hook panics so a
// buggy app hook cannot take down the runner. Recovered panics
// are logged to stderr by default (override the destination via
// phase.SetHookPanicLog — io.Discard silences entirely).
// Recovery is not a substitute for not panicking; the log line
// is meant to surface the bug, not normalize it.
func WithLineageFailureHook(fn LineageFailureFn) ComposeOption {
	return func(o *runnerOpts) { o.failureHook = fn }
}
