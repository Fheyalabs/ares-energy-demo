// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"fmt"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// ComposeWith constructs a lineage-enabled SessionRunner over the
// given phase list with the supplied options. Validates required
// options (WithSigner; WithPeerVerifiers for multi-party
// pipelines) fail-fast at construction time rather than at first
// verification attempt.
//
// Pipelines built with ComposeWith emit WSMessages at
// transport.WireProtocolVersionLineage ("2") with required
// Lineage fields. Pipelines built with the existing
// phase.Compose(...) function continue emitting v1 frames
// without Lineage (lineage-disabled backward-compatibility
// path).
//
// # Auto-commit semantics (load-bearing)
//
// After every Phase.Exit, the runner walks the phase's Provides
// schema and auto-commits each output key. Three exemption rules
// apply — these are intentional but easy to miss:
//
//  1. Outputs declared NoLineage:true in ContextKeyType are skipped
//     entirely. Use this for ephemeral or public outputs that don't
//     need cryptographic binding (e.g. liveness pings, debug
//     metadata). Audit from one place: grep `"NoLineage: true"`.
//  2. Outputs whose runtime value is NOT a []byte slice are silently
//     skipped. Phase.Provides declares the TypeName but the
//     auto-commit hook checks the concrete type. Apps wanting to
//     commit struct types MUST serialize to []byte themselves
//     before ctx.Set (json.Marshal, proto.Marshal, etc.).
//  3. Outputs not yet ctx.Set at Exit time are skipped (no value
//     to hash). This usually indicates a phase bug — the Provides
//     contract said the key would be set but Exit ran without it.
//
// Returns:
//   - *SessionRunner: ready for BeginSession + HandleLineageMessage.
//   - error wrapped with ErrPermanent for missing/invalid options.
//
// Default store (when WithStore is omitted):
// lineage.NewInMemoryStore() — in-memory, per-runner, NOT shared
// across runners unless the caller injects a shared store via
// WithStore.
func ComposeWith(phases []Phase, opts ...ComposeOption) (*SessionRunner, error) {
	o := &runnerOpts{}
	for _, opt := range opts {
		opt(o)
	}

	// Required: signer.
	if o.signer == nil {
		return nil, fmt.Errorf("%w: ComposeWith requires WithSigner(...)", ErrPermanent)
	}

	// Required for multi-party: peer verifiers. A pipeline is
	// multi-party if any phase consumes WS messages from senders
	// other than the local party — detect by ConsumedMessageTypes
	// != nil on any phase.
	if needsPeers(phases) && len(o.peerVerifiers) == 0 {
		return nil, fmt.Errorf(
			"%w: ComposeWith requires WithPeerVerifiers(...) for multi-party pipelines "+
				"(pipeline contains phases that consume WS messages)", ErrPermanent)
	}

	// Default store.
	if o.store == nil {
		o.store = lineage.NewInMemoryStore()
	}

	// Verifier map: combine our own signer with peer verifiers so
	// self-produced commits also verify (a producer's own runner
	// re-verifies its own commits as a safety check).
	verifiers := map[string]sign.Signer{}
	for alg, v := range o.peerVerifiers {
		verifiers[alg] = v
	}
	if _, ok := verifiers[o.signer.Algorithm()]; !ok {
		verifiers[o.signer.Algorithm()] = o.signer
	}

	// Delegate to the existing Compose for phase-chain validation;
	// then attach lineage state. Compose returns ErrPermanent-wrapped
	// errors for invalid pipelines; preserve the sentinel through
	// our prefix.
	runner, err := Compose(phases...)
	if err != nil {
		return nil, fmt.Errorf("ComposeWith: %w", err)
	}
	runner.attachLineage(o.store, o.signer, verifiers, o.failureHook)
	return runner, nil
}

// needsPeers returns true if any phase in phases consumes WS
// messages — implying multi-party communication.
func needsPeers(phases []Phase) bool {
	for _, p := range phases {
		if len(p.ConsumedMessageTypes()) > 0 {
			return true
		}
	}
	return false
}
