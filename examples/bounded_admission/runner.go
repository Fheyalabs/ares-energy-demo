// SPDX-License-Identifier: Apache-2.0

package bounded_admission

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
)

// PipelineWithCrypto builds a SessionRunner over the bounded-admission
// pipeline:
//
//	Invitation → Keygen (pre-shared) → SubmitInput → boundcheck → Settle
//
// The boundcheck phase is constructed via NewPhase (no process-shared
// handle/fuse). In real mode, the trigger supplies per-session
// ContextHandle + fuse via CtxBoundCheckHandle / CtxBoundCheckFuse on the
// SessionContext (the B0 affordance). In stub mode (neither construction-
// nor context-provided), the boundcheck phase no-ops its FHE path — the
// session reaches StateSettled without real crypto, suitable for smoke
// tests and wire-format validation.
func PipelineWithCrypto() (*phase.SessionRunner, error) {
	return phase.Compose(
		NewPhaseInvitation(),
		NewPhaseKeygen(),
		NewPhaseSubmitInput(),
		boundcheck.NewPhase(
			boundcheck.NormCircuit{Eps: 0.05, NDim: 8},
			recordingHandler{},
			boundcheck.DefaultParams(),
			StateChecking,
			StateSettled,
		),
		NewPhaseSettle(),
	)
}
