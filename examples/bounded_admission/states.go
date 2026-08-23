// SPDX-License-Identifier: Apache-2.0

// Package bounded_admission is a worked example of ARES-BC bounded
// admission: admit parties whose normalized vector norm falls within
// [1-Eps, 1+Eps] via the boundcheck.NormCircuit. The example pipeline
// demonstrates the per-session handle/fuse affordance: the boundcheck
// phase is constructed in stub mode (no process-shared handle), and the
// trigger supplies the real ContextHandle + fuse per session via the
// SessionContext — enabling a shared-runner session-service.
//
// Pre-shared keygen: clients generate the threshold CKKS key bundle
// offline and seed it via admin POST attrs. The server never holds
// secret key shares.
package bounded_admission

import "github.com/Fheyalabs/ares-core/pkg/ares/phase"

const (
	StateInviting   phase.SessionState = "ADMISSION_INVITING"
	StateLocked     phase.SessionState = "ADMISSION_LOCKED"
	StateSubmitting phase.SessionState = "ADMISSION_SUBMITTING"
	StateChecking   phase.SessionState = "ADMISSION_CHECKING"
	StateSettled    phase.SessionState = "ADMISSION_SETTLED"
)

// Context keys this app owns (the boundcheck phase + defaults own the rest).
const (
	CtxAdmissionResults = "admission.results" // map[string]string: party -> "admitted"|"violation:<sev>"
)

// MsgInput is the client-to-server encrypted-input submission; payload is
// {"enc_x":"<hex serialized ciphertext>"}. MsgBoundPartial (from boundcheck
// package) is the partial-decrypt reply. MsgChallenge is the server-to-client
// broadcast of ALL parties' check CTs + commitments (sent by the PostDispatchHook):
// {"checks":{party:"<hex>"},"commitments":{party:"<hex>"}}.
const (
	MsgInput     = "admission.input"
	MsgChallenge = "bound_check.challenge"
)
