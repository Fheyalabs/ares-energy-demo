// SPDX-License-Identifier: Apache-2.0

package boundcheck

import (
	"math"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// Bound is the closed interval the decrypted check value must lie in.
type Bound struct{ Lo, Hi float64 }

// Severity classifies a bound-check outcome.
type Severity int

const (
	SeverityOK Severity = iota
	SeveritySoft
	SeverityHard
)

// Params are ARES-core's detection bands (distinct from any app penalty curve).
type Params struct {
	EpsNorm float64 // noise floor; nu <= EpsNorm is treated as in-bound
	NuHard  float64 // hard-violation threshold on the distance outside the bound
}

// DefaultParams mirror ARES v2.6 SC-5 reference values.
func DefaultParams() Params { return Params{EpsNorm: 0.01, NuHard: 1.25} }

// BoundCircuit is the homomorphic map producing the single safe-to-decrypt
// check value for one encrypted input, plus the bound the value must satisfy.
// It is also a fhecalib.CircuitUnderTest, so the exact circuit run at phase
// runtime is the one calibrated for depth.
type BoundCircuit interface {
	fhecalib.CircuitUnderTest
	Bound() Bound
	// Dim returns the expected input-vector dimension (slot count) for this
	// circuit. Enter rejects sessions where CtxInputDim != Dim() to prevent
	// silently summing the wrong number of slots and producing a wrong norm.
	Dim() int
}

// ViolationHandler is the application boundary: invoked once per violating
// party before the session aborts. nu is the distance outside the bound; the
// app maps it to a domain penalty.
type ViolationHandler interface {
	// OnViolation is called synchronously before the jitter sleep and the
	// session abort. The returned error is advisory (for application-layer
	// logging or side effects); the framework discards it and aborts the
	// session regardless of what OnViolation returns.
	OnViolation(ctx *phase.SessionContext, party string, nu float64, sev Severity) error
}

// classify computes the distance outside the bound and its severity.
//
//	nu = max(0, Lo - value, value - Hi)
//	nu <= EpsNorm          -> OK (noise floor)
//	EpsNorm < nu <= NuHard -> Soft
//	nu > NuHard            -> Hard
func classify(value float64, b Bound, p Params) (nu float64, sev Severity) {
	nu = math.Max(0, math.Max(b.Lo-value, value-b.Hi))
	switch {
	case nu <= p.EpsNorm:
		return nu, SeverityOK
	case nu <= p.NuHard:
		return nu, SeveritySoft
	default:
		return nu, SeverityHard
	}
}

// Context keys: the app's input-submit phase Provides these; the bound phase
// Requires them. (Use defaults.CtxParticipants for the participant set — NOT a
// boundcheck-local copy.)
const (
	CtxEncryptedInputs   = "boundcheck.encrypted_inputs"  // map[string][]byte: party -> lineage-committed ciphertext
	CtxInputDim          = "boundcheck.input_dim"         // int: slot count of each input vector
	CtxEvalKeyBundle     = "boundcheck.eval_key_bundle"   // serialized cgo.EvalKeyFinal
	CtxJointPublicKey    = "boundcheck.joint_public_key"  // []byte: pk_joint
	CtxBoundCheckCiphers      = "boundcheck.check_ciphertexts"  // map[string][]byte: party -> enc_check (phase Provides; app unicasts)
	CtxBoundCheckCommitments  = "boundcheck.check_commitments"  // map[string][]byte: party -> H(enc_check ‖ H(enc_x) ‖ session_id)

	// CtxBoundCheckHandle / CtxBoundCheckFuse let a shared-runner session-service
	// supply a PER-SESSION fhecalib.ContextHandle and fuse function via the
	// SessionContext (set by the app's trigger at BeginSession), for apps that
	// cannot bake a single handle into a process-shared Phase. They are honored
	// only when the construction-time handle/fuse (NewPhaseWithCrypto) are nil.
	CtxBoundCheckHandle = "boundcheck.handle" // fhecalib.ContextHandle (server-set)
	CtxBoundCheckFuse   = "boundcheck.fuse"   // func(partials [][]byte, nSlots int) ([]float64, error) (server-set)
)

// MsgBoundPartial is the message type each party replies with: its partial
// decrypt of the broadcast check value.
const MsgBoundPartial = "bound_check.partial"

// bucketPartials is the internal accumulation bucket for partial decrypts.
const bucketPartials = "boundcheck.bucket.partials"
