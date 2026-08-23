// SPDX-License-Identifier: Apache-2.0

package fhecalib

import (
	"errors"
	"fmt"
	"math"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// ErrModulusCap is returned when a candidate depth requires a ciphertext
// modulus larger than the chosen RingDim permits. The caller should raise
// RingDim, not depth.
var ErrModulusCap = errors.New("fhecalib: depth requires modulus exceeding RingDim cap")

// ContextHandle is the stable surface a CircuitUnderTest.Eval uses to run
// homomorphic ops, so circuits are written once against it regardless of the
// underlying backend. The openfhe-gated implementation is cgo-backed.
type ContextHandle interface {
	// Params returns the CKKS parameters provisioned for the current sweep step.
	Params() helperclient.ContractParams
	// EvalMult multiplies two ciphertexts under the joint eval-mult key.
	EvalMult(ctA, ctB []byte) ([]byte, error)
	// EvalSubConst subtracts a public plaintext vector (the bound center) from ct.
	EvalSubConst(ct []byte, vals []float64) ([]byte, error)
	// EvalProductSum computes EvalSum(EvalMult(left,right)) over nSlots (the
	// squared magnitude when left == right).
	EvalProductSum(ctLeft, ctRight []byte, nSlots int) ([]byte, error)
}

// CircuitUnderTest describes one homomorphic computation to calibrate.
// Implementations are use-case specific; the calibrator is generic.
type CircuitUnderTest interface {
	// Name identifies the circuit in results and logs.
	Name() string
	// Inputs returns representative plaintext input vectors for the use case;
	// one vector per encrypted input the circuit consumes.
	Inputs() [][]float64
	// Expected returns the plaintext ground-truth result for those inputs.
	Expected(inputs [][]float64) []float64
	// Eval runs the homomorphic circuit on the encrypted inputs and returns
	// the encrypted result.
	Eval(h ContextHandle, encInputs [][]byte) (encResult []byte, err error)
}

// CalibrationParams configures a sweep. ScalingModSize and RingDim are taken
// from Base; Depth is the primary sweep dimension (StartDepth..MaxDepth).
type CalibrationParams struct {
	Base       helperclient.ContractParams // RingDim + ScalingModSize (Depth is overridden by the sweep)
	StartDepth uint32
	MaxDepth   uint32
	Tolerance  float64 // max acceptable abs error per output slot
}

// CalibrationResult reports the sweep outcome.
type CalibrationResult struct {
	Circuit          string
	Depth            uint32  // minimum viable depth (valid when Passed)
	ScalingModSize   int
	RingDim          uint32
	AchievedAbsError float64 // best (smallest) worst-slot abs error seen
	Passed           bool
}

// maxSlotAbsError returns the largest per-slot absolute difference over the
// overlapping prefix of got and want.
func maxSlotAbsError(got, want []float64) float64 {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	worst := 0.0
	for i := 0; i < n; i++ {
		d := math.Abs(got[i] - want[i])
		if d > worst {
			worst = d
		}
	}
	return worst
}

// sweep drives the depth search. runAtDepth provisions+runs the circuit at a
// given depth and returns (worst-slot abs error, modulusCapHit, err). The
// first depth whose error is within Tolerance wins. If a depth hits the
// modulus cap, sweep returns ErrModulusCap. If MaxDepth is reached without
// passing, it returns Passed=false with the best error seen.
func sweep(
	p CalibrationParams,
	runAtDepth func(depth uint32) (absErr float64, modulusCapHit bool, err error),
) (CalibrationResult, error) {
	res := CalibrationResult{
		ScalingModSize:   p.Base.ScalingModSize,
		RingDim:          p.Base.RingDim,
		AchievedAbsError: math.Inf(1),
	}
	for depth := p.StartDepth; depth <= p.MaxDepth; depth++ {
		absErr, capHit, err := runAtDepth(depth)
		if err != nil {
			return res, fmt.Errorf("fhecalib: run at depth %d: %w", depth, err)
		}
		if capHit {
			return res, fmt.Errorf("%w (at depth %d)", ErrModulusCap, depth)
		}
		if absErr < res.AchievedAbsError {
			res.AchievedAbsError = absErr
		}
		if absErr <= p.Tolerance {
			res.Depth = depth
			res.Passed = true
			return res, nil
		}
	}
	return res, nil
}
