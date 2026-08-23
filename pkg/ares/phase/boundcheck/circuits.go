// SPDX-License-Identifier: Apache-2.0

package boundcheck

import (
	"math"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
)

// NormCircuit is the SC-5 embedding norm check: center 0, check value ‖x‖²,
// bound [1-Eps, 1+Eps]. NDim is the embedding dimension (the number of CKKS
// slots summed); it must match the input vector length at runtime (CtxInputDim).
type NormCircuit struct {
	Eps  float64
	NDim int
}

func (NormCircuit) Name() string { return "norm" }

// Inputs returns a representative unit-norm vector of length NDim (for depth calibration).
func (c NormCircuit) Inputs() [][]float64 {
	v := make([]float64, c.NDim)
	for i := range v {
		v[i] = 1.0 / math.Sqrt(float64(c.NDim)) // ‖v‖² = 1
	}
	return [][]float64{v}
}

func (NormCircuit) Expected(in [][]float64) []float64 {
	return []float64{sumOfSquares(in[0])}
}

func (c NormCircuit) Eval(h fhecalib.ContextHandle, enc [][]byte) ([]byte, error) {
	return h.EvalProductSum(enc[0], enc[0], c.NDim)
}

func (c NormCircuit) Bound() Bound { return Bound{Lo: 1 - c.Eps, Hi: 1 + c.Eps} }

// Dim returns the expected input-vector dimension for this circuit.
func (c NormCircuit) Dim() int { return c.NDim }

// DistanceBoundCircuit checks ‖x - Center‖² ∈ [Lo, Hi] (public Center). Covers
// geographic-radius and multi-dimensional resource budgets.
type DistanceBoundCircuit struct {
	Center []float64
	Lo, Hi float64
}

func (DistanceBoundCircuit) Name() string { return "distance" }

// Inputs returns the center itself (squared distance 0 — a representative
// in-bound point for calibration).
func (c DistanceBoundCircuit) Inputs() [][]float64 { return [][]float64{c.Center} }

func (c DistanceBoundCircuit) Expected(in [][]float64) []float64 {
	v := in[0]
	s := 0.0
	for i := range v {
		d := v[i] - c.Center[i]
		s += d * d
	}
	return []float64{s}
}

func (c DistanceBoundCircuit) Eval(h fhecalib.ContextHandle, enc [][]byte) ([]byte, error) {
	shifted, err := h.EvalSubConst(enc[0], c.Center)
	if err != nil {
		return nil, err
	}
	return h.EvalProductSum(shifted, shifted, len(c.Center))
}

func (c DistanceBoundCircuit) Bound() Bound { return Bound{Lo: c.Lo, Hi: c.Hi} }

// Dim returns the expected input-vector dimension for this circuit.
func (c DistanceBoundCircuit) Dim() int { return len(c.Center) }

func sumOfSquares(v []float64) float64 {
	s := 0.0
	for _, x := range v {
		s += x * x
	}
	return s
}

// Compile-time assertions: both circuits must satisfy the BoundCircuit
// interface (which embeds fhecalib.CircuitUnderTest).
var (
	_ BoundCircuit = NormCircuit{}
	_ BoundCircuit = DistanceBoundCircuit{}
)
