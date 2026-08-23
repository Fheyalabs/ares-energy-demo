// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package fhecalib

// squareCircuit is a reference CircuitUnderTest: element-wise square of one
// input vector (one EvalMult = 1 multiplicative level). Used to exercise the
// calibrator itself — the known minimum depth is 1.
type squareCircuit struct {
	in []float64
}

func (squareCircuit) Name() string { return "elementwise-square" }

func (c squareCircuit) Inputs() [][]float64 { return [][]float64{c.in} }

func (c squareCircuit) Expected(inputs [][]float64) []float64 {
	v := inputs[0]
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = x * x
	}
	return out
}

func (squareCircuit) Eval(h ContextHandle, encInputs [][]byte) ([]byte, error) {
	return h.EvalMult(encInputs[0], encInputs[0])
}
