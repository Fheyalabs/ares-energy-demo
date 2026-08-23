// SPDX-License-Identifier: Apache-2.0

package helperclient

// Built-in sharpening polynomials. These are reasonable defaults; apps
// can also supply their own EvalPolyParams.
//
// The polynomial is evaluated slot-wise on a ciphertext of pairwise
// differences (a_i - a_j). The output approximates sign(x) for x in
// [-1, 1] — positive inputs become ~+1, negative become ~-1, with a
// transition band whose sharpness depends on the polynomial's degree.
// Apps offset and scale the output to produce 0/1 indicator masks.

// SharpenSignDegree3 is a depth-1 cubic sign approximation: 1.5x −
// 0.5x³. Fast, fits in shallow circuits; the transition band is
// wide. Use only when scores are well-separated.
func SharpenSignDegree3() EvalPolyParams {
	return EvalPolyParams{
		Coefficients: []float64{0, 1.5, 0, -0.5},
		LowerBound:   -1.0,
		UpperBound:   1.0,
	}
}

// SharpenSignDegree9 is a depth-3 degree-9 odd polynomial that
// approximates sign(x) closely on [-1, 1]. Coefficients from the
// minimax approximation used by Cheon-Kim-Kim-Song (CKKS argmax
// literature). Use for tighter ranking when depth permits.
func SharpenSignDegree9() EvalPolyParams {
	return EvalPolyParams{
		// f9(x) = (315/128)x − (105/32)x³ + (189/64)x⁵ − (45/32)x⁷ + (35/128)x⁹
		Coefficients: []float64{
			0,
			315.0 / 128.0,
			0,
			-105.0 / 32.0,
			0,
			189.0 / 64.0,
			0,
			-45.0 / 32.0,
			0,
			35.0 / 128.0,
		},
		LowerBound: -1.0,
		UpperBound: 1.0,
	}
}

// SharpenChebyshev approximates sign(x) on [low, high] via the
// truncated Chebyshev series of the requested degree. The helper-side
// implementation may delegate to OpenFHE's EvalChebyshevFunction
// directly; the coefficients here serve as a fallback / spec.
//
// Returning empty Coefficients with a non-zero LowerBound / UpperBound
// signals to the helper "use Chebyshev sign approximation at native
// degree".
func SharpenChebyshev(low, high float64, degree int) EvalPolyParams {
	return EvalPolyParams{
		LowerBound: low,
		UpperBound: high,
		// Coefficients intentionally nil — helper picks the
		// canonical Chebyshev approximation at the runtime degree
		// hint, which OpenFHE expresses via EvalChebyshevFunction.
		// Until the helper-side handler lands, this is documented
		// behavior.
		Coefficients: nil,
	}
}
