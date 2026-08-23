// SPDX-License-Identifier: Apache-2.0

package helperclient

// Decomposable scoring primitives. Each maps to one homomorphic
// operation an application's scoring circuit may want to compose.
// Polynomials are passed as float64 slices in coefficient-ascending
// order (coeffs[0] = constant, coeffs[1] = x, coeffs[2] = x², …),
// matching OpenFHE's EvalPoly convention.
//
// Server-side (helper) implementation status:
//   - eval_add / eval_mult / eval_sub: planned, currently
//     ErrNotImplemented.
//   - eval_const_mult: planned.
//   - eval_poly: planned. The single most important swappable
//     primitive — sharpening polynomials (Chebyshev sign
//     approximations, low-degree odd polynomials, custom curves)
//     plug in here.
//   - argmax: composite that calls eval_poly + arithmetic primitives
//     to build a one-hot mask of the maximum ciphertext.
//
// All ops require evalKeys (the joint EvalMult + EvalSum + rotation
// key bundle produced by the keygen rounds) because every homomorphic
// op that isn't pure addition consumes eval-mult or rotation keys.

// EvalAdd returns ct(a) + ct(b) homomorphically.
func (c *Client) EvalAdd(params ContractParams, evalKeys, ctA, ctB []byte) ([]byte, error) {
	resp, err := c.call(Request{
		Op:          "eval_add",
		Params:      params,
		EvalKeys:    encodeB64(evalKeys),
		CiphertextA: encodeB64(ctA),
		CiphertextB: encodeB64(ctB),
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// EvalSub returns ct(a) − ct(b) homomorphically.
func (c *Client) EvalSub(params ContractParams, evalKeys, ctA, ctB []byte) ([]byte, error) {
	resp, err := c.call(Request{
		Op:          "eval_sub",
		Params:      params,
		EvalKeys:    encodeB64(evalKeys),
		CiphertextA: encodeB64(ctA),
		CiphertextB: encodeB64(ctB),
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// EvalMult returns ct(a) × ct(b) homomorphically (consumes one level).
func (c *Client) EvalMult(params ContractParams, evalKeys, ctA, ctB []byte) ([]byte, error) {
	resp, err := c.call(Request{
		Op:          "eval_mult",
		Params:      params,
		EvalKeys:    encodeB64(evalKeys),
		CiphertextA: encodeB64(ctA),
		CiphertextB: encodeB64(ctB),
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// EvalConstMult multiplies a ciphertext by a cleartext constant.
// Does not consume a level under CKKS.
func (c *Client) EvalConstMult(params ContractParams, ct []byte, scalar float64) ([]byte, error) {
	resp, err := c.call(Request{
		Op:         "eval_const_mult",
		Params:     params,
		Ciphertext: encodeB64(ct),
		Scalar:     scalar,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// EvalPolyParams configures a polynomial evaluation:
//
//	Coefficients: ascending-order coefficient vector.
//	LowerBound / UpperBound: the domain of the input. OpenFHE uses
//	  this for Chebyshev expansion / scaling — supplying the actual
//	  expected input range yields accurate evaluation; over-wide
//	  bounds waste precision.
type EvalPolyParams struct {
	Coefficients []float64
	LowerBound   float64
	UpperBound   float64
}

// EvalPoly evaluates the polynomial p(x) = Σ coeffs[i] · xⁱ on the
// ciphertext (slot-wise). The depth of the resulting ciphertext rises
// roughly with log2(degree). This is the swappable sharpening
// primitive: argmax callers supply whatever polynomial matches their
// depth budget.
//
// Common choices:
//   - sign(x) ≈ Chebyshev-9 on [-1, 1] for a sharp comparator at ~4
//     levels of depth.
//   - low-degree odd polynomial (3 or 5) for shallow circuits where
//     2-3 levels are available.
//   - app-specific monotone curves for ranking with smooth ties.
func (c *Client) EvalPoly(params ContractParams, evalKeys, ct []byte, poly EvalPolyParams) ([]byte, error) {
	resp, err := c.call(Request{
		Op:             "eval_poly",
		Params:         params,
		EvalKeys:       encodeB64(evalKeys),
		Ciphertext:     encodeB64(ct),
		Coefficients:   poly.Coefficients,
		PolyLowerBound: poly.LowerBound,
		PolyUpperBound: poly.UpperBound,
	})
	if err != nil {
		return nil, err
	}
	return decodeB64(resp.Ciphertext)
}

// ArgmaxParams configures a composite argmax over N candidate
// ciphertexts. SharpeningPoly is the polynomial used to convert
// pairwise differences into ~0/1 indicators; tighter polynomials
// produce cleaner masks at the cost of higher depth.
type ArgmaxParams struct {
	SharpeningPoly EvalPolyParams
}

// Argmax returns a list of N "mask" ciphertexts where the winner's
// mask is approximately 1.0 and losers' masks are approximately 0.0.
// Apps fuse the mask with the candidates (or with a payload vector)
// to recover the winning value.
//
// The op is a composite implemented on top of EvalSub + EvalPoly +
// EvalMult (selector tree). It exists as a single helper call rather
// than a Go-side sequence so the helper can keep all intermediate
// ciphertexts in-process — every intermediate over the IPC boundary
// would be ~hundreds of KiB.
func (c *Client) Argmax(params ContractParams, evalKeys []byte, ciphertexts [][]byte, p ArgmaxParams) ([][]byte, error) {
	enc := make([]string, len(ciphertexts))
	for i, ct := range ciphertexts {
		enc[i] = encodeB64(ct)
	}
	resp, err := c.call(Request{
		Op:             "argmax",
		Params:         params,
		EvalKeys:       encodeB64(evalKeys),
		Ciphertexts:    enc,
		Coefficients:   p.SharpeningPoly.Coefficients,
		PolyLowerBound: p.SharpeningPoly.LowerBound,
		PolyUpperBound: p.SharpeningPoly.UpperBound,
	})
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(resp.Ciphertexts))
	for i, s := range resp.Ciphertexts {
		raw, err := decodeB64(s)
		if err != nil {
			return nil, err
		}
		out[i] = raw
	}
	return out, nil
}
