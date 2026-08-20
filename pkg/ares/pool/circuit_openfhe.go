// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package pool

import (
	"fmt"
	"math"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
)

// ClearingInputs are the two packed aggregate curves. Callers sum the
// individual participant ciphertexts (level-free EvalAdd) and add the
// public grid curves before calling EvalClearing.
type ClearingInputs struct {
	Supply []byte
	Demand []byte
}

// ClearingOutputs are the ciphertexts a quorum threshold-decrypts.
//
// OneHot is ~1 at the clearing bucket of each delivery slot and ~0
// elsewhere. The three masked aggregates carry S[k*], S[k*-1] and D[k*]
// at that same index, which is what participants need to compute their
// own allocation when supply exceeds demand at the crossing.
type ClearingOutputs struct {
	OneHot       []byte
	SupplyAt     []byte
	SupplyPrevAt []byte
	DemandAt     []byte
}

// tanhSeries holds the Maclaurin coefficients of tanh(z) for the odd
// powers z^1, z^3, ... z^13. The logistic has no clean factorial
// recurrence (its series involves Bernoulli numbers), so the exact
// tanh coefficients are tabulated and the identity
// sigma(u) = (1 + tanh(u/2)) / 2 supplies the rest.
var tanhSeries = []float64{
	1.0,                 // z^1
	-1.0 / 3.0,          // z^3
	2.0 / 15.0,          // z^5
	-17.0 / 315.0,       // z^7
	62.0 / 2835.0,       // z^9
	-1382.0 / 155925.0,  // z^11
	21844.0 / 6081075.0, // z^13
}

// LogisticCoeffs returns ascending-order coefficients of an odd
// polynomial approximating the logistic step 1/(1+exp(-gain*x)),
// shifted so p(0) = 0.5.
//
// Oddness is load-bearing: it puts the 0.5 crossing exactly at x = 0
// regardless of gain, so comparator softness changes the ramp's
// steepness but never displaces the clearing bucket (spec §3.5).
func LogisticCoeffs(degree int, gain float64) []float64 {
	if degree < 1 {
		degree = 1
	}
	coeffs := make([]float64, degree+1)
	coeffs[0] = 0.5
	// sigma(gain*x) = 0.5 + 0.5*tanh(gain*x/2), so the x^d coefficient is
	// 0.5 * tanhSeries[i] * (gain/2)^d for the i-th odd power d.
	half := gain / 2.0
	for i, tc := range tanhSeries {
		d := 2*i + 1
		if d > degree {
			break
		}
		coeffs[d] = 0.5 * tc * math.Pow(half, float64(d))
	}
	return coeffs
}

// EvalClearing runs the uniform-price clearing circuit (spec §3.3).
//
// Depth ledger:
//
//	E      = S - D                    0 levels
//	m      = poly(E/scale)            ceil(log2(deg)) + 1
//	mPrev  = rotate(m, -1)            0 levels
//	oneHot = m - mPrev                0 levels
//	masked = oneHot * X               1 level   (three of these)
//
// The rotation uses index -1 only, so the hot path needs exactly one
// rotation key.
func EvalClearing(
	h fhecalib.ContextHandle,
	g GridSpec,
	in ClearingInputs,
	coeffs []float64,
	scale float64,
) (ClearingOutputs, error) {
	var out ClearingOutputs
	if err := g.Validate(); err != nil {
		return out, err
	}
	if len(in.Supply) == 0 || len(in.Demand) == 0 {
		return out, fmt.Errorf("pool: both aggregate curves are required")
	}
	if len(coeffs) == 0 {
		return out, fmt.Errorf("pool: comparator coefficients are required")
	}
	if !(scale > 0) {
		return out, fmt.Errorf("pool: scale must be > 0, got %v", scale)
	}

	// Stage 3: excess supply. Level-free.
	excess, err := h.EvalSub(in.Supply, in.Demand)
	if err != nil {
		return out, fmt.Errorf("pool: excess supply: %w", err)
	}

	// Range control: divide by scale so the comparator input stays in the
	// polynomial's trusted domain. Folded into coeffs so it costs no level.
	scaled := make([]float64, len(coeffs))
	inv := 1.0
	for i, c := range coeffs {
		scaled[i] = c * inv
		inv /= scale
	}

	// Stage 4: sign test.
	step, err := h.EvalPoly(excess, scaled)
	if err != nil {
		return out, fmt.Errorf("pool: comparator: %w", err)
	}

	// Stage 5: align bucket k-1 against bucket k along the price axis.
	prev, err := h.EvalAtIndex(step, -1)
	if err != nil {
		return out, fmt.Errorf("pool: price-axis shift: %w", err)
	}

	// Stage 6: the crossing is where the step turns on, masked at each
	// delivery slot's first price bucket.
	//
	// The mask does two jobs. The rotation runs over the whole ciphertext,
	// so bucket 0 of each slot would otherwise inherit the *previous*
	// slot's last bucket (slot 0 wrapping from the end). And bucket 0 has
	// no predecessor to difference against at all: leaving it as step[0]
	// makes it a false crossing whenever the comparator has not saturated
	// by the bottom of the grid, which readily outbids the true crossing.
	//
	// So bucket 0 is a guard: never a valid clearing price. This is
	// economically benign — the grid is floored at price 0 precisely
	// because clearing at or below zero is meaningless (sellers curtail
	// rather than pay to inject) — but it does mean the usable price range
	// is buckets 1..K-1.
	diff, err := h.EvalSub(step, prev)
	if err != nil {
		return out, fmt.Errorf("pool: one-hot: %w", err)
	}
	ctMask, err := h.Encrypt(SlotBoundaryMask(g))
	if err != nil {
		return out, fmt.Errorf("pool: encrypt boundary mask: %w", err)
	}
	oneHot, err := h.EvalMult(diff, ctMask)
	if err != nil {
		return out, fmt.Errorf("pool: apply boundary mask: %w", err)
	}
	out.OneHot = oneHot

	// Stage 7: mask the aggregates so the crossing values survive decrypt.
	supplyPrev, err := h.EvalAtIndex(in.Supply, -1)
	if err != nil {
		return out, fmt.Errorf("pool: shift supply: %w", err)
	}
	for _, m := range []struct {
		dst *[]byte
		src []byte
		lbl string
	}{
		{&out.SupplyAt, in.Supply, "supply"},
		{&out.SupplyPrevAt, supplyPrev, "supply-prev"},
		{&out.DemandAt, in.Demand, "demand"},
	} {
		masked, err := h.EvalMult(oneHot, m.src)
		if err != nil {
			return out, fmt.Errorf("pool: mask %s: %w", m.lbl, err)
		}
		*m.dst = masked
	}
	return out, nil
}

// oneHotThreshold is the floor a bump must clear to count as a crossing.
//
// It is deliberately far below 1. At the crossing supply meets demand, so
// E[k*] is at or just above 0 and the comparator returns ~0.5 there — the
// bump height is p(E[k*]/scale) - p(E[k*-1]/scale), structurally capped at
// 0.5 and smaller still when the curve approaches the crossing gently.
// Measured heights on the reference cohorts are ~0.21-0.23 against a noise
// floor of ~1e-6, so this separates signal from noise by four orders of
// magnitude while accepting genuine shallow crossings.
const oneHotThreshold = 0.01

// DecodeOneHot reads the clearing bucket for each delivery slot from a
// decrypted one-hot vector.
//
// CKKS softness spreads the one-hot into a bump over a few buckets near
// the crossing, so this takes the per-slot argmax. Where the aggregate
// curve is flat the crossing is indeterminate by the mechanism itself,
// not by the crypto, so any bucket in the flat region is a valid
// tie-break (spec §3.5).
func DecodeOneHot(g GridSpec, oneHot []float64) []int {
	out := make([]int, g.NumSlots)
	for slot := 0; slot < g.NumSlots; slot++ {
		best, bestVal := NoClearing, oneHotThreshold
		for k := 0; k < g.NumBuckets; k++ {
			v := oneHot[g.Index(slot, k)]
			if v > bestVal {
				best, bestVal = k, v
			}
		}
		out[slot] = best
	}
	return out
}

// DecodeClearing reads the full clearing outcome from the four decrypted
// circuit outputs, returning the same shape as the plaintext oracle so
// the two are directly comparable.
//
// The masked aggregates carry m*S, m*S_prev and m*D where m is the
// one-hot amplitude at the clearing bucket. That amplitude is not 1 — the
// comparator returns ~0.5 at the crossing (see oneHotThreshold) — so each
// is divided by the one-hot value at the same index. The quotient is
// exact regardless of what amplitude the comparator happened to produce,
// which is what makes the readout insensitive to comparator gain.
func DecodeClearing(g GridSpec, oneHot, supplyAt, supplyPrevAt, demandAt []float64) []SlotResult {
	buckets := DecodeOneHot(g, oneHot)
	out := make([]SlotResult, g.NumSlots)
	for slot, k := range buckets {
		if k == NoClearing {
			out[slot] = SlotResult{Bucket: NoClearing}
			continue
		}
		idx := g.Index(slot, k)
		m := oneHot[idx]
		res := SlotResult{
			Bucket:     k,
			PriceCt:    g.Price(k),
			Supply:     supplyAt[idx] / m,
			SupplyPrev: supplyPrevAt[idx] / m,
			Demand:     demandAt[idx] / m,
		}
		deriveAllocation(&res)
		if res.Bucket != NoClearing {
			res.Bucket, res.PriceCt = k, g.Price(k)
		}
		out[slot] = res
	}
	return out
}

// PinnedDepth is the measured minimum multiplicative depth of the
// clearing circuit, established by TestCalibrate_ClearingCircuitDepth
// (ring 32768, ScalingModSize 50, degree-13 comparator): worst-slot
// absolute error 1.75e-4 against a 0.35 tolerance.
//
// This is a measurement, not the design estimate — the spec's ledger
// projected 7. Depth 5 is also the lowest depth at which the circuit
// runs at all (TestClearingCircuit_MinimumRunnableDepth), so accuracy is
// not the binding constraint here; the level count is.
const PinnedDepth uint32 = 5

// ClearingCircuit adapts EvalClearing to fhecalib.CircuitUnderTest so
// the depth sweep can measure the circuit instead of guessing at it.
//
// The calibrated output is the one-hot vector: it is the only output
// whose accuracy determines the clearing decision, and its plaintext
// ground truth is a clean indicator, which makes the abs-error tolerance
// meaningful.
type ClearingCircuit struct {
	Grid   GridSpec
	Supply []float64
	Demand []float64
	Coeffs []float64
	Scale  float64
}

func (ClearingCircuit) Name() string { return "pool-uniform-price-clearing" }

func (c ClearingCircuit) Inputs() [][]float64 {
	return [][]float64{c.Supply, c.Demand}
}

// Expected evaluates the same formula the circuit does, in plaintext.
//
// It deliberately mirrors EvalClearing stage for stage rather than
// returning an idealised 0/1 indicator. The calibrator's job is to find
// the depth at which FHE approximation error falls below tolerance, so
// the ground truth must isolate *that* error — comparing against an
// idealised indicator would instead measure how far the comparator
// polynomial sits from a true step, which no amount of depth can fix.
//
// Note the bump height is not 1: at the crossing E is at or just above 0,
// so the comparator returns ~0.5 and the bump is
// p(E[k*]/scale) - p(E[k*-1]/scale).
func (c ClearingCircuit) Expected(inputs [][]float64) []float64 {
	g := c.Grid
	step := make([]float64, g.Len())
	for i := range step {
		step[i] = evalPolyAt(c.Coeffs, (inputs[0][i]-inputs[1][i])/c.Scale)
	}
	mask := SlotBoundaryMask(g)
	out := make([]float64, g.Len())
	for slot := 0; slot < g.NumSlots; slot++ {
		for k := 0; k < g.NumBuckets; k++ {
			idx := g.Index(slot, k)
			prev := 0.0
			if k > 0 {
				prev = step[idx-1]
			}
			out[idx] = (step[idx] - prev) * mask[idx]
		}
	}
	return out
}

func (c ClearingCircuit) Eval(h fhecalib.ContextHandle, encInputs [][]byte) ([]byte, error) {
	if len(encInputs) != 2 {
		return nil, fmt.Errorf("pool: want 2 encrypted inputs, got %d", len(encInputs))
	}
	out, err := EvalClearing(h, c.Grid, ClearingInputs{
		Supply: encInputs[0],
		Demand: encInputs[1],
	}, c.Coeffs, c.Scale)
	if err != nil {
		return nil, err
	}
	return out.OneHot, nil
}

// evalPolyAt evaluates an ascending-order coefficient list by Horner.
func evalPolyAt(coeffs []float64, x float64) float64 {
	acc := 0.0
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc = acc*x + coeffs[i]
	}
	return acc
}
