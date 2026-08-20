// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package pool

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// The depth sweep is the gate that turns the spec's estimate into a
// measurement. It is slow, so it is skipped under -short (CI).
func TestCalibrate_ClearingCircuitDepth(t *testing.T) {
	if testing.Short() {
		t.Skip("depth sweep is slow; run without -short")
	}
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.75, Quantity: 4},
		{Slot: 1, PriceCt: 1.50, Quantity: 2},
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{
		{Slot: 0, PriceCt: 1.75, Quantity: 4},
		{Slot: 1, PriceCt: 1.75, Quantity: 2},
	})

	cut := ClearingCircuit{
		Grid:   g,
		Supply: sup,
		Demand: dem,
		Coeffs: LogisticCoeffs(13, 4.0),
		Scale:  8.0,
	}
	// RingDim 32768 is required, not chosen for realism. Calibrate enforces
	// the 128-bit-classic modulus budget itself (fhecalib.exceedsModulusBudget):
	// a depth-d chain needs 60 + d*ScalingModSize bits and the ring admits
	// ring*1761/65536. At depth 14 / ScalingModSize 50 that is 760 bits,
	// requiring ring >= 28288 -> 32768. Any smaller ring returns
	// ErrModulusCap before the sweep starts, regardless of the insecure opt-out
	// (which only affects the cgo bridge, not this pre-flight check).
	res, err := fhecalib.Calibrate(cut, fhecalib.CalibrationParams{
		Base: helperclient.ContractParams{RingDim: 32768, ScalingModSize: 50},
		// StartDepth must be at or above the lowest depth at which the
		// circuit can *run*: fhecalib.sweep treats an evaluation error as
		// fatal rather than "try deeper", so starting too shallow aborts
		// the sweep with "EvalMult failed" instead of advancing.
		// TestClearingCircuit_MinimumRunnableDepth pins that floor at 5.
		StartDepth: 5,
		MaxDepth:   14,
		Tolerance:  0.35,
	}, g.Len())
	if err != nil {
		t.Fatalf("Calibrate: %v", err)
	}
	if !res.Passed {
		t.Fatalf("no depth in [4,14] met tolerance; best abs error %v", res.AchievedAbsError)
	}
	t.Logf("PINNED DEPTH = %d (ring %d, abs error %v)", res.Depth, res.RingDim, res.AchievedAbsError)

	if PinnedDepth != 0 && res.Depth > PinnedDepth {
		t.Errorf("measured depth %d exceeds PinnedDepth %d — update the constant and the spec",
			res.Depth, PinnedDepth)
	}
}

// The circuit hard-fails rather than degrading when depth is
// insufficient, and fhecalib.sweep aborts on an evaluation error instead
// of advancing to the next depth. So the sweep's StartDepth must be at or
// above the lowest runnable depth; this test records where that floor is.
func TestClearingCircuit_MinimumRunnableDepth(t *testing.T) {
	if testing.Short() {
		t.Skip("provisions several CKKS contexts; slow")
	}
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{{Slot: 0, PriceCt: 0.75, Quantity: 4}})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 1.75, Quantity: 4}})

	first := uint32(0)
	for depth := uint32(3); depth <= 10; depth++ {
		env := newTestEnv(t, 8192, depth)
		ctS, err := env.handle.Encrypt(sup)
		if err != nil {
			t.Fatalf("depth %d: encrypt supply: %v", depth, err)
		}
		ctD, err := env.handle.Encrypt(dem)
		if err != nil {
			t.Fatalf("depth %d: encrypt demand: %v", depth, err)
		}
		_, err = EvalClearing(env.handle, g, ClearingInputs{Supply: ctS, Demand: ctD},
			LogisticCoeffs(13, 4.0), 8.0)
		if err != nil {
			t.Logf("depth %2d: cannot run (%v)", depth, err)
			continue
		}
		t.Logf("depth %2d: runs", depth)
		if first == 0 {
			first = depth
		}
	}
	if first == 0 {
		t.Fatal("circuit did not run at any depth in [3,10]")
	}
	t.Logf("MINIMUM RUNNABLE DEPTH = %d", first)
}

// step(E) must be non-decreasing along the price axis within each
// delivery slot. If CKKS noise makes it dip, the one-hot picks up a
// spurious second bump and the clearing bucket becomes ambiguous.
// Spec §3.4 names this as the specific failure mode to test for.
func TestComparator_MonotoneAlongPriceAxis(t *testing.T) {
	g := testGrid()
	// A deliberately shallow crossing: supply ramps in small steps so
	// E[k] passes slowly through zero — the hardest case for monotonicity.
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.25, Quantity: 1},
		{Slot: 0, PriceCt: 0.50, Quantity: 1},
		{Slot: 0, PriceCt: 0.75, Quantity: 1},
		{Slot: 0, PriceCt: 1.00, Quantity: 1},
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 1.75, Quantity: 3}})

	env := newTestEnv(t, 8192, PinnedDepth)
	h := env.handle

	ctS, err := h.Encrypt(sup)
	if err != nil {
		t.Fatalf("encrypt supply: %v", err)
	}
	ctD, err := h.Encrypt(dem)
	if err != nil {
		t.Fatalf("encrypt demand: %v", err)
	}

	excess, err := h.EvalSub(ctS, ctD)
	if err != nil {
		t.Fatalf("excess: %v", err)
	}
	coeffs := LogisticCoeffs(13, 4.0)
	const scale = 8.0
	scaled := make([]float64, len(coeffs))
	inv := 1.0
	for i, c := range coeffs {
		scaled[i] = c * inv
		inv /= scale
	}
	step, err := h.EvalPoly(excess, scaled)
	if err != nil {
		t.Fatalf("comparator: %v", err)
	}

	got := env.decrypt(t, step, g.Len())
	// Allow a small noise dip; anything larger is a real inversion.
	const slack = 0.02
	for slot := 0; slot < g.NumSlots; slot++ {
		for k := 1; k < g.NumBuckets; k++ {
			prev := got[g.Index(slot, k-1)]
			cur := got[g.Index(slot, k)]
			if cur < prev-slack {
				t.Errorf("slot %d bucket %d: step dipped %v -> %v (slack %v); "+
					"comparator is non-monotone at depth %d",
					slot, k, prev, cur, slack, PinnedDepth)
			}
		}
	}
}

// A monotone odd comparator crosses 0.5 at E == 0 regardless of gain.
// If this holds, comparator softness changes the ramp's steepness but
// never displaces the clearing bucket (spec §3.5).
func TestComparator_CrossingIndependentOfGain(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the circuit three times; slow")
	}
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{{Slot: 0, PriceCt: 0.75, Quantity: 4}})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 1.75, Quantity: 4}})
	want, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}

	env := newTestEnv(t, 8192, PinnedDepth)
	h := env.handle
	ctS, err := h.Encrypt(sup)
	if err != nil {
		t.Fatalf("encrypt supply: %v", err)
	}
	ctD, err := h.Encrypt(dem)
	if err != nil {
		t.Fatalf("encrypt demand: %v", err)
	}

	for _, gain := range []float64{2.0, 3.0, 4.0} {
		out, err := EvalClearing(h, g, ClearingInputs{Supply: ctS, Demand: ctD},
			LogisticCoeffs(13, gain), 8.0)
		if err != nil {
			t.Fatalf("gain %v: EvalClearing: %v", gain, err)
		}
		got := DecodeOneHot(g, env.decrypt(t, out.OneHot, g.Len()))
		if got[0] != want[0].Bucket {
			t.Errorf("gain %v: bucket %d, want %d", gain, got[0], want[0].Bucket)
		}
	}
}
