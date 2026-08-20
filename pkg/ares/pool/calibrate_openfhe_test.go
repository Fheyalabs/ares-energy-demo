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
