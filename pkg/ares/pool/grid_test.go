// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"math"
	"testing"
)

func testGrid() GridSpec {
	return GridSpec{TickCt: 0.25, NumBuckets: 8, NumSlots: 2}
}

func TestGridSpec_PriceAndIndex(t *testing.T) {
	g := testGrid()
	if got := g.Price(0); got != 0.0 {
		t.Errorf("Price(0) = %v, want 0", got)
	}
	if got := g.Price(7); math.Abs(got-1.75) > 1e-12 {
		t.Errorf("Price(7) = %v, want 1.75", got)
	}
	if got := g.Len(); got != 16 {
		t.Errorf("Len() = %d, want 16", got)
	}
	if got := g.Index(1, 3); got != 11 {
		t.Errorf("Index(1,3) = %d, want 11", got)
	}
}

func TestGridSpec_ValidateRejectsBadSpecs(t *testing.T) {
	for name, g := range map[string]GridSpec{
		"zero tick":    {TickCt: 0, NumBuckets: 8, NumSlots: 2},
		"zero buckets": {TickCt: 0.25, NumBuckets: 0, NumSlots: 2},
		"zero slots":   {TickCt: 0.25, NumBuckets: 8, NumSlots: 0},
		"neg tick":     {TickCt: -0.25, NumBuckets: 8, NumSlots: 2},
	} {
		if err := g.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want error", name)
		}
	}
}

// A seller offering q at price b contributes q to every bucket whose
// grid price is >= b, and 0 below. Spec §3.1.
func TestEncodeSupply_StepAtBid(t *testing.T) {
	g := testGrid()
	got, err := EncodeSupply(g, []Offer{{Slot: 0, PriceCt: 0.75, Quantity: 4.0}})
	if err != nil {
		t.Fatalf("EncodeSupply: %v", err)
	}
	// bucket 3 has price 0.75 -> first bucket at or above the bid.
	want := []float64{0, 0, 0, 4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-12 {
			t.Fatalf("slot index %d: got %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

// A buyer willing to pay up to v contributes e to every bucket at or
// below v, and 0 above.
func TestEncodeDemand_StepAtLimit(t *testing.T) {
	g := testGrid()
	got, err := EncodeDemand(g, []Offer{{Slot: 1, PriceCt: 1.0, Quantity: 3.0}})
	if err != nil {
		t.Fatalf("EncodeDemand: %v", err)
	}
	// bucket 4 has price 1.00 -> last bucket at or below the limit.
	want := []float64{0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 0, 0, 0}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-12 {
			t.Fatalf("slot index %d: got %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

// Multiple offers in one slot accumulate — this is what gives a
// participant a multi-step offer curve for free (spec §3.1).
func TestEncodeSupply_MultiStepAccumulates(t *testing.T) {
	g := testGrid()
	got, err := EncodeSupply(g, []Offer{
		{Slot: 0, PriceCt: 0.25, Quantity: 2.0},
		{Slot: 0, PriceCt: 1.00, Quantity: 5.0},
	})
	if err != nil {
		t.Fatalf("EncodeSupply: %v", err)
	}
	want := []float64{0, 2, 2, 2, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-12 {
			t.Fatalf("index %d: got %v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

// A bid above the top of the grid never clears; a demand limit below
// the bottom never clears. Neither is an error.
func TestEncode_OutOfBandOffersAreEmpty(t *testing.T) {
	g := testGrid()
	sup, err := EncodeSupply(g, []Offer{{Slot: 0, PriceCt: 99.0, Quantity: 4.0}})
	if err != nil {
		t.Fatalf("EncodeSupply: %v", err)
	}
	for i, v := range sup {
		if v != 0 {
			t.Fatalf("supply index %d = %v, want 0", i, v)
		}
	}
	dem, err := EncodeDemand(g, []Offer{{Slot: 0, PriceCt: -5.0, Quantity: 4.0}})
	if err != nil {
		t.Fatalf("EncodeDemand: %v", err)
	}
	for i, v := range dem {
		if v != 0 {
			t.Fatalf("demand index %d = %v, want 0", i, v)
		}
	}
}

func TestEncode_RejectsBadOffers(t *testing.T) {
	g := testGrid()
	if _, err := EncodeSupply(g, []Offer{{Slot: 5, PriceCt: 1, Quantity: 1}}); err == nil {
		t.Error("slot out of range: want error")
	}
	if _, err := EncodeSupply(g, []Offer{{Slot: 0, PriceCt: 1, Quantity: -1}}); err == nil {
		t.Error("negative quantity: want error")
	}
}

// PaddingValue implements the ARES-BC normalising coordinate from spec
// §3.6: ||a||^2 + z^2 = C, so the decrypted bound is constant and
// therefore leaks nothing about where the step sits.
func TestPaddingValue_MakesNormConstant(t *testing.T) {
	vec := []float64{3, 4} // ||vec||^2 = 25
	z, err := PaddingValue(vec, 41.0)
	if err != nil {
		t.Fatalf("PaddingValue: %v", err)
	}
	if math.Abs(z-4.0) > 1e-12 {
		t.Errorf("z = %v, want 4", z)
	}
	total := 0.0
	for _, v := range vec {
		total += v * v
	}
	total += z * z
	if math.Abs(total-41.0) > 1e-9 {
		t.Errorf("||a||^2 + z^2 = %v, want 41", total)
	}
}

func TestPaddingValue_RejectsOverBudget(t *testing.T) {
	if _, err := PaddingValue([]float64{10}, 25.0); err == nil {
		t.Error("norm exceeds C: want error")
	}
}
