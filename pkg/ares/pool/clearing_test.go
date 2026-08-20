// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"math"
	"testing"
)

func mustEncode(t *testing.T, fn func(GridSpec, []Offer) ([]float64, error), g GridSpec, offers []Offer) []float64 {
	t.Helper()
	v, err := fn(g, offers)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return v
}

// One seller at 0.75 with 4 kWh, one buyer at 1.25 with 4 kWh.
// E[k] = S[k]-D[k] first turns non-negative at bucket 3 (price 0.75),
// where S=4 and D=4.
func TestClearPlaintext_SimpleCrossing(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{{Slot: 0, PriceCt: 0.75, Quantity: 4}})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 1.25, Quantity: 4}})

	res, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("ClearPlaintext: %v", err)
	}
	got := res[0]
	if got.Bucket != 3 {
		t.Fatalf("Bucket = %d, want 3 (result %+v)", got.Bucket, got)
	}
	if math.Abs(got.PriceCt-0.75) > 1e-12 {
		t.Errorf("PriceCt = %v, want 0.75", got.PriceCt)
	}
	if math.Abs(got.Cleared-4) > 1e-12 {
		t.Errorf("Cleared = %v, want 4", got.Cleared)
	}
}

// No seller is willing to trade inside the grid: no crossing.
func TestClearPlaintext_NoCrossing(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, nil)
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 1.0, Quantity: 4}})

	res, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("ClearPlaintext: %v", err)
	}
	if res[0].Bucket != NoClearing {
		t.Errorf("Bucket = %d, want NoClearing", res[0].Bucket)
	}
	if res[0].Cleared != 0 {
		t.Errorf("Cleared = %v, want 0", res[0].Cleared)
	}
}

// Two sellers below the crossing plus one at it. Demand is 5.
// Inframarginal supply (bids strictly cheaper) is 4, marginal tranche
// is 6, so the marginal tranche is rationed to (5-4)/6.
func TestClearPlaintext_MarginalRationing(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.25, Quantity: 4},
		{Slot: 0, PriceCt: 0.75, Quantity: 6},
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{{Slot: 0, PriceCt: 2.0, Quantity: 5}})

	res, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("ClearPlaintext: %v", err)
	}
	got := res[0]
	if got.Bucket != 3 {
		t.Fatalf("Bucket = %d, want 3 (result %+v)", got.Bucket, got)
	}
	if math.Abs(got.SupplyPrev-4) > 1e-12 {
		t.Errorf("SupplyPrev = %v, want 4", got.SupplyPrev)
	}
	if math.Abs(got.Supply-10) > 1e-12 {
		t.Errorf("Supply = %v, want 10", got.Supply)
	}
	if math.Abs(got.Cleared-5) > 1e-12 {
		t.Errorf("Cleared = %v, want 5", got.Cleared)
	}
	if math.Abs(got.InframarginalRatio-1) > 1e-12 {
		t.Errorf("InframarginalRatio = %v, want 1", got.InframarginalRatio)
	}
	wantMarginal := 1.0 / 6.0
	if math.Abs(got.MarginalRatio-wantMarginal) > 1e-12 {
		t.Errorf("MarginalRatio = %v, want %v", got.MarginalRatio, wantMarginal)
	}
}

// Each delivery slot clears independently within one packed vector.
func TestClearPlaintext_SlotsAreIndependent(t *testing.T) {
	g := testGrid()
	sup := mustEncode(t, EncodeSupply, g, []Offer{
		{Slot: 0, PriceCt: 0.25, Quantity: 2},
		{Slot: 1, PriceCt: 1.50, Quantity: 2},
	})
	dem := mustEncode(t, EncodeDemand, g, []Offer{
		{Slot: 0, PriceCt: 2.0, Quantity: 2},
		{Slot: 1, PriceCt: 2.0, Quantity: 2},
	})

	res, err := ClearPlaintext(g, sup, dem)
	if err != nil {
		t.Fatalf("ClearPlaintext: %v", err)
	}
	if res[0].Bucket != 1 {
		t.Errorf("slot 0 Bucket = %d, want 1", res[0].Bucket)
	}
	if res[1].Bucket != 6 {
		t.Errorf("slot 1 Bucket = %d, want 6", res[1].Bucket)
	}
}

func TestClearPlaintext_RejectsWrongLength(t *testing.T) {
	g := testGrid()
	if _, err := ClearPlaintext(g, make([]float64, 4), make([]float64, g.Len())); err == nil {
		t.Error("short supply vector: want error")
	}
}
