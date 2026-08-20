// SPDX-License-Identifier: Apache-2.0

package pool

import "fmt"

// NoClearing is the Bucket value for a delivery slot where aggregate
// excess supply never turns non-negative inside the grid.
const NoClearing = -1

// SlotResult is the clearing outcome for one delivery slot.
//
// Every participant can derive their own allocation from Bucket plus
// their own private curve; the ratios cover the case where supply at the
// clearing bucket exceeds demand and sellers must be rationed.
type SlotResult struct {
	Bucket     int     // k*, or NoClearing
	PriceCt    float64 // Price(k*)
	Supply     float64 // S[k*]
	SupplyPrev float64 // S[k*-1], 0 when k* == 0
	Demand     float64 // D[k*]
	Cleared    float64 // min(S[k*], D[k*])

	// MarginalRatio is the dispatched fraction of the marginal tranche
	// S[k*] - S[k*-1] (sellers whose bid is exactly at the clearing
	// price). InframarginalRatio is the dispatched fraction of S[k*-1]
	// (strictly cheaper sellers), which is 1 unless even they oversupply.
	MarginalRatio      float64
	InframarginalRatio float64
}

// ClearPlaintext computes the reference clearing for every delivery slot
// in a packed supply/demand pair. It is the ground truth the homomorphic
// circuit is validated against.
//
// E[k] = S[k] - D[k] is non-decreasing in k, so its first non-negative
// bucket is the unique crossing.
func ClearPlaintext(g GridSpec, supply, demand []float64) ([]SlotResult, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if len(supply) != g.Len() {
		return nil, fmt.Errorf("pool: supply has %d slots, want %d", len(supply), g.Len())
	}
	if len(demand) != g.Len() {
		return nil, fmt.Errorf("pool: demand has %d slots, want %d", len(demand), g.Len())
	}

	out := make([]SlotResult, g.NumSlots)
	for slot := 0; slot < g.NumSlots; slot++ {
		out[slot] = clearSlot(g, supply, demand, slot)
	}
	return out, nil
}

func clearSlot(g GridSpec, supply, demand []float64, slot int) SlotResult {
	res := SlotResult{Bucket: NoClearing}
	for k := 0; k < g.NumBuckets; k++ {
		i := g.Index(slot, k)
		if supply[i]-demand[i] < 0 {
			continue
		}
		res.Bucket = k
		res.PriceCt = g.Price(k)
		res.Supply = supply[i]
		res.Demand = demand[i]
		if k > 0 {
			res.SupplyPrev = supply[g.Index(slot, k-1)]
		}
		break
	}
	if res.Bucket == NoClearing {
		return res
	}

	deriveAllocation(&res)
	return res
}

// deriveAllocation fills Cleared and the two rationing ratios from
// Supply, SupplyPrev and Demand, or resets the result to NoClearing when
// the crossing turns out to be degenerate. Shared by the plaintext oracle
// and by DecodeClearing, so the circuit and the oracle agree by
// construction rather than by coincidence.
func deriveAllocation(res *SlotResult) {
	res.Cleared = res.Supply
	if res.Demand < res.Cleared {
		res.Cleared = res.Demand
	}

	// A non-negative E[k] is not sufficient for a trade: above the last
	// bucket any buyer will pay, both curves are zero, so E == 0 without
	// anything crossing. Reject that degenerate case.
	//
	// One check suffices. S is non-decreasing and D non-increasing, so
	// Cleared == 0 here implies D[k*] == 0 (S[k*] == 0 with D[k*] > 0
	// would make E[k*] negative), and D stays 0 for every later bucket —
	// so no later bucket can trade either.
	if res.Cleared <= 0 {
		*res = SlotResult{Bucket: NoClearing}
		return
	}

	// Strictly cheaper sellers dispatch fully unless they alone oversupply.
	res.InframarginalRatio = 1
	if res.SupplyPrev > res.Cleared && res.SupplyPrev > 0 {
		res.InframarginalRatio = res.Cleared / res.SupplyPrev
	}

	// The marginal tranche absorbs whatever demand is left.
	tranche := res.Supply - res.SupplyPrev
	if tranche > 0 {
		ratio := (res.Cleared - res.SupplyPrev) / tranche
		if ratio < 0 {
			ratio = 0
		}
		if ratio > 1 {
			ratio = 1
		}
		res.MarginalRatio = ratio
	}
}
