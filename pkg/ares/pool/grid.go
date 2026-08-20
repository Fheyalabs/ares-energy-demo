// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"fmt"
	"math"
)

// tickEpsilon absorbs float noise when mapping a price onto a bucket
// boundary, so a bid landing exactly on a grid tick maps to that tick
// rather than to its neighbour.
const tickEpsilon = 1e-9

// GridSpec pins the public price grid and the packing layout for one
// epoch. Layout is price-minor: index = slot*NumBuckets + bucket, so a
// rotation by one slot shifts along the price axis.
type GridSpec struct {
	TickCt     float64 // price tick, ct/kWh
	NumBuckets int     // K — grid points per delivery slot
	NumSlots   int     // delivery slots packed per ciphertext
}

// Validate reports whether the spec is usable.
func (g GridSpec) Validate() error {
	if !(g.TickCt > 0) {
		return fmt.Errorf("pool: TickCt must be > 0, got %v", g.TickCt)
	}
	if g.NumBuckets <= 0 {
		return fmt.Errorf("pool: NumBuckets must be > 0, got %d", g.NumBuckets)
	}
	if g.NumSlots <= 0 {
		return fmt.Errorf("pool: NumSlots must be > 0, got %d", g.NumSlots)
	}
	return nil
}

// Price returns the grid price at a bucket index.
func (g GridSpec) Price(bucket int) float64 { return g.TickCt * float64(bucket) }

// Len returns the number of plaintext slots one packed curve occupies.
func (g GridSpec) Len() int { return g.NumSlots * g.NumBuckets }

// Index maps a (delivery slot, price bucket) pair to its plaintext slot.
func (g GridSpec) Index(slot, bucket int) int { return slot*g.NumBuckets + bucket }

// Offer is one participant's bid for one delivery slot. For a seller
// PriceCt is the lowest price they will accept; for a buyer it is the
// highest price they will pay.
type Offer struct {
	Slot     int
	PriceCt  float64
	Quantity float64
}

func (g GridSpec) validateOffers(offers []Offer) error {
	if err := g.Validate(); err != nil {
		return err
	}
	for i, o := range offers {
		if o.Slot < 0 || o.Slot >= g.NumSlots {
			return fmt.Errorf("pool: offer %d: slot %d out of range [0,%d)", i, o.Slot, g.NumSlots)
		}
		if o.Quantity < 0 {
			return fmt.Errorf("pool: offer %d: negative quantity %v", i, o.Quantity)
		}
		if math.IsNaN(o.PriceCt) || math.IsInf(o.PriceCt, 0) {
			return fmt.Errorf("pool: offer %d: non-finite price %v", i, o.PriceCt)
		}
	}
	return nil
}

// EncodeSupply lays out a seller's packed step curve:
// a[slot*K+k] = sum of quantities whose bid price is <= Price(k).
func EncodeSupply(g GridSpec, offers []Offer) ([]float64, error) {
	if err := g.validateOffers(offers); err != nil {
		return nil, err
	}
	out := make([]float64, g.Len())
	for _, o := range offers {
		// First bucket at or above the bid price.
		first := int(math.Ceil(o.PriceCt/g.TickCt - tickEpsilon))
		if first < 0 {
			first = 0
		}
		for k := first; k < g.NumBuckets; k++ {
			out[g.Index(o.Slot, k)] += o.Quantity
		}
	}
	return out, nil
}

// EncodeDemand lays out a buyer's packed step curve:
// d[slot*K+k] = sum of quantities whose limit price is >= Price(k).
func EncodeDemand(g GridSpec, offers []Offer) ([]float64, error) {
	if err := g.validateOffers(offers); err != nil {
		return nil, err
	}
	out := make([]float64, g.Len())
	for _, o := range offers {
		// Last bucket at or below the limit price.
		last := int(math.Floor(o.PriceCt/g.TickCt + tickEpsilon))
		if last >= g.NumBuckets {
			last = g.NumBuckets - 1
		}
		for k := 0; k <= last; k++ {
			out[g.Index(o.Slot, k)] += o.Quantity
		}
	}
	return out, nil
}

// SlotBoundaryMask returns a plaintext vector that is 0 at every
// delivery slot's first price bucket and 1 everywhere else.
//
// A slot rotation along the packed price axis crosses delivery-slot
// boundaries, so the circuit multiplies the rotated curve by this mask to
// stop each slot's bucket 0 from inheriting the previous slot's last
// bucket.
func SlotBoundaryMask(g GridSpec) []float64 {
	out := make([]float64, g.Len())
	for i := range out {
		out[i] = 1
	}
	for slot := 0; slot < g.NumSlots; slot++ {
		out[g.Index(slot, 0)] = 0
	}
	return out
}

// PaddingValue returns the ARES-BC normalising coordinate z such that
// ||vec||^2 + z^2 == c.
//
// Without it the decrypted bound ||x-center||^2 varies with where the
// curve's step sits, which would turn the bound check into an oracle for
// the very bid it is meant to protect. With it the check always decrypts
// the same constant while still enforcing ||vec||^2 <= c.
func PaddingValue(vec []float64, c float64) (float64, error) {
	norm := 0.0
	for _, v := range vec {
		norm += v * v
	}
	if norm > c {
		return 0, fmt.Errorf("pool: squared norm %v exceeds budget %v", norm, c)
	}
	return math.Sqrt(c - norm), nil
}
