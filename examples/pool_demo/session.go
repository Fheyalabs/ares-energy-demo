// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sync"

	"github.com/Fheyalabs/ares-core/pkg/ares/pool"
)

// Demo grid: 0.25 ct ticks over [0, 15.75], one delivery slot at a time.
// Bucket 0 is a guard and never clears, so usable prices are 0.25..15.75.
const (
	TickCt       = 0.25
	NumBuckets   = 64
	MaxGridPrice = TickCt * float64(NumBuckets-1)
)

// DemoGrid is the public price grid every participant encodes against.
func DemoGrid() pool.GridSpec {
	return pool.GridSpec{TickCt: TickCt, NumBuckets: NumBuckets, NumSlots: 1}
}

// Side is which half of the market a participant is on.
type Side string

const (
	SideSeller Side = "seller"
	SideBuyer  Side = "buyer"
)

// Participant is one browser tab.
//
// PriceCt and QuantityKWh are the participant's private position. In the
// deployed scheme they never leave the device: the tab encodes its own
// step curve and encrypts it locally. In this demo the server does that
// encoding on the tab's behalf — see the ClientEncryption seam in
// clearing_openfhe.go.
type Participant struct {
	ID          string  `json:"id"`
	Label       string  `json:"label"`
	Side        Side    `json:"side"`
	PriceCt     float64 `json:"price_ct"`
	QuantityKWh float64 `json:"quantity_kwh"`
	Submitted   bool    `json:"submitted"`

	// Allocation is filled in after a clearing, computed from the public
	// clearing price plus this participant's own private curve. Nothing
	// per-participant is ever decrypted to produce it — that locality is
	// the whole point of the reduction.
	AllocatedKWh float64 `json:"allocated_kwh"`
	SettledCt    float64 `json:"settled_ct"`
	Cleared      bool    `json:"cleared"`
}

// Outcome is the published result of one clearing round.
type Outcome struct {
	Hour        int     `json:"hour"`
	SpotCt      float64 `json:"spot_ct"`
	FloorCt     float64 `json:"floor_ct"`
	CapCt       float64 `json:"cap_ct"`
	ClearedPx   float64 `json:"cleared_px"`  // p*
	ClearedKWh  float64 `json:"cleared_kwh"` // Q*
	Sellers     int     `json:"sellers"`     // count only, never identities
	Buyers      int     `json:"buyers"`
	DidClear    bool    `json:"did_clear"`
	Note        string  `json:"note"`
	CircuitName string  `json:"circuit_name"`
	Depth       uint32  `json:"depth"`
	ElapsedMS   int64   `json:"elapsed_ms"`

	// SupplyCurve and DemandCurve are the aggregate curves. In the
	// deployed scheme these are withheld and published only after the
	// confidentiality delay; the demo shows them immediately so the
	// clearing is legible.
	SupplyCurve []float64 `json:"supply_curve"`
	DemandCurve []float64 `json:"demand_curve"`
}

// Session holds all demo state behind one lock. A demo has one pool.
type Session struct {
	mu           sync.Mutex
	Hour         int
	participants map[string]*Participant
	order        []string
	last         *Outcome
}

func NewSession() *Session {
	return &Session{Hour: 13, participants: map[string]*Participant{}}
}

func (s *Session) Join(id string) *Participant {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &Participant{ID: id, Label: fmt.Sprintf("Participant %d", len(s.order)+1), Side: SideSeller}
	s.participants[id] = p
	s.order = append(s.order, id)
	return p
}

func (s *Session) Leave(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.participants, id)
	for i, v := range s.order {
		if v == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

func (s *Session) Update(id string, fn func(*Participant)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.participants[id]; ok {
		fn(p)
	}
}

func (s *Session) SetHour(h int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Hour = ((h % 24) + 24) % 24
	// A new delivery slot invalidates every standing offer and the
	// previous result.
	for _, p := range s.participants {
		p.Submitted = false
		p.Cleared = false
		p.AllocatedKWh = 0
		p.SettledCt = 0
	}
	s.last = nil
}

// Snapshot returns the state the UI renders.
func (s *Session) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	band := BandAt(s.Hour)
	list := make([]*Participant, 0, len(s.order))
	for _, id := range s.order {
		if p, ok := s.participants[id]; ok {
			list = append(list, p)
		}
	}
	return map[string]any{
		"hour":         s.Hour,
		"band":         band,
		"participants": list,
		"outcome":      s.last,
		"grid": map[string]any{
			"tick_ct":     TickCt,
			"num_buckets": NumBuckets,
			"max_price":   MaxGridPrice,
		},
	}
}

// applyAllocations computes each participant's own outcome locally, the
// way a real client would: from the public clearing price and its own
// private curve. No per-participant ciphertext is opened.
func (s *Session) applyAllocations(out *Outcome) {
	for _, p := range s.participants {
		p.Cleared = false
		p.AllocatedKWh = 0
		p.SettledCt = 0
		if !out.DidClear || !p.Submitted || p.QuantityKWh <= 0 {
			continue
		}
		switch p.Side {
		case SideSeller:
			if p.PriceCt <= out.ClearedPx {
				p.Cleared = true
				p.AllocatedKWh = p.QuantityKWh
			}
		case SideBuyer:
			if p.PriceCt >= out.ClearedPx {
				p.Cleared = true
				p.AllocatedKWh = p.QuantityKWh
			}
		}
		if p.Cleared {
			p.SettledCt = p.AllocatedKWh * out.ClearedPx
		}
	}
}
