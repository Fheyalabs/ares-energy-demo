// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package main

import (
	"os"
	"testing"
)

// The demo uses a small ring for responsiveness; the canonical bridge is
// secure-by-default and rejects it. Test binary only.
func init() { _ = os.Setenv("ARES_FHE_ALLOW_INSECURE", "1") }

// A round with sellers below the buyers' limits must clear inside the
// published band. Hour 13 is the negative-price hour, where the floor is
// 0 and the band is at its widest.
func TestRunClearing_ClearsInsideBand(t *testing.T) {
	s := NewSession()
	s.SetHour(13)

	s.Join("s1")
	s.Update("s1", func(p *Participant) {
		p.Side, p.PriceCt, p.QuantityKWh, p.Submitted = SideSeller, 3.0, 5, true
	})
	s.Join("s2")
	s.Update("s2", func(p *Participant) {
		p.Side, p.PriceCt, p.QuantityKWh, p.Submitted = SideSeller, 6.0, 5, true
	})
	s.Join("b1")
	s.Update("b1", func(p *Participant) {
		p.Side, p.PriceCt, p.QuantityKWh, p.Submitted = SideBuyer, 12.0, 8, true
	})

	out, err := s.RunClearing()
	if err != nil {
		t.Fatalf("RunClearing: %v", err)
	}
	if !out.DidClear {
		t.Fatalf("did not clear: %s", out.Note)
	}
	if out.ClearedPx < out.FloorCt || out.ClearedPx > out.CapCt {
		t.Errorf("p* = %v outside published band [%v, %v] — the guarantee is broken",
			out.ClearedPx, out.FloorCt, out.CapCt)
	}
	if out.ClearedKWh <= 0 {
		t.Errorf("cleared volume = %v, want > 0", out.ClearedKWh)
	}
	t.Logf("hour %d: spot %.2f, band [%.2f, %.2f], p* = %.2f ct, Q* = %.2f kWh, %d ms",
		out.Hour, out.SpotCt, out.FloorCt, out.CapCt, out.ClearedPx, out.ClearedKWh, out.ElapsedMS)

	// The cheap seller must clear; allocations are derived locally from
	// the public price, never decrypted per participant.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.participants["s1"].Cleared {
		t.Error("seller bidding 3.0 below p* should have cleared")
	}
	if !s.participants["b1"].Cleared {
		t.Error("buyer with a 12.0 limit above p* should have cleared")
	}
}

// One-sided rounds must refuse rather than invent a price.
func TestRunClearing_NeedsBothSides(t *testing.T) {
	s := NewSession()
	s.SetHour(9)
	s.Join("s1")
	s.Update("s1", func(p *Participant) {
		p.Side, p.PriceCt, p.QuantityKWh, p.Submitted = SideSeller, 3.0, 5, true
	})
	out, err := s.RunClearing()
	if err != nil {
		t.Fatalf("RunClearing: %v", err)
	}
	if out.DidClear {
		t.Error("cleared with no buyers")
	}
}

// The band must widen when wholesale collapses: that is the whole
// economic story the demo exists to show.
func TestBand_WidestAtNegativePrices(t *testing.T) {
	noon, evening := BandAt(13), BandAt(20)
	if noon.SpotCt >= 0 {
		t.Fatalf("hour 13 spot = %v, expected negative", noon.SpotCt)
	}
	wNoon := noon.CapCt - noon.FloorCt
	wEve := evening.CapCt - evening.FloorCt
	if wNoon <= wEve {
		t.Errorf("band at 13:00 (%.2f) should exceed 20:00 (%.2f)", wNoon, wEve)
	}
	t.Logf("13:00 spot %.2f band %.2f wide; 20:00 spot %.2f band %.2f wide",
		noon.SpotCt, wNoon, evening.SpotCt, wEve)
}
