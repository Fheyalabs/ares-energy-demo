// SPDX-License-Identifier: Apache-2.0

package boundcheck

import "testing"

func TestClassify_InBound_Ok(t *testing.T) {
	nu, sev := classify(1.0, Bound{Lo: 0.99, Hi: 1.01}, Params{EpsNorm: 0.01, NuHard: 1.25})
	if nu != 0 || sev != SeverityOK {
		t.Fatalf("in-bound: want (0, OK), got (%v, %v)", nu, sev)
	}
}

func TestClassify_AboveHi_Hard(t *testing.T) {
	// value 2.25, Hi 1.01 -> nu = 1.24 > NuHard 1.0 -> hard
	nu, sev := classify(2.25, Bound{Lo: 0.99, Hi: 1.01}, Params{EpsNorm: 0.01, NuHard: 1.0})
	if sev != SeverityHard {
		t.Fatalf("want Hard, got %v (nu=%v)", sev, nu)
	}
	if nu < 1.23 || nu > 1.25 {
		t.Fatalf("nu want ~1.24, got %v", nu)
	}
}

func TestClassify_SlightlyOut_Soft(t *testing.T) {
	// value 1.05, Hi 1.01 -> nu = 0.04, between EpsNorm 0.01 and NuHard 1.0 -> soft
	_, sev := classify(1.05, Bound{Lo: 0.99, Hi: 1.01}, Params{EpsNorm: 0.01, NuHard: 1.0})
	if sev != SeveritySoft {
		t.Fatalf("want Soft, got %v", sev)
	}
}

func TestClassify_WithinNoiseFloor_Ok(t *testing.T) {
	// value 1.015, Hi 1.01 -> nu = 0.005 <= EpsNorm 0.01 -> OK (noise floor)
	_, sev := classify(1.015, Bound{Lo: 0.99, Hi: 1.01}, Params{EpsNorm: 0.01, NuHard: 1.0})
	if sev != SeverityOK {
		t.Fatalf("want OK (noise floor), got %v", sev)
	}
}

func TestClassify_BelowLo_Violates(t *testing.T) {
	// value 0.5, Lo 0.99 -> nu = 0.49 (two-sided: deflation also caught)
	nu, sev := classify(0.5, Bound{Lo: 0.99, Hi: 1.01}, Params{EpsNorm: 0.01, NuHard: 1.0})
	if sev != SeveritySoft || nu < 0.48 || nu > 0.50 {
		t.Fatalf("below-Lo: want Soft nu~0.49, got %v nu=%v", sev, nu)
	}
}

func TestNormCircuit_ExpectedAndBound(t *testing.T) {
	c := NormCircuit{Eps: 0.01, NDim: 4}
	got := c.Expected([][]float64{{0.5, 0.5, 0.5, 0.5}}) // sum of squares = 1.0
	if len(got) != 1 || got[0] < 0.999 || got[0] > 1.001 {
		t.Fatalf("want [~1.0], got %v", got)
	}
	if b := c.Bound(); b.Lo != 0.99 || b.Hi != 1.01 {
		t.Fatalf("norm bound want [0.99,1.01], got %v", b)
	}
	if c.Name() != "norm" {
		t.Fatalf("name want norm, got %q", c.Name())
	}
}

func TestDistanceCircuit_ExpectedAndBound(t *testing.T) {
	c := DistanceBoundCircuit{Center: []float64{1, 1}, Lo: 0, Hi: 4}
	got := c.Expected([][]float64{{3, 1}}) // (3-1)^2 + (1-1)^2 = 4
	if len(got) != 1 || got[0] < 3.999 || got[0] > 4.001 {
		t.Fatalf("want [~4.0], got %v", got)
	}
	if b := c.Bound(); b.Lo != 0 || b.Hi != 4 {
		t.Fatalf("distance bound want [0,4], got %v", b)
	}
}
