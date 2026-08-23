// SPDX-License-Identifier: Apache-2.0

package fhecalib

import (
	"errors"
	"testing"
)

func TestSweep_ReturnsMinDepthThatPasses(t *testing.T) {
	// Circuit "passes" (error within tol) only at depth >= 2.
	run := func(depth uint32) (float64, bool, error) {
		if depth >= 2 {
			return 0.001, false, nil
		}
		return 0.5, false, nil // too imprecise below depth 2
	}
	res, err := sweep(CalibrationParams{StartDepth: 0, MaxDepth: 5, Tolerance: 0.01}, run)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !res.Passed || res.Depth != 2 {
		t.Fatalf("want Passed at depth 2, got Passed=%v depth=%d", res.Passed, res.Depth)
	}
	if res.AchievedAbsError != 0.001 {
		t.Fatalf("want achieved err 0.001, got %v", res.AchievedAbsError)
	}
}

func TestSweep_FailsAtMaxDepthReportsBestError(t *testing.T) {
	// Never precise enough; error plateaus (precision-bound, not depth-bound).
	run := func(depth uint32) (float64, bool, error) {
		return 0.2, false, nil
	}
	res, err := sweep(CalibrationParams{StartDepth: 1, MaxDepth: 3, Tolerance: 0.01}, run)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Passed {
		t.Fatalf("want not Passed")
	}
	if res.AchievedAbsError != 0.2 {
		t.Fatalf("want best err 0.2, got %v", res.AchievedAbsError)
	}
}

func TestSweep_ModulusCapSurfacesDistinctError(t *testing.T) {
	// run signals capHit=true: depth needs more modulus than RingDim allows.
	run := func(depth uint32) (float64, bool, error) {
		if depth >= 2 {
			return 0, true, nil
		}
		return 0.5, false, nil
	}
	_, err := sweep(CalibrationParams{StartDepth: 1, MaxDepth: 5, Tolerance: 0.01}, run)
	if !errors.Is(err, ErrModulusCap) {
		t.Fatalf("want ErrModulusCap, got %v", err)
	}
}

func TestSweep_PropagatesRunError(t *testing.T) {
	boom := errors.New("provision failed")
	run := func(depth uint32) (float64, bool, error) {
		return 0, false, boom
	}
	_, err := sweep(CalibrationParams{StartDepth: 1, MaxDepth: 5, Tolerance: 0.01}, run)
	if !errors.Is(err, boom) {
		t.Fatalf("want propagated run error, got %v", err)
	}
}

func TestMaxSlotAbsError(t *testing.T) {
	got := maxSlotAbsError([]float64{1.0, 2.0, 3.0}, []float64{1.01, 1.8, 3.0})
	if got < 0.199 || got > 0.201 {
		t.Fatalf("want ~0.2, got %v", got)
	}
}
