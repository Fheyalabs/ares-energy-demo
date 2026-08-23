// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package boundcheck

import (
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

func TestNormCircuit_CalibratesOnRealFHE(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	res, err := fhecalib.Calibrate(NormCircuit{Eps: 0.01, NDim: 8}, fhecalib.CalibrationParams{
		Base:       helperclient.ContractParams{RingDim: 1 << 14, ScalingModSize: 50},
		StartDepth: 1, MaxDepth: 4, Tolerance: 0.01,
	}, 8 /* profileDim = slot count of NormCircuit.Inputs() */)
	if err != nil {
		t.Fatalf("norm calibrate: %v", err)
	}
	if !res.Passed {
		t.Fatalf("norm: expected pass, best err %v", res.AchievedAbsError)
	}
	if res.Depth != 1 {
		t.Fatalf("norm circuit needs depth 1, got %d", res.Depth)
	}
	if res.Circuit != "norm" {
		t.Fatalf("circuit name want norm, got %q", res.Circuit)
	}
	t.Logf("norm circuit calibrated to depth %d (abs err %v)", res.Depth, res.AchievedAbsError)
}

func TestDistanceCircuit_CalibratesOnRealFHE(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	// Center {1,1,1,1}; Inputs() returns the center -> squared distance 0,
	// which is within [0,4]. The calibrator checks the decrypted value matches
	// the plaintext Expected (0) within tolerance.
	res, err := fhecalib.Calibrate(
		DistanceBoundCircuit{Center: []float64{1, 1, 1, 1}, Lo: 0, Hi: 4},
		fhecalib.CalibrationParams{
			Base:       helperclient.ContractParams{RingDim: 1 << 14, ScalingModSize: 50},
			StartDepth: 1, MaxDepth: 4, Tolerance: 0.05,
		}, 4)
	if err != nil {
		t.Fatalf("distance calibrate: %v", err)
	}
	if !res.Passed {
		t.Fatalf("distance: expected pass, best err %v", res.AchievedAbsError)
	}
	if res.Circuit != "distance" {
		t.Fatalf("circuit name want distance, got %q", res.Circuit)
	}
	t.Logf("distance circuit calibrated to depth %d (abs err %v)", res.Depth, res.AchievedAbsError)
}
