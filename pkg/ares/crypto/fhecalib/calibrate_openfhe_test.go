// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package fhecalib

import (
	"errors"
	"testing"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

func TestCalibrate_SquareCircuitFindsDepth1(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	cut := squareCircuit{in: []float64{0.5, -0.3, 0.25, 0.1}}
	res, err := Calibrate(cut, CalibrationParams{
		Base:       helperclient.ContractParams{RingDim: 1 << 14, ScalingModSize: 50},
		StartDepth: 1,
		MaxDepth:   4,
		Tolerance:  0.01,
	}, 4 /* profileDim = slot count */)
	if err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if !res.Passed {
		t.Fatalf("expected pass, got best err %v", res.AchievedAbsError)
	}
	if res.Depth != 1 {
		t.Fatalf("square needs depth 1, calibrator found %d", res.Depth)
	}
	if res.Circuit != "elementwise-square" {
		t.Fatalf("circuit name not propagated: %q", res.Circuit)
	}
	if res.RingDim != 1<<14 {
		t.Fatalf("expected resolved RingDim=16384, got %d", res.RingDim)
	}
}

func TestCalibrate_ModulusCapSurfaces(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("OpenFHE unavailable: %v", err)
	}
	cut := squareCircuit{in: []float64{0.5, 0.5}}
	// RingDim 1024 has a ~27-bit modulus budget at 128-bit security; even a
	// depth-1 CKKS circuit (60 + 50 bits) exceeds it, so the calibrator must
	// refuse with ErrModulusCap rather than silently running at an insecure ring.
	_, err := Calibrate(cut, CalibrationParams{
		Base:       helperclient.ContractParams{RingDim: 1 << 10, ScalingModSize: 50},
		StartDepth: 1,
		MaxDepth:   4,
		Tolerance:  0.01,
	}, 2)
	if err == nil {
		t.Fatal("expected ErrModulusCap at RingDim 1024")
	}
	if !errors.Is(err, ErrModulusCap) {
		t.Fatalf("want ErrModulusCap, got %v", err)
	}
}
