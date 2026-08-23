// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"fmt"
	"testing"
	"time"
)

// TestResidentCombineProfile compares the per-cohort ONLINE combine in two models
// to show how much of the hot path is (de)serialization of the large eval-key
// blobs vs. genuine combine compute:
//
//   - byte path  (CombineEvalKeyRound1 today): createCtx + deserialize + combine
//   - reserialize.
//   - resident   (benchResidentCombineRound1): context + deserialized key handles
//     already in RAM; per-cohort cost is the handle combine only.
//
// Run: go test -tags openfhe -run TestResidentCombineProfile -v -timeout 30m
func TestResidentCombineProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark, not a unit test")
	}
	const scaling = float64(uint64(1) << 50)
	const ring = 16384
	const n = 6
	depths := []uint32{8, 12, 16}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
	nz := func(d time.Duration) float64 {
		if v := ms(d); v > 0 {
			return v
		}
		return 0.001
	}

	fmt.Println("\n=== ONLINE combine: byte-path vs resident-in-RAM (ring 16384, N=6) ===")
	fmt.Printf("%4s %9s | %13s %12s | %8s\n", "dep", "evalMB", "byte_combR1", "resident", "speedup")

	for _, depth := range depths {
		params := ContractParams{RingDim: ring, ScalingFactor: scaling, Depth: depth}

		// --- setup (not timed): produce the N parties' round-1 share blobs ---
		shares := make([]DistributedKeyShare, n)
		var err error
		if shares[0], err = DistributedKeyGenFirst(params); err != nil {
			t.Fatalf("d%d keygen first: %v", depth, err)
		}
		for i := 1; i < n; i++ {
			if shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey); err != nil {
				t.Fatalf("d%d keygen %d: %v", depth, i, err)
			}
		}
		lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
		if err != nil {
			t.Fatalf("d%d r1 lead: %v", depth, err)
		}
		pubKeys := make([][]byte, n)
		multShares := make([][]byte, n)
		sumShares := make([][]byte, n)
		pubKeys[0], multShares[0], sumShares[0] = shares[0].PublicKey, lead.EvalMultBase, lead.EvalSumBase
		for i := 1; i < n; i++ {
			r1, err := EvalKeyRound1Participant(params, shares[i].SecretKeyShare, lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
			if err != nil {
				t.Fatalf("d%d r1 participant %d: %v", depth, i, err)
			}
			pubKeys[i], multShares[i], sumShares[i] = shares[i].PublicKey, r1.EvalMultSwitchShare, r1.EvalSumShare
		}
		evalMB := 0.0
		for _, b := range multShares {
			evalMB += float64(len(b))
		}
		for _, b := range sumShares {
			evalMB += float64(len(b))
		}
		evalMB /= 1024.0 * 1024.0

		// --- byte path (current) ---
		t0 := time.Now()
		if _, err = CombineEvalKeyRound1(params, pubKeys, multShares, sumShares); err != nil {
			t.Fatalf("d%d byte combine: %v", depth, err)
		}
		bytePath := time.Since(t0)

		// --- resident path (handles already in RAM) ---
		resident, err := benchResidentCombineRound1(params, pubKeys, multShares, sumShares)
		if err != nil {
			t.Fatalf("d%d resident combine: %v", depth, err)
		}

		fmt.Printf("%4d %9.1f | %13.1f %12.1f | %7.1fx\n", depth, evalMB, ms(bytePath), ms(resident), nz(bytePath)/nz(resident))
	}
	fmt.Println("\nbyte_combR1 = createCtx + deserialize shares + combine + reserialize (today's path).")
	fmt.Println("resident    = handle combine only (context + deserialized keys already resident in RAM).")
	fmt.Println("The gap is (de)serialization of the eval-key blobs — eliminated by a resident precompute pool.")
}
