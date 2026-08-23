// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"fmt"
	"testing"
	"time"
)

// TestKeygenAmortizationProfile measures, per scenario, where threshold-CKKS
// keygen time actually goes, and splits it into the amortization buckets the
// session-key design relies on:
//
//   - PRECOMP (per-individual, offline): eval-key round-1 shares. A party can
//     compute these against the (shared) bases without knowing the cohort, so
//     they precompute in the background and are reused across every cohort the
//     party lands in. (Under a parallel CRS-sum CPK they would also include the
//     public-key share; CPK is currently chained, reported separately.)
//   - ONLINE (per-cohort, hot path): combine round-1 + round-2 + combine round-2
//   - the decrypt path. This is the floor a session request cannot avoid.
//
// Run: go test -tags openfhe -run TestKeygenAmortizationProfile -v -timeout 30m
// Sweep is small->large so the scaling curve extrapolates to the heavy
// (deep / large-ring) point without running it repeatedly.
func TestKeygenAmortizationProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("keygen profile is a benchmark, not a unit test")
	}
	scenarios := []struct {
		name  string
		n     int
		ring  uint32
		depth uint32
	}{
		// Depth sweep at fixed ring/N — isolates the depth-scaling factor so the
		// depth-30 (deep-circuit worst case) point can be projected, and gives the
		// per-depth latency table for density-tiered circuit selection.
		{"d8-r16k-6p", 6, 16384, 8},
		{"d12-r16k-6p", 6, 16384, 12},
		{"d16-r16k-6p", 6, 16384, 16},
	}
	const scaling = float64(uint64(1) << 50)
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
	kb := func(b []byte) float64 { return float64(len(b)) / 1024.0 }

	fmt.Println("\n=== threshold-CKKS keygen stage profile (ms) ===")
	fmt.Printf("%-18s %2s %6s %3s | %8s %9s %8s %8s %8s | %9s %9s | %7s %9s\n",
		"scenario", "N", "ring", "dep",
		"cpk", "r1/party", "r1_tot", "combR1", "r2+comb", "PRECOMP", "ONLINE", "pkKB", "evalKB")

	for _, s := range scenarios {
		params := ContractParams{RingDim: s.ring, ScalingFactor: scaling, Depth: s.depth}

		// --- Collective public key (currently chained / sequential) ---
		t0 := time.Now()
		shares := make([]DistributedKeyShare, s.n)
		var err error
		if shares[0], err = DistributedKeyGenFirst(params); err != nil {
			t.Fatalf("%s: keygen first: %v", s.name, err)
		}
		for i := 1; i < s.n; i++ {
			if shares[i], err = DistributedKeyGenNext(params, shares[i-1].PublicKey); err != nil {
				t.Fatalf("%s: keygen %d: %v", s.name, i, err)
			}
		}
		cpk := time.Since(t0)
		collectivePK := shares[s.n-1].PublicKey

		// --- eval-key round 1 (per-individual; PRECOMPUTABLE) ---
		t0 = time.Now()
		lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
		if err != nil {
			t.Fatalf("%s: r1 lead: %v", s.name, err)
		}
		pubKeys := make([][]byte, s.n)
		multR1 := make([][]byte, s.n)
		sumR1 := make([][]byte, s.n)
		pubKeys[0], multR1[0], sumR1[0] = shares[0].PublicKey, lead.EvalMultBase, lead.EvalSumBase
		var partySum time.Duration
		for i := 1; i < s.n; i++ {
			pt := time.Now()
			r1, err := EvalKeyRound1Participant(params, shares[i].SecretKeyShare, lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
			if err != nil {
				t.Fatalf("%s: r1 participant %d: %v", s.name, i, err)
			}
			partySum += time.Since(pt)
			pubKeys[i], multR1[i], sumR1[i] = shares[i].PublicKey, r1.EvalMultSwitchShare, r1.EvalSumShare
		}
		r1Tot := time.Since(t0)
		divisor := s.n - 1
		if divisor < 1 {
			divisor = 1
		}
		r1PerParty := partySum / time.Duration(divisor)

		// --- combine round 1 (per-cohort) ---
		t0 = time.Now()
		comb1, err := CombineEvalKeyRound1(params, pubKeys, multR1, sumR1)
		if err != nil {
			t.Fatalf("%s: combine r1: %v", s.name, err)
		}
		combR1 := time.Since(t0)

		// --- round 2 + combine (per-cohort) ---
		t0 = time.Now()
		finalShares := make([][]byte, s.n)
		for i := range shares {
			r2, err := EvalKeyRound2Participant(params, shares[i].SecretKeyShare, comb1.EvalMultJoined, collectivePK, shares[i].Lead)
			if err != nil {
				t.Fatalf("%s: r2 participant %d: %v", s.name, i, err)
			}
			finalShares[i] = r2.EvalMultFinalShare
		}
		final, err := CombineEvalKeyRound2(params, collectivePK, finalShares, comb1.EvalSumFinal)
		if err != nil {
			t.Fatalf("%s: combine r2: %v", s.name, err)
		}
		r2c := time.Since(t0)

		// --- decrypt path: encrypt + N partials + fuse (per-cohort, hot path) ---
		profile := []float64{1, 0.5, -0.25, 0.125}
		t0 = time.Now()
		ct, err := EncryptCKKSForContract(params, collectivePK, profile)
		if err != nil {
			t.Fatalf("%s: encrypt: %v", s.name, err)
		}
		partials := make([][]byte, s.n)
		for i, sh := range shares {
			if partials[i], err = PartialDecryptCKKSForContract(params, ct, sh.SecretKeyShare, sh.Lead); err != nil {
				t.Fatalf("%s: partial %d: %v", s.name, i, err)
			}
		}
		if _, err = FuseCKKSPartialsForContract(params, partials, len(profile)); err != nil {
			t.Fatalf("%s: fuse: %v", s.name, err)
		}
		decrypt := time.Since(t0)

		precomp := r1Tot                 // per-individual, offline
		online := combR1 + r2c + decrypt // per-cohort, hot path

		fmt.Printf("%-18s %2d %6d %3d | %8.1f %9.1f %8.1f %8.1f %8.1f | %9.1f %9.1f | %7.1f %9.1f\n",
			s.name, s.n, s.ring, s.depth,
			ms(cpk), ms(r1PerParty), ms(r1Tot), ms(combR1), ms(r2c),
			ms(precomp), ms(online), kb(collectivePK), kb(final.EvalMultFinal)+kb(final.EvalSumFinal))
	}
	fmt.Println("\nPRECOMP = per-individual eval-key round-1 (precompute offline, reuse across cohorts).")
	fmt.Println("ONLINE  = per-cohort hot path (combine r1 + round-2 + combine r2 + decrypt).")
	fmt.Println("CPK is currently chained (sequential). Parallel CRS-sum CPK (MultiAddPubKeys + seeded a)")
	fmt.Println("would move it into PRECOMP (per-party share) + a near-free sum, the next thing to prototype.")
}
