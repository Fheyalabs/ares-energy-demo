// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestPerPartyShareGenRAM measures what ONE party (a phone) shoulders per epoch:
// the peak process RSS, wall time, and serialized size of generating its keypair
// share + eval-key round-1 share (the rotation + relin shares). This is the heavy
// per-individual precompute — done once per epoch in the background — NOT the
// per-session path (encrypt + partial-decrypt is MB and is not measured here).
//
// Peak RSS is sampled from the OS (ps), so it includes the C++ OpenFHE objects
// plus the serialized share blob (a phone must serialize to upload). The sweep
// goes up to ring 2^16 / depth-30 (the harness's likely auto-picked ring); 2^17
// is extrapolated (×2) to avoid OOM on a 16 GB host.
//
// Run: go test -tags openfhe -run TestPerPartyShareGenRAM -v -timeout 40m
func TestPerPartyShareGenRAM(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark, not a unit test")
	}
	const scaling = float64(uint64(1) << 50)
	scenarios := []struct {
		name        string
		ring, depth uint32
	}{
		{"r2^14-d8", 16384, 8},
		{"r2^14-d16", 16384, 16},
		{"r2^14-d24", 16384, 24},
		{"r2^14-d30", 16384, 30},
		{"r2^15-d30", 32768, 30},
		{"r2^16-d30", 65536, 30},
		{"r2^17-d30", 131072, 30}, // deep-circuit worst case (secure ring for depth-30)
	}
	// Rows above ring 2^14 use multi-GB to tens-of-GB RSS. Gate them behind
	// ARES_BENCH_HEAVY=1 so they run only on a high-RAM host (the homelab, 23 GiB),
	// never the 16 GB dev Mac (where ring 2^15/depth-30 already OOM-kills).
	heavy := os.Getenv("ARES_BENCH_HEAVY") == "1"
	pid := os.Getpid()
	readRSS := func() int64 {
		out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		return v // KB
	}
	bump := func(peak *atomic.Int64, v int64) {
		for {
			old := peak.Load()
			if v <= old || peak.CompareAndSwap(old, v) {
				return
			}
		}
	}

	fmt.Println("\n=== per-party epoch share-gen: peak RSS + time (one phone's per-epoch burden) ===")
	fmt.Printf("%-12s %7s %4s | %8s %12s %10s\n", "scenario", "ring", "dep", "gen_s", "peakRSS_GB", "shareMB")

	for _, s := range scenarios {
		if s.ring > 16384 && !heavy {
			fmt.Printf("%-12s %7d %4d | %8s %12s %10s  (skipped — set ARES_BENCH_HEAVY=1 on a >=24GB host)\n",
				s.name, s.ring, s.depth, "-", "-", "-")
			continue
		}
		params := ContractParams{RingDim: s.ring, ScalingFactor: scaling, Depth: s.depth}
		runtime.GC()

		var peak atomic.Int64
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					close(done)
					return
				default:
					if v := readRSS(); v > 0 {
						bump(&peak, v)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()

		t0 := time.Now()
		first, err := DistributedKeyGenFirst(params)
		if err != nil {
			close(stop)
			t.Fatalf("%s keygen: %v", s.name, err)
		}
		lead, err := EvalKeyRound1Lead(params, first.SecretKeyShare)
		if err != nil {
			close(stop)
			t.Fatalf("%s round1: %v", s.name, err)
		}
		gen := time.Since(t0)
		bump(&peak, readRSS())
		close(stop)
		<-done

		shareMB := float64(len(lead.EvalMultBase)+len(lead.EvalSumBase)) / (1024 * 1024)
		fmt.Printf("%-12s %7d %4d | %8.1f %12.2f %10.1f\n",
			s.name, s.ring, s.depth, gen.Seconds(), float64(peak.Load())/(1024*1024), shareMB)
	}
	fmt.Println("\npeakRSS_GB = peak process RSS during one party's keygen + eval-key round-1 (C++ objects + serialized share).")
	fmt.Println("This is the per-EPOCH burden (background, amortized). Per-SESSION work (encrypt + partial-decrypt) is MB.")
	fmt.Println("r2^17/depth-30 ~ 2x the r2^16 row (ring is linear in RAM) — extrapolated, not run, to avoid OOM on 16 GB.")
}
