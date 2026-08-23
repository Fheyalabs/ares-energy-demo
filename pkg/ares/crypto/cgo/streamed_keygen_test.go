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

// TestStreamedKeygenRAM compares the peak RSS of generating a party's rotation key
// three ways, at depth-30 across rings 2^14..2^17:
//
//   - all-at-once  : EvalSumKeyShare builds the whole map, then serializes (today).
//   - stream-part  : streams the participant share per-index, but still holds the
//     lead's full base map (base-dominated).
//   - stream-full  : streams BOTH lead base and participant share per-index, so the
//     peak is bounded to a single rotation index regardless of ring.
//
// stream-full runs at every ring (it's bounded → safe even at 2^17 on 16 GB). The
// OOM-prone modes run only at the safe 2^14 unless ARES_BENCH_HEAVY=1.
//
// Run: go test -tags openfhe -run TestStreamedKeygenRAM -v -timeout 40m
func TestStreamedKeygenRAM(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark, not a unit test")
	}
	const scaling = float64(uint64(1) << 50)
	const depth = 30
	rings := []uint32{16384, 32768, 65536, 131072}
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
	// sample runs fn while sampling peak process RSS; returns (peakGB, totalMB, err).
	sample := func(fn func() (uint64, error)) (float64, float64, error) {
		var peak atomic.Int64
		bump := func(v int64) {
			for {
				old := peak.Load()
				if v <= old || peak.CompareAndSwap(old, v) {
					return
				}
			}
		}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					close(done)
					return
				default:
					bump(readRSS())
					time.Sleep(80 * time.Millisecond)
				}
			}
		}()
		total, err := fn()
		bump(readRSS())
		close(stop)
		<-done
		return float64(peak.Load()) / (1024 * 1024), float64(total) / (1024 * 1024), err
	}
	gb := func(peak float64, err error) string {
		if err != nil {
			return "ERR"
		}
		return fmt.Sprintf("%.2f GB", peak)
	}

	fmt.Println("\n=== rotation-key gen peak RSS: all-at-once vs streamed (depth-30, N=2) ===")
	fmt.Printf("%8s | %12s | %12s | %14s | %9s\n", "ring", "all-at-once", "stream-part", "stream-full", "totalMB")

	for _, ring := range rings {
		runtime.GC()
		params := ContractParams{RingDim: ring, ScalingFactor: scaling, Depth: depth}

		// stream-full: bounded peak -> safe at every ring incl 2^17.
		fPeak, fMB, fErr := sample(func() (uint64, error) { return benchStreamedFullRot(params) })
		if fErr != nil {
			t.Fatalf("ring %d stream-full: %v", ring, fErr)
		}

		allStr, partStr := "skip(OOM)", "skip(OOM)"
		if ring <= 16384 || heavy {
			aPeak, _, aErr := sample(func() (uint64, error) { return benchRotShareGen(params, false) })
			allStr = gb(aPeak, aErr)
			pPeak, _, pErr := sample(func() (uint64, error) { return benchRotShareGen(params, true) })
			partStr = gb(pPeak, pErr)
		}
		fmt.Printf("%8d | %12s | %12s | %11.2f GB | %9.0f\n", ring, allStr, partStr, fPeak, fMB)
	}
	fmt.Println("\nstream-full bounds peak to one rotation index across both parties — flat across rings,")
	fmt.Println("so a RAM-constrained client (phone / 16 GB Mac) can generate a depth-30/2^17 share without OOM.")
}

// TestBOnlyTransfer checks the CRS wire optimization: is the rotation-key 'a' shared
// across parties (so a participant can transmit only its b-vector), and how much does
// b-only save vs the full (a,b) key. One rotation index per ring -> cheap.
func TestBOnlyTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark, not a unit test")
	}
	const scaling = float64(uint64(1) << 50)
	cases := []struct{ ring, depth uint32 }{
		{16384, 30}, {65536, 30}, {131072, 30},
	}
	fmt.Println("\n=== CRS wire optimization: full rotation key vs b-only (one index, depth-30) ===")
	fmt.Printf("%8s | %9s | %10s | %11s | %7s | %s\n", "ring", "a_shared", "full_MB", "b_only_MB", "ratio", "save")
	for _, c := range cases {
		params := ContractParams{RingDim: c.ring, ScalingFactor: scaling, Depth: c.depth}
		full, bOnly, aShared, err := benchBOnlyRotShare(params)
		if err != nil {
			t.Fatalf("ring %d: %v", c.ring, err)
		}
		fMB := float64(full) / (1024 * 1024)
		bMB := float64(bOnly) / (1024 * 1024)
		ratio := bMB / fMB
		fmt.Printf("%8d | %9v | %10.2f | %11.2f | %7.2f | %.0f%%\n", c.ring, aShared, fMB, bMB, ratio, (1-ratio)*100)
	}
	fmt.Println("\na_shared=true => a participant transmits only its b-vector; the server pairs it with the")
	fmt.Println("(once-sent, or seed-derived) shared a. b-only ~= half => ~halved per-party upload.")
}
