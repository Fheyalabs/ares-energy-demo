// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"bytes"
	"testing"
)

// The incremental eval-sum combine must produce a byte-identical joint key to the
// resident all-at-once CombineEvalSumKeys, while folding shares one at a time so
// peak RAM is bounded to the accumulator plus one share. (ARES_FHE_ALLOW_INSECURE
// is set for the package test binary by insecure_optout_test.go, so the small
// ring-1024 params are accepted.)
func TestIncrementalEvalSumCombineMatchesAllAtOnce(t *testing.T) {
	params := ContractParams{RingDim: 1024, ScalingFactor: float64(uint64(1) << 50), Depth: 2}
	res, err := runIncrementalCombineCheck(params)
	if err != nil {
		t.Fatalf("incremental combine check: %v", err)
	}
	if len(res.allAtOnce) == 0 {
		t.Fatal("empty all-at-once joint key")
	}
	if !bytes.Equal(res.allAtOnce, res.incremental) {
		t.Fatalf("incremental eval-sum combine differs from all-at-once: %d vs %d bytes",
			len(res.allAtOnce), len(res.incremental))
	}
}
