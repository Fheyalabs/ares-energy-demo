// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import "testing"

// TestMinimalKeygenShrinksEvalSumShare checks that opting a context into minimal
// rotation keys produces a materially smaller participant eval-sum share than the
// full-batch path (fewer rotation keys = less wire = less RAM), for the same ring.
func TestMinimalKeygenShrinksEvalSumShare(t *testing.T) {
	const profileDim, payloadSlots = 128, 640

	// A fixed ring large enough that the full-batch EvalSum + broadcast key set is
	// materially bigger than the minimal set. (At tiny rings both collapse to a
	// handful of keys and the saving isn't visible.) Set here, NOT in the shared
	// DefaultContractParams, so other callers' ring sizing is unaffected.
	full := ContractParams{RingDim: 8192, ScalingFactor: float64(uint64(1) << 50), Depth: 12}

	minimal := full
	minimal.MinimalRotationKeys = true
	minimal.ProfileDim = profileDim
	minimal.PayloadSlotCount = payloadSlots

	fullBytes := evalSumShareBytesForTest(t, full)
	minBytes := evalSumShareBytesForTest(t, minimal)

	if minBytes == 0 || fullBytes == 0 {
		t.Fatalf("share sizes must be non-zero (full=%d minimal=%d)", fullBytes, minBytes)
	}
	if minBytes >= fullBytes {
		t.Fatalf("minimal share (%d B) must be smaller than full share (%d B)", minBytes, fullBytes)
	}
	if ratio := float64(minBytes) / float64(fullBytes); ratio > 0.75 {
		t.Fatalf("minimal/full size ratio %.2f too high; expected < 0.75", ratio)
	}
}

// evalSumShareBytesForTest runs a 2-party keygen under params and returns the
// serialized size of party-1's eval-sum (rotation) share.
func evalSumShareBytesForTest(t *testing.T, params ContractParams) int {
	t.Helper()
	shares := distributedSharesForTest(t, params, 2)
	lead, err := EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		t.Fatalf("eval-key round1 lead: %v", err)
	}
	round1, err := EvalKeyRound1Participant(params, shares[1].SecretKeyShare,
		lead.EvalMultBase, lead.EvalSumBase, shares[1].PublicKey)
	if err != nil {
		t.Fatalf("eval-key round1 participant: %v", err)
	}
	return len(round1.EvalSumShare)
}

// TestMinimalStreamedRotShareShrinks confirms the streamed per-index keygen helper
// honors minimal mode: the streamed total for the minimal index set is smaller than
// the full-batch streamed total at the same ring (fewer keys streamed = less work/RAM).
func TestMinimalStreamedRotShareShrinks(t *testing.T) {
	const profileDim, payloadSlots = 128, 640
	// Fixed ring large enough that (a) the minimal broadcast indices (up to 512 for
	// payload 640) are valid at this batch size, and (b) the full-batch set is bigger
	// than the minimal set. Set here, not in the shared DefaultContractParams.
	full := ContractParams{RingDim: 8192, ScalingFactor: float64(uint64(1) << 50), Depth: 12}
	minimal := full
	minimal.MinimalRotationKeys = true
	minimal.ProfileDim = profileDim
	minimal.PayloadSlotCount = payloadSlots

	fullTotal, err := benchStreamedFullRot(full)
	if err != nil {
		t.Fatalf("full streamed keygen: %v", err)
	}
	minTotal, err := benchStreamedFullRot(minimal)
	if err != nil {
		t.Fatalf("minimal streamed keygen: %v", err)
	}
	if minTotal == 0 || minTotal >= fullTotal {
		t.Fatalf("minimal streamed total (%d) must be > 0 and < full (%d)", minTotal, fullTotal)
	}
}
