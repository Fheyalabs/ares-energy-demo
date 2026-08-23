// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"bytes"
	"testing"
)

// TestBOnlyRotKeyReconstruction validates the production b-only wire path: the
// rotation-key 'a'-vectors are shared across parties, a participant transmits only
// its 'b'-vectors, and the combiner rebuilds a share whose (a,b) match the original
// exactly. Fast unit test (small ring, depth 2). The homomorphic equivalence of the
// rebuilt key is established by the scratch prototype + MeasureBOnlyRotShare; this
// exercises the serialize_a / serialize_b / reconstruct_from_b production API.
func TestBOnlyRotKeyReconstruction(t *testing.T) {
	res, err := runBOnlyRotReconstruction(ContractParams{
		RingDim:       1 << 13,
		ScalingFactor: float64(uint64(1) << 50),
		Depth:         2,
	})
	if err != nil {
		t.Fatalf("b-only reconstruction run: %v", err)
	}

	// 'a' must be byte-identical between the lead base and the participant share
	// (the shared CRS), the soundness precondition for transmitting only 'b'.
	if !bytes.Equal(res.aBase, res.aShare) {
		t.Fatalf("rotation-key 'a' differs between parties (%d vs %d B): b-only would be unsound",
			len(res.aBase), len(res.aShare))
	}
	if len(res.bShare) >= len(res.full) {
		t.Errorf("b-only payload (%d B) is not smaller than the full share (%d B)",
			len(res.bShare), len(res.full))
	}
	// the share rebuilt from shared 'a' + its 'b' must have matching (a,b).
	if !bytes.Equal(res.reconA, res.aBase) {
		t.Errorf("reconstructed 'a' differs from the shared 'a'")
	}
	if !bytes.Equal(res.reconB, res.bShare) {
		t.Errorf("reconstructed 'b' differs from the transmitted 'b'")
	}

	saved := 100 * (1 - float64(len(res.bShare))/float64(len(res.full)))
	t.Logf("b-only wire: full share %d B -> b-only %d B (%.0f%% saved); shared a = %d B (sent once)",
		len(res.full), len(res.bShare), saved, len(res.aBase))
}
