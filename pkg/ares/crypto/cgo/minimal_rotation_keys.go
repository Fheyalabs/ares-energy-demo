// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

// minimalRotationIndices returns the at-index rotation set a dimension-parameterized
// threshold-CKKS scorer needs: positive power-of-two shifts (< profileDim) to fold
// a profileDim-wide dot product into slot 0, plus negative power-of-two shifts
// (< payloadSlots) to broadcast slot 0 across the candidate's payload bit-slots.
// The fold bound is "< profileDim" (not "<= profileDim/2"): for a non-power-of-two
// dim it must cover a window >= profileDim (the extra slots are zero), and it must
// match the rotate-and-add loop in fold_dot_to_first_slot exactly, or scoring would
// rotate by a shift whose key was never generated.
// This is the opt-in minimal set that replaces full-batch EvalSum + broadcast keygen.
//
// For (profileDim=128, payloadSlots=640) this is 7 positive + 10 negative = 17 indices,
// versus ~30 generated for a full ring/2 batch at ring 2^16.
func minimalRotationIndices(profileDim, payloadSlots int) []int {
	idx := make([]int, 0, 24)
	for s := 1; s < profileDim; s *= 2 {
		idx = append(idx, s)
	}
	for s := 1; s < payloadSlots; s *= 2 {
		idx = append(idx, -s)
	}
	return idx
}
