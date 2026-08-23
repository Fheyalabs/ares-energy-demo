// SPDX-License-Identifier: Apache-2.0

//go:build !openfhe

package bounded_admission

import "github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"

// BuildSessionCrypto returns (nil, nil, nil) in stub mode — no real FHE.
// The boundcheck phase will operate in stub mode (Enter/Exit no-ops).
func BuildSessionCrypto(ringDim, depth, dim int, jointPK, evalMultFinal, evalSumFinal []byte) (fhecalib.ContextHandle, func([][]byte, int) ([]float64, error), error) {
	return nil, nil, nil
}
