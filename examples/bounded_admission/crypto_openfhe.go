// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package bounded_admission

import (
	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
)

// BuildSessionCrypto reconstructs the per-session ContextHandle + fuse from the
// client-seeded key bundle (collective PK + eval-mult-final + eval-sum-final).
// The nParties parameter for DefaultContractParams is set to 0 because the
// number of parties is unused for handle/fuse construction.
func BuildSessionCrypto(ringDim, depth, dim int, jointPK, evalMultFinal, evalSumFinal []byte) (fhecalib.ContextHandle, func([][]byte, int) ([]float64, error), error) {
	params := cgo.DefaultContractParams(dim, 0)
	params.RingDim = uint32(ringDim)
	params.Depth = uint32(depth)

	evalKeys := cgo.EvalKeyFinal{
		EvalMultFinal: evalMultFinal,
		EvalSumFinal:  evalSumFinal,
	}
	hc := helperclient.ContractParams{
		RingDim:        params.RingDim,
		Depth:          params.Depth,
		ScalingModSize: 50,
	}
	handle := fhecalib.NewContextHandle(hc, evalKeys, jointPK)
	fuse := func(partials [][]byte, nSlots int) ([]float64, error) {
		return cgo.FuseCKKSPartialsForContract(params, partials, nSlots)
	}
	return handle, fuse, nil
}
