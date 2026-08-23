// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

/*
#include "openfhe_wrapper.h"
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

// benchResidentCombineRound1 models a precompute pool that holds the context and
// the deserialized eval-key share handles resident in RAM: it deserializes the
// round-1 shares once (the precompute), then times ONLY the handle combine — no
// per-cohort serialization round-trip. Returns the resident combine duration.
// Build-tagged openfhe; used by the keygen benchmark to isolate (de)serialization
// overhead from genuine combine compute.
func benchResidentCombineRound1(params ContractParams, pubKeys, multShares, sumShares [][]byte) (time.Duration, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return 0, err
	}
	defer C.FreeCryptoContext(ctx)

	pks, freePKs, err := deserializePublicKeys(ctx, pubKeys)
	if err != nil {
		return 0, err
	}
	defer freePKs()
	multH, freeM, err := deserializeEvalMultKeys(ctx, multShares)
	if err != nil {
		return 0, err
	}
	defer freeM()
	sumH, freeS, err := deserializeRotKeys(ctx, sumShares)
	if err != nil {
		return 0, err
	}
	defer freeS()

	start := time.Now()
	var joined C.EvalMultKeyHandle
	if rc := C.CombineEvalMultSwitchShares(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.EvalMultKeyHandle)(unsafe.Pointer(&multH[0])), C.int(len(multH)), &joined); rc != 0 {
		return 0, fmt.Errorf("resident eval-mult combine failed")
	}
	defer C.FreeEvalMultKey(joined)
	var sumFinal C.RotKeyHandle
	if rc := C.CombineEvalSumKeys(ctx, (*C.PublicKeyHandle)(unsafe.Pointer(&pks[0])), (*C.RotKeyHandle)(unsafe.Pointer(&sumH[0])), C.int(len(sumH)), &sumFinal); rc != 0 {
		return 0, fmt.Errorf("resident eval-sum combine failed")
	}
	defer C.FreeRotKey(sumFinal)
	return time.Since(start), nil
}
