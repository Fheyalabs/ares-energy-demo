// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

/*
#include "openfhe_wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// serializeRotKeyBVectors returns only the b-vectors of a rotation/eval-sum key
// share, the per-party b-only wire payload. The shared a-vectors are sent once
// (serializeRotKeyAVectors) or seeded from a CRS; the combiner rebuilds the full
// share with reconstructRotKeyFromAB.
func serializeRotKeyBVectors(key C.RotKeyHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeRotKeyBVectors(key, &data, &n); rc != 0 {
		return nil, fmt.Errorf("b-vector rotation-key serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

// serializeRotKeyAVectors returns only the shared CRS a-vectors of a rotation key
// (byte-identical across parties; transmit once per epoch or derive from a seed).
func serializeRotKeyAVectors(key C.RotKeyHandle) ([]byte, error) {
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeRotKeyAVectors(key, &data, &n); rc != 0 {
		return nil, fmt.Errorf("a-vector rotation-key serialization failed")
	}
	defer C.free(unsafe.Pointer(data))
	return copyCBytes(data, n), nil
}

// reconstructRotKeyFromAB rebuilds a full rotation-key share from the shared
// a-vectors and a party's b-vectors. The caller frees the returned handle with
// C.FreeRotKey. The two serialized maps must cover the same rotation indices.
func reconstructRotKeyFromAB(ctx C.CryptoContextHandle, a, b []byte) (C.RotKeyHandle, error) {
	if len(a) == 0 || len(b) == 0 {
		return nil, fmt.Errorf("both a-vectors and b-vectors are required")
	}
	key := C.ReconstructRotKeyFromAB(ctx,
		(*C.uint8_t)(unsafe.Pointer(&a[0])), C.size_t(len(a)),
		(*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	if key == nil {
		return nil, fmt.Errorf("b-only rotation-key reconstruction failed")
	}
	return key, nil
}

// deserializeAVectors deserializes the shared a-vectors into a reusable handle.
// The a-vectors are byte-identical across parties, so deserialize ONCE per index
// and reuse for all N party reconstructions. Caller frees with freeAVectors.
func deserializeAVectors(a []byte) (C.AVectorsHandle, error) {
	if len(a) == 0 {
		return nil, fmt.Errorf("a-vectors are required")
	}
	h := C.DeserializeAVectors((*C.uint8_t)(unsafe.Pointer(&a[0])), C.size_t(len(a)))
	if h == nil {
		return nil, fmt.Errorf("a-vector deserialization failed")
	}
	return h, nil
}

func freeAVectors(h C.AVectorsHandle) {
	C.FreeAVectors(h)
}

// reconstructRotKeyFromAVectors rebuilds a rotation-key share from a pre-deserialized
// a-vector handle and a party's b-vectors. Avoids re-deserializing the shared a per party.
func reconstructRotKeyFromAVectors(ctx C.CryptoContextHandle, a C.AVectorsHandle, b []byte) (C.RotKeyHandle, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("b-vectors are required")
	}
	key := C.ReconstructRotKeyFromAVectors(ctx, a,
		(*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	if key == nil {
		return nil, fmt.Errorf("b-only rotation-key reconstruction from cached a failed")
	}
	return key, nil
}

// SplitRotShareAB splits a serialized rotation/eval-sum key share into its shared
// a-vectors and its per-party b-vectors. A participant uploads only b; the shared a
// is transmitted once per epoch (or seeded from a CRS) and the combiner rebuilds the
// full share with ReconstructRotShareAB. Halves the per-party upload with no new crypto.
func SplitRotShareAB(params ContractParams, fullShare []byte) (a []byte, b []byte, err error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, nil, err
	}
	defer C.FreeCryptoContext(ctx)

	share, err := deserializeRotKey(ctx, fullShare)
	if err != nil {
		return nil, nil, err
	}
	defer C.FreeRotKey(share)

	if a, err = serializeRotKeyAVectors(share); err != nil {
		return nil, nil, err
	}
	if b, err = serializeRotKeyBVectors(share); err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

// ReconstructRotShareAB rebuilds a full rotation-key share from the shared a-vectors
// and a party's b-vectors, returning its full serialization. The two serialized maps
// must cover the same rotation indices.
func ReconstructRotShareAB(params ContractParams, a, b []byte) ([]byte, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return nil, err
	}
	defer C.FreeCryptoContext(ctx)

	share, err := reconstructRotKeyFromAB(ctx, a, b)
	if err != nil {
		return nil, err
	}
	defer C.FreeRotKey(share)
	return serializeRotKey(share)
}

// bOnlyRotResult holds the serialized byte slices a correctness test compares.
type bOnlyRotResult struct {
	full   []byte // full (a,b) serialization of the participant share
	aBase  []byte // a-vectors from the lead base (the shared CRS)
	aShare []byte // a-vectors from the participant share (must equal aBase)
	bShare []byte // b-vectors from the participant share (the b-only payload)
	reconA []byte // a-vectors of the share rebuilt from aBase + bShare
	reconB []byte // b-vectors of the rebuilt share
}

// runBOnlyRotReconstruction runs a 2-party eval-sum keygen, serializes the
// participant share full / a-only / b-only, rebuilds it from the shared a + its b,
// and returns the byte slices so a (cgo-free) test can assert on them. All C
// handles are freed before returning.
func runBOnlyRotReconstruction(params ContractParams) (res bOnlyRotResult, err error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return res, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk0, pk1 C.PublicKeyHandle
	var sk0, sk1 C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk0, &sk0); rc != 0 {
		return res, fmt.Errorf("keygen first failed")
	}
	defer C.FreePublicKey(pk0)
	defer C.FreeSecretKeyShare(sk0)
	if rc := C.KeyGenNext(ctx, pk0, &pk1, &sk1); rc != 0 {
		return res, fmt.Errorf("keygen next failed")
	}
	defer C.FreePublicKey(pk1)
	defer C.FreeSecretKeyShare(sk1)

	var base, share C.RotKeyHandle
	if rc := C.EvalSumKeyGenLead(ctx, sk0, &base); rc != 0 {
		return res, fmt.Errorf("eval-sum lead failed")
	}
	defer C.FreeRotKey(base)
	if rc := C.EvalSumKeyShare(ctx, sk1, base, pk1, &share); rc != 0 {
		return res, fmt.Errorf("eval-sum share failed")
	}
	defer C.FreeRotKey(share)

	if res.full, err = serializeRotKey(share); err != nil {
		return res, err
	}
	if res.aBase, err = serializeRotKeyAVectors(base); err != nil {
		return res, err
	}
	if res.aShare, err = serializeRotKeyAVectors(share); err != nil {
		return res, err
	}
	if res.bShare, err = serializeRotKeyBVectors(share); err != nil {
		return res, err
	}

	recon, err := reconstructRotKeyFromAB(ctx, res.aBase, res.bShare)
	if err != nil {
		return res, err
	}
	defer C.FreeRotKey(recon)
	if res.reconA, err = serializeRotKeyAVectors(recon); err != nil {
		return res, err
	}
	if res.reconB, err = serializeRotKeyBVectors(recon); err != nil {
		return res, err
	}
	return res, nil
}
