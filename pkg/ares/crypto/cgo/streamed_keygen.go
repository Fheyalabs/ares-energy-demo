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

// benchRotShareGen generates one non-lead party's rotation-key share against a lead
// base, either all-at-once (EvalSumKeyShare — today's path: build the whole map,
// then serialize) or streamed per-index (StreamedRotShareBytes — generate one
// rotation index, serialize, free, repeat). Returns the total serialized bytes.
// Peak RSS is sampled by the caller; this is the comparison that shows whether
// streaming bounds the per-party generation peak. openfhe-tagged benchmark helper.
func benchRotShareGen(params ContractParams, streamed bool) (uint64, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return 0, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk0, pk1 C.PublicKeyHandle
	var sk0, sk1 C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk0, &sk0); rc != 0 {
		return 0, fmt.Errorf("keygen first failed")
	}
	defer C.FreePublicKey(pk0)
	defer C.FreeSecretKeyShare(sk0)
	if rc := C.KeyGenNext(ctx, pk0, &pk1, &sk1); rc != 0 {
		return 0, fmt.Errorf("keygen next failed")
	}
	defer C.FreePublicKey(pk1)
	defer C.FreeSecretKeyShare(sk1)

	var base C.RotKeyHandle
	if rc := C.EvalSumKeyGenLead(ctx, sk0, &base); rc != 0 {
		return 0, fmt.Errorf("eval-sum lead failed")
	}
	defer C.FreeRotKey(base)

	if streamed {
		var total C.ulonglong
		if rc := C.StreamedRotShareBytes(ctx, sk1, base, pk1, &total); rc != 0 {
			return 0, fmt.Errorf("streamed rot share failed")
		}
		return uint64(total), nil
	}

	var share C.RotKeyHandle
	if rc := C.EvalSumKeyShare(ctx, sk1, base, pk1, &share); rc != 0 {
		return 0, fmt.Errorf("eval-sum share failed")
	}
	defer C.FreeRotKey(share)
	var data *C.uint8_t
	var n C.size_t
	if rc := C.SerializeRotKey(share, &data, &n); rc != 0 {
		return 0, fmt.Errorf("serialize rot share failed")
	}
	C.free(unsafe.Pointer(data))
	return uint64(n), nil
}

// benchStreamedFullRot runs the FULLY-streamed 2-party rotation keygen: both the
// lead base and the participant share are generated one index at a time, so no
// full rotation-key map is ever held. Peak RSS is bounded to a single index
// regardless of ring. Returns total serialized bytes (lead + participant).
func benchStreamedFullRot(params ContractParams) (uint64, error) {
	ctx, err := createContractContext(params)
	if err != nil {
		return 0, err
	}
	defer C.FreeCryptoContext(ctx)

	var pk0, pk1 C.PublicKeyHandle
	var sk0, sk1 C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk0, &sk0); rc != 0 {
		return 0, fmt.Errorf("keygen first failed")
	}
	defer C.FreePublicKey(pk0)
	defer C.FreeSecretKeyShare(sk0)
	if rc := C.KeyGenNext(ctx, pk0, &pk1, &sk1); rc != 0 {
		return 0, fmt.Errorf("keygen next failed")
	}
	defer C.FreePublicKey(pk1)
	defer C.FreeSecretKeyShare(sk1)

	var total C.ulonglong
	if rc := C.StreamedTwoPartyRotKeygenBytes(ctx, sk0, sk1, pk1, &total); rc != 0 {
		return 0, fmt.Errorf("streamed two-party rot keygen failed")
	}
	return uint64(total), nil
}

// benchBOnlyRotShare reports, for one rotation index, whether the CRS 'a' is shared
// across parties and the full-key vs b-only serialized sizes — i.e. whether a party
// can transmit only its b-vector (server rebuilds the key from the shared a).
func benchBOnlyRotShare(params ContractParams) (full, bOnly uint64, aShared bool, err error) {
	ctx, e := createContractContext(params)
	if e != nil {
		return 0, 0, false, e
	}
	defer C.FreeCryptoContext(ctx)

	var pk0, pk1 C.PublicKeyHandle
	var sk0, sk1 C.SecretKeyShareHandle
	if rc := C.KeyGenFirst(ctx, &pk0, &sk0); rc != 0 {
		return 0, 0, false, fmt.Errorf("keygen first failed")
	}
	defer C.FreePublicKey(pk0)
	defer C.FreeSecretKeyShare(sk0)
	if rc := C.KeyGenNext(ctx, pk0, &pk1, &sk1); rc != 0 {
		return 0, 0, false, fmt.Errorf("keygen next failed")
	}
	defer C.FreePublicKey(pk1)
	defer C.FreeSecretKeyShare(sk1)

	var f, b C.ulonglong
	var shared C.int
	if rc := C.MeasureBOnlyRotShare(ctx, sk0, sk1, pk1, &f, &b, &shared); rc != 0 {
		return 0, 0, false, fmt.Errorf("measure b-only failed rc=%d", int(rc))
	}
	return uint64(f), uint64(b), shared == 1, nil
}
