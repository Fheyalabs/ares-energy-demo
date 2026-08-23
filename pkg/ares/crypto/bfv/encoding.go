// SPDX-License-Identifier: Apache-2.0

// Package bfv contains scheme-neutral helpers for BFV packed-integer
// circuits. The OpenFHE bridge lives in pkg/ares/crypto/cgo.
package bfv

import (
	"fmt"
	"math"
)

func QuantizeSigned(values []float64, scale int64) []int64 {
	out := make([]int64, len(values))
	if scale <= 0 {
		return out
	}
	lo, hi := -scale, scale
	for i, v := range values {
		q := int64(math.Round(v * float64(scale)))
		if q < lo {
			q = lo
		}
		if q > hi {
			q = hi
		}
		out[i] = q
	}
	return out
}

func PayloadBytesToSlots(payload []byte, slotCount int) []int64 {
	out := make([]int64, slotCount)
	for i, b := range payload {
		if i >= slotCount {
			break
		}
		out[i] = int64(b)
	}
	return out
}

func SlotsToPayloadBytes(slots []int64, payloadLen int) ([]byte, error) {
	if payloadLen < 0 {
		return nil, fmt.Errorf("payloadLen must be non-negative")
	}
	if payloadLen > len(slots) {
		return nil, fmt.Errorf("payloadLen %d exceeds slot count %d", payloadLen, len(slots))
	}
	out := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		if slots[i] < 0 || slots[i] > 255 {
			return nil, fmt.Errorf("slot %d = %d outside byte range", i, slots[i])
		}
		out[i] = byte(slots[i])
	}
	return out, nil
}
