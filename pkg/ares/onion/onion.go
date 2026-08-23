// SPDX-License-Identifier: Apache-2.0

package onion

import (
	"bytes"
	"errors"
	"fmt"
)

// BuildOnion wraps payload in len(peelOrderPubs) ECIES layers in the
// REVERSE of peel order — innermost layer for the last peeler,
// outermost for the first — INCLUDING the builder's own layer at
// selfIndex (SC-2: no skip-self). It returns the assembled onion and
// selfMemo: the onion bytes immediately after the builder's own layer
// is applied. selfMemo is what the builder will receive (as the outer
// bytes of its own item) when it is the builder's turn to peel, so the
// builder identifies its own item by exact byte match — never by
// "cannot decrypt", which is the SC-2 fix.
func BuildOnion(payload []byte, peelOrderPubs [][]byte, selfIndex int) (onion, selfMemo []byte, err error) {
	if selfIndex < 0 || selfIndex >= len(peelOrderPubs) {
		return nil, nil, fmt.Errorf("onion: selfIndex %d out of range [0,%d)", selfIndex, len(peelOrderPubs))
	}
	data := append([]byte(nil), payload...)
	for i := len(peelOrderPubs) - 1; i >= 0; i-- {
		enc, err := ECIESEncrypt(peelOrderPubs[i], data)
		if err != nil {
			return nil, nil, fmt.Errorf("onion: wrap layer %d: %w", i, err)
		}
		data = enc
		if i == selfIndex {
			selfMemo = append([]byte(nil), data...)
		}
	}
	return data, selfMemo, nil
}

// PeelBatch removes one layer from every onion in the batch using the
// peeler's slot private key, returning the peeled inner layers in input
// order. It identifies the peeler's own item by exact byte match
// against selfMemo (ciphertext memory match) and returns its index as
// ownIndex (-1 if selfMemo is nil or no match — callers that always
// have a self item should treat ownIndex<0 as an error).
//
// All items in a well-formed batch are addressed to this peeler at this
// round; a decryption failure is therefore a protocol error, not a
// self-identification signal.
func PeelBatch(myPriv, selfMemo []byte, onions [][]byte) (peeled [][]byte, ownIndex int, err error) {
	ownIndex = -1
	peeled = make([][]byte, len(onions))
	for i, o := range onions {
		if selfMemo != nil && bytes.Equal(o, selfMemo) {
			ownIndex = i
		}
		inner, derr := ECIESDecrypt(myPriv, o)
		if derr != nil {
			return nil, -1, fmt.Errorf("onion: peel item %d: %w", i, derr)
		}
		peeled[i] = inner
	}
	if selfMemo != nil && ownIndex < 0 {
		return nil, -1, errors.New("onion: selfMemo did not match any item in batch")
	}
	return peeled, ownIndex, nil
}
