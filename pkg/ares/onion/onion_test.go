// SPDX-License-Identifier: Apache-2.0

package onion_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/onion"
)

// Full N-party shuffle: every participant builds an onion of their
// (slot) payload wrapped for all peelers including self; peelers peel
// in order, identifying their own item by selfMemo; the last peeler
// recovers all N-1 payloads. Asserts SC-2 correctness (no item is
// fully peeled before the final round) implicitly via successful
// recovery + correct own-identification at every peeler.
func TestOnion_FullShuffleRecoversAllPayloads(t *testing.T) {
	for _, n := range []int{3, 5, 6} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			privs := make([][]byte, n)
			pubs := make([][]byte, n)
			for i := 0; i < n; i++ {
				priv, pub, err := onion.GenerateSlotKey()
				if err != nil {
					t.Fatalf("keygen %d: %v", i, err)
				}
				privs[i], pubs[i] = priv, pub
			}

			payloads := make([][]byte, n)
			onions := make([][]byte, n)
			selfMemos := make([][]byte, n)
			for b := 0; b < n; b++ {
				payloads[b] = []byte(fmt.Sprintf("payload-%d", b))
				o, memo, err := onion.BuildOnion(payloads[b], pubs, b)
				if err != nil {
					t.Fatalf("build %d: %v", b, err)
				}
				onions[b], selfMemos[b] = o, memo
			}

			batch := onions
			for k := 0; k < n; k++ {
				peeled, own, err := onion.PeelBatch(privs[k], selfMemos[k], batch)
				if err != nil {
					t.Fatalf("peel by %d: %v", k, err)
				}
				if own < 0 {
					t.Fatalf("peeler %d failed to identify its own item", k)
				}
				if len(peeled) != n {
					t.Fatalf("peeler %d: got %d items want %d", k, len(peeled), n)
				}
				batch = peeled
			}

			got := make(map[string]bool)
			for _, p := range batch {
				got[string(p)] = true
			}
			for b := 0; b < n; b++ {
				if !got[string(payloads[b])] {
					t.Fatalf("payload %q not recovered; final batch=%v", payloads[b], batch)
				}
			}
		})
	}
}

func TestOnion_SelfMemoIdentifiesOwnItem(t *testing.T) {
	const n = 4
	privs := make([][]byte, n)
	pubs := make([][]byte, n)
	for i := 0; i < n; i++ {
		privs[i], pubs[i], _ = onion.GenerateSlotKey()
	}
	onions := make([][]byte, n)
	var memo2 []byte
	for b := 0; b < n; b++ {
		o, memo, err := onion.BuildOnion([]byte(fmt.Sprintf("p%d", b)), pubs, b)
		if err != nil {
			t.Fatalf("build %d: %v", b, err)
		}
		onions[b] = o
		if b == 2 {
			memo2 = memo
		}
	}
	b0, _, _ := onion.PeelBatch(privs[0], nil, onions)
	b1, _, _ := onion.PeelBatch(privs[1], nil, b0)
	_, own, err := onion.PeelBatch(privs[2], memo2, b1)
	if err != nil {
		t.Fatalf("peel by 2: %v", err)
	}
	if own < 0 {
		t.Fatal("peeler 2 did not identify its own item via selfMemo")
	}
	if !bytes.Equal(b1[own], memo2) {
		t.Fatalf("own item bytes != selfMemo")
	}
}
