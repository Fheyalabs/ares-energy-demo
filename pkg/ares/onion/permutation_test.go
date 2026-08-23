// SPDX-License-Identifier: Apache-2.0

package onion_test

import (
	"sort"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/onion"
)

func TestSlotPermutation_IsADeterministicPermutation(t *testing.T) {
	seed := []byte("gossip-seed")
	const n = 5
	p1 := onion.SlotPermutation(seed, n)
	p2 := onion.SlotPermutation(seed, n)

	if len(p1) != n {
		t.Fatalf("len = %d want %d", len(p1), n)
	}
	for i := range p1 {
		if p1[i] != p2[i] {
			t.Fatalf("not deterministic at %d: %d vs %d", i, p1[i], p2[i])
		}
	}
	sorted := append([]int(nil), p1...)
	sort.Ints(sorted)
	for i := 0; i < n; i++ {
		if sorted[i] != i {
			t.Fatalf("not a permutation of [0,n): %v", p1)
		}
	}
}

func TestSlotPermutation_DiffersBySeed(t *testing.T) {
	a := onion.SlotPermutation([]byte("seed-a"), 8)
	b := onion.SlotPermutation([]byte("seed-b"), 8)
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different seeds should (almost surely) give different permutations")
	}
}
