// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package cgo

import (
	"reflect"
	"testing"
)

func TestMinimalRotationIndices(t *testing.T) {
	got := minimalRotationIndices(128, 640)
	want := []int{
		1, 2, 4, 8, 16, 32, 64, // sum: fold the 128-dim dot into slot 0
		-1, -2, -4, -8, -16, -32, -64, -128, -256, -512, // broadcast: slot 0 -> 640 payload slots
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("minimalRotationIndices(128,640) = %v, want %v", got, want)
	}
	if len(got) != 17 {
		t.Fatalf("expected 17 indices for (128,640), got %d", len(got))
	}
}

func TestMinimalRotationIndicesEdgeCases(t *testing.T) {
	if got := minimalRotationIndices(1, 1); len(got) != 0 {
		t.Fatalf("(1,1) should yield no indices, got %v", got)
	}
	// dim=5 needs shifts {1,2,4} to cover the 5-slot fold window (8>=5); {1,2}
	// covers only 4 slots and would drop slot 4. Must match Task 3's fold bound.
	got := minimalRotationIndices(5, 3) // sum: 1,2,4 ; broadcast: -1,-2
	want := []int{1, 2, 4, -1, -2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("(5,3) = %v, want %v", got, want)
	}
}
