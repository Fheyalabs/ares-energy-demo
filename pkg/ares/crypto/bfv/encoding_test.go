// SPDX-License-Identifier: Apache-2.0

package bfv

import "testing"

func TestQuantizeSignedClipsToScale(t *testing.T) {
	got := QuantizeSigned([]float64{-2, -0.5, 0, 0.49, 2}, 63)
	want := []int64{-63, -32, 0, 31, 63}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slot %d = %d, want %d (all %v)", i, got[i], want[i], got)
		}
	}
}

func TestPayloadBytesRoundTrip(t *testing.T) {
	payload := []byte{0, 1, 127, 128, 255}
	slots := PayloadBytesToSlots(payload, 8)
	if len(slots) != 8 {
		t.Fatalf("slots len = %d, want 8", len(slots))
	}
	got, err := SlotsToPayloadBytes(slots, len(payload))
	if err != nil {
		t.Fatalf("SlotsToPayloadBytes: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %v, want %v", got, payload)
	}
}

func TestSlotsToPayloadBytesRejectsOutOfByteRange(t *testing.T) {
	_, err := SlotsToPayloadBytes([]int64{0, 256}, 2)
	if err == nil {
		t.Fatalf("expected byte-range error")
	}
}
