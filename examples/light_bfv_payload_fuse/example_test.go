// SPDX-License-Identifier: Apache-2.0

package light_bfv_payload_fuse

import (
	"context"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestLightProfileAndEncoding(t *testing.T) {
	p := Profile()
	if p.Name != "bfv_light_blind_v1" {
		t.Fatalf("Profile name = %q", p.Name)
	}
	q := QuantizeProfile([]float64{-1, -0.25, 0.25, 1})
	want := []int64{-15, -4, 4, 15}
	for i := range want {
		if q[i] != want[i] {
			t.Fatalf("q[%d] = %d, want %d (all %v)", i, q[i], want[i], q)
		}
	}
}

func TestCommitArtifactUsesLineage(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store := lineage.NewInMemoryStore()
	node, err := CommitArtifact("session-1", RoleBFVCandidateCiphertext, []byte("ciphertext"), nil, signer)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := store.Append(context.Background(), node); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := lineage.Verify(node, []byte("ciphertext"), map[string]sign.Signer{sign.Ed25519Algorithm: signer}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
