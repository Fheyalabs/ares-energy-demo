// SPDX-License-Identifier: Apache-2.0

package blind_bfv_payload_fuse

import (
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestProductionProfile(t *testing.T) {
	p := Profile()
	if p.Name != "bfv_ring32k_blind_v1" {
		t.Fatalf("Profile name = %q", p.Name)
	}
	if p.RingDim != 32768 || p.BatchSize != 128 || p.PackageBytes != 80 {
		t.Fatalf("unexpected production BFV profile: %+v", p)
	}
}

func TestCommitFusedPayloadReferencesParents(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	parent, err := CommitArtifact("session-1", RoleBFVCandidateCiphertext, []byte("candidate"), nil, signer)
	if err != nil {
		t.Fatalf("parent commit: %v", err)
	}
	child, err := CommitArtifact("session-1", RoleBFVFusedPayload, []byte("fused"), []ParentNode{parent}, signer)
	if err != nil {
		t.Fatalf("child commit: %v", err)
	}
	if len(child.Parents) != 1 || child.Parents[0] != parent.Hash {
		t.Fatalf("child parents = %v, want [%x]", child.Parents, parent.Hash)
	}
}
