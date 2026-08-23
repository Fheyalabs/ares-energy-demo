// SPDX-License-Identifier: Apache-2.0

package blind_bfv_payload_fuse

import (
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/bfv"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/profiles"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

type ParentNode = lineage.DAGNode

const (
	PhaseBFVPayloadFuse        = "bfv.payload_fuse.ring32k"
	RoleBFVInitiatorCiphertext = "bfv.initiator_ct"
	RoleBFVCandidateCiphertext = "bfv.candidate_ct"
	RoleBFVPayloadCiphertext   = "bfv.payload_ct"
	RoleBFVFusedPayload        = "bfv.fused_payload_ct"
)

func Profile() profiles.BFVBlindProfile {
	return profiles.BFVRing32KBlindV1()
}

func QuantizeProfile(values []float64) []int64 {
	return bfv.QuantizeSigned(values, int64(Profile().QuantizationScale))
}

func PayloadBytesToSlots(payload []byte) []int64 {
	return bfv.PayloadBytesToSlots(payload, Profile().PackageBytes)
}

func CommitArtifact(sessionID, role string, payload []byte, parents []ParentNode, signer sign.Signer) (lineage.DAGNode, error) {
	return lineage.Commit(sessionID, PhaseBFVPayloadFuse, role, payload, parents, signer)
}
