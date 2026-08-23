// SPDX-License-Identifier: Apache-2.0

package lineage

import (
	"fmt"

	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Verify checks the integrity of a DAGNode against the byte payload
// it claims to commit to. Verifies:
//
//  1. node.Algorithm is in verifiers (else *MismatchError{Field:"Algorithm"}).
//  2. SHA-256(payload) equals node.PayloadHash (else *MismatchError{Field:"PayloadHash"}).
//  3. node.Hash equals the canonical DeriveNodeHash on the node's
//     fields + node.PayloadHash + node.Parents.
//  4. node.Signature is valid under node.Producer on the canonical
//     SigningMessage (else *MismatchError{Field:"Signature"}).
//
// Parent-ref existence (ParentRef field) is checked at Store.Append
// time, not here, since Verify operates on a single node in
// isolation.
//
// verifiers is keyed by Algorithm string so multiple signature
// schemes can coexist in one deployment.
func Verify(node DAGNode, payload []byte, verifiers map[string]sign.Signer) error {
	v, ok := verifiers[node.Algorithm]
	if !ok {
		return &MismatchError{
			Field:    "Algorithm",
			Expected: []byte(fmt.Sprintf("verifier for %q", node.Algorithm)),
			Got:      nil,
			NodeHash: node.Hash,
		}
	}

	payloadHash := HashPayload(payload)
	if payloadHash != node.PayloadHash {
		return &MismatchError{
			Field:    "PayloadHash",
			Expected: node.PayloadHash[:],
			Got:      payloadHash[:],
			NodeHash: node.Hash,
		}
	}

	// Re-derive the canonical hash and confirm it matches node.Hash.
	// This catches a node whose declared Hash is inconsistent with
	// its other fields (e.g., a tampered Hash byte).
	derived := DeriveNodeHash(node.SessionID, node.PhaseID, node.Role, payload, node.Parents)
	if derived != node.Hash {
		return &MismatchError{
			Field:    "PayloadHash",
			Expected: node.Hash[:],
			Got:      derived[:],
			NodeHash: node.Hash,
		}
	}

	// Defensive: confirm Producer non-empty before signature check.
	if len(node.Producer) == 0 {
		return &MismatchError{
			Field:    "Signature",
			Expected: []byte("non-empty producer pubkey"),
			Got:      nil,
			NodeHash: node.Hash,
		}
	}

	sigMsg := SigningMessage(node.Hash, node.SessionID, node.PhaseID, node.Role)
	if err := v.Verify(node.Producer, sigMsg, node.Signature); err != nil {
		return &MismatchError{
			Field:    "Signature",
			Expected: node.Signature,
			Got:      nil,
			NodeHash: node.Hash,
		}
	}

	return nil
}
