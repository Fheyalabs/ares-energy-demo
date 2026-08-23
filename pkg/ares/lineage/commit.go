// SPDX-License-Identifier: Apache-2.0

package lineage

import (
	"errors"

	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// Commit constructs a signed DAGNode for the given payload. It does
// NOT persist; callers typically pass the result to Store.Append.
//
// Parents must be the upstream DAGNodes whose outputs feed into
// this node's payload (typically the nodes registered for the
// phase's Requires keys). Their Hash fields become this node's
// Parents (sorted canonically); their Roles populate ParentRoles
// (parallel after sort) for audit.
//
// Returns an error if signer is nil or the Sign call fails.
func Commit(
	sessionID, phaseID, role string,
	payload []byte,
	parents []DAGNode,
	signer sign.Signer,
) (DAGNode, error) {
	if signer == nil {
		return DAGNode{}, errors.New("lineage: Commit requires non-nil signer")
	}

	parentRefs := make([]NodeRef, len(parents))
	parentRoles := make([]string, len(parents))
	for i, p := range parents {
		parentRefs[i] = p.Hash
		parentRoles[i] = p.Role
	}

	// Sort parents canonically before computing the hash (NewDAGNode
	// will sort again but we need the sorted refs for the hash
	// computation below — and re-sorting is cheap + idempotent).
	sortedRefs, sortedRoles := sortParents(parentRefs, parentRoles)
	hash := DeriveNodeHash(sessionID, phaseID, role, payload, sortedRefs)

	sigMsg := SigningMessage(hash, sessionID, phaseID, role)
	signature, err := signer.Sign(sigMsg)
	if err != nil {
		return DAGNode{}, err
	}

	return NewDAGNode(
		sessionID, phaseID, role, payload,
		sortedRefs, sortedRoles,
		signer.PublicKey(), signature, signer.Algorithm(),
	), nil
}
