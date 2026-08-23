// SPDX-License-Identifier: Apache-2.0

package lineage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// NodeRef is a 32-byte SHA-256 content hash identifying a DAGNode.
type NodeRef [32]byte

// MarshalJSON encodes the ref as a lowercase 64-char hex string.
func (r NodeRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(r[:]))
}

// UnmarshalJSON decodes a 64-char hex string into the ref.
func (r *NodeRef) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if len(s) != 64 {
		return fmt.Errorf("lineage: NodeRef must be 64 hex chars, got %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("lineage: NodeRef hex decode: %w", err)
	}
	copy(r[:], raw)
	return nil
}

// DAGNode is one entry in the session-rooted Merkle DAG. Each node
// commits a byte payload to the triple (SessionID, PhaseID, Role)
// and references parent nodes that produced its inputs.
//
// The framework's runner auto-wraps phases to construct DAGNodes
// from Phase.Provides outputs; applications typically do not call
// NewDAGNode directly.
type DAGNode struct {
	// Hash is the canonical content hash. See DeriveNodeHash.
	Hash NodeRef

	// SessionID identifies the session this node belongs to.
	SessionID string

	// PhaseID is the phase name (matches Phase.Name).
	PhaseID string

	// Role is an app-defined string distinguishing multiple
	// outputs of the same phase ("profile-ct-p_i", "score-ct",
	// "winner-pkg"). Required.
	Role string

	// Parents are the hashes of nodes this output derives from
	// (typically declared via Phase.Requires). Stored in
	// canonical sorted order for deterministic hashing.
	Parents []NodeRef

	// ParentRoles is parallel to Parents (after sort), giving
	// human-readable role names for the parent nodes. Used for
	// forensic logging and audit; NOT part of the hash.
	ParentRoles []string

	// PayloadHash is sha256(payload bytes). Stored separately so
	// verifiers can confirm received bytes hash to PayloadHash
	// without re-deriving the full Hash chain.
	PayloadHash NodeRef

	// CreatedAt is the wall-clock time the producer constructed
	// this node. INFORMATIONAL ONLY — not part of Hash or
	// Signature. Useful for audit timeline reconstruction.
	CreatedAt time.Time

	// Producer is the producer's public key bytes (matches the
	// Signer's PublicKey()).
	Producer []byte

	// Signature is the producer's signature over the canonical
	// signing message (Hash || SessionID || PhaseID || Role).
	Signature []byte

	// Algorithm names the signature scheme (matches the
	// producer's Signer.Algorithm()).
	Algorithm string
}

// dagNodeJSON is the v2 wire DTO for DAGNode. All binary fields use
// lowercase hex strings; keys are snake_case. The in-memory DAGNode
// field types are unchanged — only the JSON form differs.
type dagNodeJSON struct {
	Hash        NodeRef   `json:"hash"`
	SessionID   string    `json:"session_id"`
	PhaseID     string    `json:"phase_id"`
	Role        string    `json:"role"`
	Parents     []NodeRef `json:"parents"`
	ParentRoles []string  `json:"parent_roles"`
	PayloadHash NodeRef   `json:"payload_hash"`
	CreatedAt   time.Time `json:"created_at"`
	Producer    string    `json:"producer"`  // lowercase hex
	Signature   string    `json:"signature"` // lowercase hex
	Algorithm   string    `json:"algorithm"`
}

// MarshalJSON encodes the node using snake_case keys and hex-encoded
// binary fields (hash, payload_hash, parents, producer, signature).
// Empty parent slices marshal as [] rather than null.
func (n DAGNode) MarshalJSON() ([]byte, error) {
	parents := n.Parents
	if parents == nil {
		parents = []NodeRef{}
	}
	roles := n.ParentRoles
	if roles == nil {
		roles = []string{}
	}
	return json.Marshal(dagNodeJSON{
		Hash:        n.Hash,
		SessionID:   n.SessionID,
		PhaseID:     n.PhaseID,
		Role:        n.Role,
		Parents:     parents,
		ParentRoles: roles,
		PayloadHash: n.PayloadHash,
		CreatedAt:   n.CreatedAt,
		Producer:    hex.EncodeToString(n.Producer),
		Signature:   hex.EncodeToString(n.Signature),
		Algorithm:   n.Algorithm,
	})
}

// UnmarshalJSON decodes a node from the v2 snake_case hex wire form.
func (n *DAGNode) UnmarshalJSON(b []byte) error {
	var d dagNodeJSON
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	prod, err := hex.DecodeString(d.Producer)
	if err != nil {
		return fmt.Errorf("lineage: producer hex decode: %w", err)
	}
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return fmt.Errorf("lineage: signature hex decode: %w", err)
	}
	*n = DAGNode{
		Hash:        d.Hash,
		SessionID:   d.SessionID,
		PhaseID:     d.PhaseID,
		Role:        d.Role,
		Parents:     d.Parents,
		ParentRoles: d.ParentRoles,
		PayloadHash: d.PayloadHash,
		CreatedAt:   d.CreatedAt,
		Producer:    prod,
		Signature:   sig,
		Algorithm:   d.Algorithm,
	}
	return nil
}

// NewDAGNode constructs a DAGNode with Hash + PayloadHash derived
// canonically from the inputs. Parents are sorted internally for
// determinism; the caller-supplied ParentRoles are reordered to
// match. CreatedAt is set to time.Now().UTC().
//
// The producer + signature + algorithm fields are passed through
// as supplied; Commit() is the convenience wrapper that runs the
// Signer.
func NewDAGNode(
	sessionID, phaseID, role string,
	payload []byte,
	parents []NodeRef,
	parentRoles []string,
	producer, signature []byte,
	algorithm string,
) DAGNode {
	sortedParents, sortedRoles := sortParents(parents, parentRoles)
	return DAGNode{
		Hash:        DeriveNodeHash(sessionID, phaseID, role, payload, sortedParents),
		SessionID:   sessionID,
		PhaseID:     phaseID,
		Role:        role,
		Parents:     sortedParents,
		ParentRoles: sortedRoles,
		PayloadHash: HashPayload(payload),
		CreatedAt:   time.Now().UTC(),
		Producer:    append([]byte(nil), producer...),
		Signature:   append([]byte(nil), signature...),
		Algorithm:   algorithm,
	}
}

// DeriveNodeHash computes the canonical content hash of a DAGNode
// from its identifying fields. The parents slice MUST already be
// in canonical sorted order (NewDAGNode sorts; callers using
// DeriveNodeHash directly are responsible for sorting).
//
// The format is length-prefixed concatenation under SHA-256:
//
//	sha256(
//	    u32(len SessionID) || SessionID ||
//	    u32(len PhaseID)   || PhaseID   ||
//	    u32(len Role)      || Role      ||
//	    u32(len PayloadHash bytes=32) || PayloadHash ||
//	    u32(num parents)   || parent[0] || parent[1] || ...
//	)
//
// Length prefixes prevent ambiguity (e.g., session="ab",phase="c"
// must not collide with session="a",phase="bc").
//
// CreatedAt is deliberately NOT in the hash — content-addressing
// requires determinism across producers with different clocks.
func DeriveNodeHash(sessionID, phaseID, role string, payload []byte, sortedParents []NodeRef) NodeRef {
	payloadHash := HashPayload(payload)
	h := sha256.New()
	writeLenPrefixed(h, []byte(sessionID))
	writeLenPrefixed(h, []byte(phaseID))
	writeLenPrefixed(h, []byte(role))
	writeLenPrefixed(h, payloadHash[:])
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(sortedParents)))
	_, _ = h.Write(n[:])
	for _, p := range sortedParents {
		_, _ = h.Write(p[:])
	}
	var out NodeRef
	copy(out[:], h.Sum(nil))
	return out
}

// HashPayload returns SHA-256(payload bytes) as a NodeRef.
func HashPayload(payload []byte) NodeRef {
	return NodeRef(sha256.Sum256(payload))
}

// SigningMessage returns the canonical bytes the producer signs.
// Defined as Hash || SessionID || PhaseID || Role concatenated
// with length prefixes for unambiguity.
func SigningMessage(hash NodeRef, sessionID, phaseID, role string) []byte {
	buf := bytes.NewBuffer(nil)
	_, _ = buf.Write(hash[:])
	writeLenPrefixed(buf, []byte(sessionID))
	writeLenPrefixed(buf, []byte(phaseID))
	writeLenPrefixed(buf, []byte(role))
	return buf.Bytes()
}

func writeLenPrefixed(w io.Writer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

// sortParents returns parents in lexicographic NodeRef order, with
// the parallel parentRoles slice reordered to match. If
// parentRoles is shorter than parents, missing roles are filled
// with the empty string.
func sortParents(parents []NodeRef, parentRoles []string) ([]NodeRef, []string) {
	indexed := make([]struct {
		ref  NodeRef
		role string
	}, len(parents))
	for i, p := range parents {
		role := ""
		if i < len(parentRoles) {
			role = parentRoles[i]
		}
		indexed[i] = struct {
			ref  NodeRef
			role string
		}{p, role}
	}
	sort.SliceStable(indexed, func(i, j int) bool {
		return bytes.Compare(indexed[i].ref[:], indexed[j].ref[:]) < 0
	})
	sortedRefs := make([]NodeRef, len(indexed))
	sortedRoles := make([]string, len(indexed))
	for i, x := range indexed {
		sortedRefs[i] = x.ref
		sortedRoles[i] = x.role
	}
	return sortedRefs, sortedRoles
}
