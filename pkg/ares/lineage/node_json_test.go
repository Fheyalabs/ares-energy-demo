// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestDAGNode_JSONRoundTrip marshals a Commit-produced DAGNode and
// unmarshals it back, asserting deep field equality. CreatedAt is
// compared with .Equal (strips monotonic clock component).
func TestDAGNode_JSONRoundTrip(t *testing.T) {
	signer, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	node, err := lineage.Commit("sess-rt", "phase-rt", "role-rt", []byte("round-trip payload"), nil, signer)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	wire, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got lineage.DAGNode
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Hash != node.Hash {
		t.Errorf("Hash: got %x, want %x", got.Hash, node.Hash)
	}
	if got.SessionID != node.SessionID {
		t.Errorf("SessionID: got %q, want %q", got.SessionID, node.SessionID)
	}
	if got.PhaseID != node.PhaseID {
		t.Errorf("PhaseID: got %q, want %q", got.PhaseID, node.PhaseID)
	}
	if got.Role != node.Role {
		t.Errorf("Role: got %q, want %q", got.Role, node.Role)
	}
	if got.PayloadHash != node.PayloadHash {
		t.Errorf("PayloadHash: got %x, want %x", got.PayloadHash, node.PayloadHash)
	}
	if got.Algorithm != node.Algorithm {
		t.Errorf("Algorithm: got %q, want %q", got.Algorithm, node.Algorithm)
	}
	// Producer and Signature are []byte — compare by hex representation.
	if hex.EncodeToString(got.Producer) != hex.EncodeToString(node.Producer) {
		t.Errorf("Producer mismatch after round-trip")
	}
	if hex.EncodeToString(got.Signature) != hex.EncodeToString(node.Signature) {
		t.Errorf("Signature mismatch after round-trip")
	}
	// CreatedAt: strip monotonic component before comparing.
	if !got.CreatedAt.Equal(node.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, node.CreatedAt)
	}
	// Parents: both nil/empty slices from a genesis node — just check length.
	if len(got.Parents) != 0 {
		t.Errorf("Parents: got len %d, want 0", len(got.Parents))
	}
}

// TestDAGNode_JSONRoundTrip_WithParents confirms Parents and
// ParentRoles survive a marshal/unmarshal cycle intact.
func TestDAGNode_JSONRoundTrip_WithParents(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	parent, _ := lineage.Commit("sess", "phase-parent", "role-parent", []byte("parent payload"), nil, signer)
	child, err := lineage.Commit("sess", "phase-child", "role-child", []byte("child payload"),
		[]lineage.DAGNode{parent}, signer)
	if err != nil {
		t.Fatalf("Commit child: %v", err)
	}

	wire, err := json.Marshal(child)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got lineage.DAGNode
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(got.Parents) != 1 || got.Parents[0] != child.Parents[0] {
		t.Errorf("Parents round-trip failed: got %v, want %v", got.Parents, child.Parents)
	}
	if len(got.ParentRoles) != 1 || got.ParentRoles[0] != child.ParentRoles[0] {
		t.Errorf("ParentRoles round-trip failed: got %v, want %v", got.ParentRoles, child.ParentRoles)
	}
}

// TestDAGNode_GoldenEncoding checks the marshaled JSON for:
//   - snake_case keys ("hash", "payload_hash", "session_id", etc.)
//   - "parents":[] (empty array, not null)
//   - 64-char hex string for "hash" (not a JSON array)
//   - hex producer string (no base64 padding '=')
func TestDAGNode_GoldenEncoding(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, err := lineage.Commit("sess-golden", "phase-golden", "role-golden",
		[]byte("golden payload"), nil, signer)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	wire, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	j := string(wire)
	t.Logf("golden JSON: %s", j)

	// Must contain snake_case keys.
	for _, key := range []string{`"hash":`, `"session_id":`, `"phase_id":`, `"payload_hash":`, `"parents":`, `"producer":`, `"signature":`, `"algorithm":`, `"created_at":`, `"parent_roles":`} {
		if !strings.Contains(j, key) {
			t.Errorf("JSON missing key %s", key)
		}
	}

	// "parents" must be empty array, not null.
	if !strings.Contains(j, `"parents":[]`) {
		t.Errorf(`"parents" is not [] in: %s`, j)
	}

	// "hash" must be a 64-char hex string, not a JSON array.
	// A JSON array would start with "[" immediately after the colon.
	if strings.Contains(j, `"hash":[`) {
		t.Errorf(`"hash" looks like an int-array: %s`, j)
	}
	// Verify the hash value is a 64-char hex string by extracting it.
	hashVal := extractJSONStringValue(j, `"hash":"`)
	if len(hashVal) != 64 {
		t.Errorf(`"hash" value is %d chars (want 64): %q`, len(hashVal), hashVal)
	}
	if _, err := hex.DecodeString(hashVal); err != nil {
		t.Errorf(`"hash" value is not valid hex: %q`, hashVal)
	}

	// "payload_hash" must also be a 64-char hex string.
	phVal := extractJSONStringValue(j, `"payload_hash":"`)
	if len(phVal) != 64 {
		t.Errorf(`"payload_hash" value is %d chars (want 64): %q`, len(phVal), phVal)
	}

	// "producer" must not contain base64 padding.
	if strings.Contains(j, "=") {
		t.Errorf(`JSON contains base64 padding '=', expected pure hex: %s`, j)
	}

	// "producer" must be a valid even-length hex string.
	prodVal := extractJSONStringValue(j, `"producer":"`)
	if len(prodVal)%2 != 0 {
		t.Errorf(`"producer" hex string has odd length %d`, len(prodVal))
	}
	if _, err := hex.DecodeString(prodVal); err != nil {
		t.Errorf(`"producer" is not valid hex: %q`, prodVal)
	}
}

// TestNodeRef_UnmarshalJSON_Rejects63Chars confirms NodeRef rejects a
// 63-char hex string (one char short of the required 64).
func TestNodeRef_UnmarshalJSON_Rejects63Chars(t *testing.T) {
	shortHex := strings.Repeat("a", 63)
	b, _ := json.Marshal(shortHex)
	var ref lineage.NodeRef
	if err := ref.UnmarshalJSON(b); err == nil {
		t.Fatal("expected error for 63-char hex, got nil")
	}
}

// TestNodeRef_UnmarshalJSON_Rejects64NonHex confirms NodeRef rejects a
// 64-char string that contains non-hex characters.
func TestNodeRef_UnmarshalJSON_RejectsNonHex64Chars(t *testing.T) {
	// Replace last two chars with 'zz' — valid length, invalid hex.
	nonHex := strings.Repeat("a", 62) + "zz"
	b, _ := json.Marshal(nonHex)
	var ref lineage.NodeRef
	if err := ref.UnmarshalJSON(b); err == nil {
		t.Fatal("expected error for non-hex 64-char string, got nil")
	}
}

// TestDAGNode_UnmarshalJSON_RejectsNonHexProducer confirms that
// DAGNode.UnmarshalJSON returns an error when "producer" is not
// valid hex (e.g. a base64-encoded value that contains non-hex chars).
func TestDAGNode_UnmarshalJSON_RejectsNonHexProducer(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("x"), nil, signer)

	// Marshal, then replace "producer":"<hex>" with an invalid value.
	wire, _ := json.Marshal(node)
	j := string(wire)

	prodVal := extractJSONStringValue(j, `"producer":"`)
	if prodVal == "" {
		t.Fatal("could not extract producer value from JSON")
	}
	// Replace with a value that has '!' chars — invalid hex.
	bad := strings.Repeat("!", len(prodVal))
	j = strings.Replace(j, `"producer":"`+prodVal+`"`, `"producer":"`+bad+`"`, 1)

	var got lineage.DAGNode
	if err := json.Unmarshal([]byte(j), &got); err == nil {
		t.Fatal("expected error for non-hex producer, got nil")
	}
}

// extractJSONStringValue is a test helper that extracts the string value
// following a given prefix in a flat JSON string (no nesting required).
// Returns "" if not found or if the closing quote is missing.
func extractJSONStringValue(j, prefix string) string {
	idx := strings.Index(j, prefix)
	if idx < 0 {
		return ""
	}
	rest := j[idx+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}
