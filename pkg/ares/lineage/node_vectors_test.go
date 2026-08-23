// SPDX-License-Identifier: Apache-2.0

// Package lineage_test — cross-language golden parity vectors.
//
// node_vectors_test.go loads testdata/node_vectors.json and replays each
// vector through the Go lineage/sign API. The test serves two purposes:
//
//  1. Freeze the wire contract: the expected.* values in the JSON are the
//     authoritative reference for Python and Swift client test suites.  If
//     the Go implementation changes any of these values the test fails,
//     which is the intended signal.
//
//  2. Guard against silent drift: a future refactor that accidentally
//     changes the hash or signing-message layout will be caught here before
//     it propagates to consumers.
//
// Contract anchor: the slot-submission node
//   session="golden-session-1", phase="anon-g-verify", role="slot-submission"
//   payload = {"slot_index":2,"slot_dk_pub":"aa...aa"} (32-byte 0xAA pubkey)
//   seed    = 0x00 0x01 … 0x1f
//
// Python/Swift implementors: reproduce every expected.* field from the
// declared input.* fields to confirm wire-format parity.

package lineage_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// vectorFile holds one entry from node_vectors.json.
type vectorFile struct {
	Name  string       `json:"name"`
	Input vectorInput  `json:"input"`
	Want  vectorExpect `json:"expected"`
}

type vectorInput struct {
	SeedHex    string   `json:"ed25519_seed_hex"`
	SessionID  string   `json:"session_id"`
	PhaseID    string   `json:"phase_id"`
	Role       string   `json:"role"`
	PayloadHex string   `json:"payload_hex"`
	ParentsHex []string `json:"parents_hex"`
}

type vectorExpect struct {
	ProducerHex    string `json:"producer_hex"`
	PayloadHashHex string `json:"payload_hash_hex"`
	NodeHashHex    string `json:"node_hash_hex"`
	SigningMsgHex  string `json:"signing_msg_hex"`
	SignatureHex   string `json:"signature_hex"`
	Algorithm      string `json:"algorithm"`
}

// TestNodeVectors loads the frozen parity fixtures and confirms the Go
// implementation reproduces every expected.* field exactly.  It also runs a
// positive Verify round-trip and a negative payload-tamper check per vector.
func TestNodeVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "node_vectors.json"))
	if err != nil {
		t.Fatalf("read testdata/node_vectors.json: %v", err)
	}

	var vectors []vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse node_vectors.json: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("node_vectors.json is empty")
	}

	for _, v := range vectors {
		v := v // capture
		t.Run(v.Name, func(t *testing.T) {
			// ---- decode seed & build signer ----
			seedBytes, err := hex.DecodeString(v.Input.SeedHex)
			if err != nil {
				t.Fatalf("decode seed: %v", err)
			}
			if len(seedBytes) != ed25519.SeedSize {
				t.Fatalf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seedBytes))
			}
			priv := ed25519.NewKeyFromSeed(seedBytes)
			signer := sign.NewEd25519SignerFromKey(priv)

			// ---- decode payload ----
			payload, err := hex.DecodeString(v.Input.PayloadHex)
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}

			// ---- decode parents and sort (mirrors DeriveNodeHash contract) ----
			parents := make([]lineage.NodeRef, len(v.Input.ParentsHex))
			for i, ph := range v.Input.ParentsHex {
				b, err := hex.DecodeString(ph)
				if err != nil {
					t.Fatalf("decode parent[%d]: %v", i, err)
				}
				if len(b) != 32 {
					t.Fatalf("parent[%d]: expected 32 bytes, got %d", i, len(b))
				}
				copy(parents[i][:], b)
			}
			sortedParents := sortNodeRefs(parents)

			// ---- recompute each field ----
			payloadHash := lineage.HashPayload(payload)
			nodeHash := lineage.DeriveNodeHash(
				v.Input.SessionID, v.Input.PhaseID, v.Input.Role,
				payload, sortedParents,
			)
			signingMsg := lineage.SigningMessage(nodeHash, v.Input.SessionID, v.Input.PhaseID, v.Input.Role)
			sig, err := signer.Sign(signingMsg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			producer := signer.PublicKey()

			// ---- assert each expected field ----
			assertHex(t, "producer",     producer,        v.Want.ProducerHex)
			assertHex(t, "payload_hash", payloadHash[:],  v.Want.PayloadHashHex)
			assertHex(t, "node_hash",    nodeHash[:],     v.Want.NodeHashHex)
			assertHex(t, "signing_msg",  signingMsg,      v.Want.SigningMsgHex)
			assertHex(t, "signature",    sig,             v.Want.SignatureHex)

			if got := signer.Algorithm(); got != v.Want.Algorithm {
				t.Errorf("algorithm: got %q, want %q", got, v.Want.Algorithm)
			}

			// ---- positive Verify round-trip ----
			// Build the node using the standard constructor; then Verify with the
			// same signer as verifier.
			node := lineage.NewDAGNode(
				v.Input.SessionID, v.Input.PhaseID, v.Input.Role,
				payload,
				sortedParents, nil, // no parentRoles needed for Verify
				producer, sig,
				signer.Algorithm(),
			)
			verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
			if err := lineage.Verify(node, payload, verifiers); err != nil {
				t.Errorf("Verify positive: unexpected error: %v", err)
			}

			// ---- negative: tampered payload must produce MismatchError{Field:"PayloadHash"} ----
			tampered := make([]byte, len(payload))
			copy(tampered, payload)
			tampered[0] ^= 0x01
			err = lineage.Verify(node, tampered, verifiers)
			var me *lineage.MismatchError
			if !errors.As(err, &me) {
				t.Fatalf("tampered payload: expected *MismatchError, got %T: %v", err, err)
			}
			if me.Field != "PayloadHash" {
				t.Errorf("tampered payload MismatchError.Field = %q, want %q", me.Field, "PayloadHash")
			}
		})
	}
}

// assertHex is a test helper that compares a byte slice against its expected
// lowercase hex representation.
func assertHex(t *testing.T, field string, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("%s: invalid expected hex %q: %v", field, wantHex, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch:\n  got  %s\n  want %s",
			field, hex.EncodeToString(got), wantHex)
	}
}

// sortNodeRefs returns a lex-sorted copy of the input slice.
// Mirrors the sort order used internally by NewDAGNode / DeriveNodeHash.
func sortNodeRefs(refs []lineage.NodeRef) []lineage.NodeRef {
	out := make([]lineage.NodeRef, len(refs))
	copy(out, refs)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(out[j-1][:], out[j][:]) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
