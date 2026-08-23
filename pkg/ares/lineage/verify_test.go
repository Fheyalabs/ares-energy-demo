// SPDX-License-Identifier: Apache-2.0

package lineage_test

import (
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestVerify_HappyPath(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	payload := []byte("good payload")
	node, _ := lineage.Commit("s", "p", "r", payload, nil, signer)
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	if err := lineage.Verify(node, payload, verifiers); err != nil {
		t.Errorf("Verify happy path failed: %v", err)
	}
}

func TestVerify_PayloadHashMismatch(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("original"), nil, signer)
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	err := lineage.Verify(node, []byte("tampered"), verifiers)
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "PayloadHash" {
		t.Errorf("Field = %q, want %q", me.Field, "PayloadHash")
	}
}

func TestVerify_SignatureMismatch(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	wrongSigner, _ := sign.NewEd25519Signer()
	payload := []byte("payload")
	node, _ := lineage.Commit("s", "p", "r", payload, nil, signer)
	// Tamper: swap producer pubkey to a different signer's pubkey;
	// the signature no longer verifies under it.
	node.Producer = wrongSigner.PublicKey()
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: wrongSigner}
	err := lineage.Verify(node, payload, verifiers)
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "Signature" {
		t.Errorf("Field = %q, want %q", me.Field, "Signature")
	}
}

func TestVerify_AlgorithmUnsupported(t *testing.T) {
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("x"), nil, signer)
	// Verifier map has no ed25519 entry; algorithm "ed25519" is
	// unsupported by this verifier set.
	verifiers := map[string]sign.Signer{"some-other-alg": signer}
	err := lineage.Verify(node, []byte("x"), verifiers)
	var me *lineage.MismatchError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MismatchError, got %T: %v", err, err)
	}
	if me.Field != "Algorithm" {
		t.Errorf("Field = %q, want %q", me.Field, "Algorithm")
	}
}

func TestVerify_HashMismatchDetected(t *testing.T) {
	// Construct a node whose Hash is manually corrupted. Verify
	// must catch the inconsistency between Hash and the canonical
	// derivation.
	signer, _ := sign.NewEd25519Signer()
	node, _ := lineage.Commit("s", "p", "r", []byte("payload"), nil, signer)
	node.Hash[0] ^= 0xff
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
	err := lineage.Verify(node, []byte("payload"), verifiers)
	if err == nil {
		t.Fatal("expected verification failure on corrupted Hash")
	}
}
