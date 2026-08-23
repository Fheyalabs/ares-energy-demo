// SPDX-License-Identifier: Apache-2.0

package sign_test

import (
	"bytes"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

func TestEd25519Signer_RoundTrip(t *testing.T) {
	s, err := sign.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	msg := []byte("hello ares")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(s.PublicKey(), msg, sig); err != nil {
		t.Fatalf("Verify round-trip failed: %v", err)
	}
}

func TestEd25519Signer_TamperedMessageFails(t *testing.T) {
	s, _ := sign.NewEd25519Signer()
	sig, _ := s.Sign([]byte("hello"))
	if err := s.Verify(s.PublicKey(), []byte("hallo"), sig); err == nil {
		t.Fatal("expected verify to fail on tampered message")
	}
}

func TestEd25519Signer_WrongPubkeyFails(t *testing.T) {
	s1, _ := sign.NewEd25519Signer()
	s2, _ := sign.NewEd25519Signer()
	sig, _ := s1.Sign([]byte("hello"))
	if err := s1.Verify(s2.PublicKey(), []byte("hello"), sig); err == nil {
		t.Fatal("expected verify to fail with wrong pubkey")
	}
}

func TestEd25519Signer_MalformedSignatureFails(t *testing.T) {
	s, _ := sign.NewEd25519Signer()
	if err := s.Verify(s.PublicKey(), []byte("hello"), []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected verify to fail on malformed signature")
	}
}

func TestEd25519Signer_MalformedPubkeyFails(t *testing.T) {
	s, _ := sign.NewEd25519Signer()
	sig, _ := s.Sign([]byte("hello"))
	if err := s.Verify([]byte{0x01, 0x02}, []byte("hello"), sig); err == nil {
		t.Fatal("expected verify to fail on malformed pubkey")
	}
}

func TestEd25519Signer_AlgorithmIsStable(t *testing.T) {
	s1, _ := sign.NewEd25519Signer()
	s2, _ := sign.NewEd25519Signer()
	if got := s1.Algorithm(); got != "ed25519" {
		t.Errorf("Algorithm() = %q, want %q", got, "ed25519")
	}
	if s1.Algorithm() != s2.Algorithm() {
		t.Error("Algorithm() inconsistent across instances")
	}
}

func TestEd25519Signer_PublicKeyIsCopy(t *testing.T) {
	// Mutating a returned PublicKey must not change subsequent calls.
	s, _ := sign.NewEd25519Signer()
	pk1 := s.PublicKey()
	pk1[0] ^= 0xff
	pk2 := s.PublicKey()
	if bytes.Equal(pk1, pk2) {
		t.Fatal("PublicKey() returned mutable shared slice")
	}
}

func TestEd25519Signer_ConcurrentSignVerify(t *testing.T) {
	// Signer is used concurrently by the runner's auto-wrap dispatch
	// across many in-flight messages. Confirm Sign + Verify are
	// goroutine-safe (they call ed25519 stdlib funcs that are
	// re-entrant; this test guards against future regressions).
	s, _ := sign.NewEd25519Signer()
	pk := s.PublicKey()
	msg := []byte("concurrent")
	const N = 64
	done := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			sig, err := s.Sign(msg)
			if err != nil {
				done <- err
				return
			}
			done <- s.Verify(pk, msg, sig)
		}()
	}
	for i := 0; i < N; i++ {
		if err := <-done; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}
