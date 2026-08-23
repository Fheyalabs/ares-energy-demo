// SPDX-License-Identifier: Apache-2.0

package authclient

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func newTestIssuer() *Issuer {
	return NewIssuer("ares-test-v1", []byte("test-signing-key-32-bytes-long!!"))
}

func TestIssuer_RoundTrip(t *testing.T) {
	iss := newTestIssuer()
	blob, err := iss.Issue("acc-1", "invite")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := iss.Verify(blob)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.AccountID != "acc-1" {
		t.Errorf("AccountID = %q, want acc-1", claims.AccountID)
	}
	if claims.Provider != "invite" {
		t.Errorf("Provider = %q, want invite", claims.Provider)
	}
	if claims.Version != CredentialVersion {
		t.Errorf("Version = %d, want %d", claims.Version, CredentialVersion)
	}
}

func TestIssuer_DetectsTamperedSignature(t *testing.T) {
	iss := newTestIssuer()
	blob, _ := iss.Issue("acc-1", "invite")
	var env Envelope
	_ = json.Unmarshal(blob, &env)
	// Flip the last hex char deterministically so the tamper is
	// always observable (literal "00" would be a no-op ~1/256 of
	// the time when the real signature happened to end in "00").
	sig := env.Signature
	last := sig[len(sig)-1]
	flipped := byte('0')
	if last == '0' {
		flipped = 'f'
	}
	env.Signature = sig[:len(sig)-1] + string(flipped)
	tampered, _ := json.Marshal(env)
	_, err := iss.Verify(tampered)
	if !errors.Is(err, ErrCredentialSignature) {
		t.Errorf("Verify on tampered sig returned %v, want ErrCredentialSignature", err)
	}
}

func TestIssuer_DetectsTamperedClaims(t *testing.T) {
	iss := newTestIssuer()
	blob, _ := iss.Issue("acc-1", "invite")
	var env Envelope
	_ = json.Unmarshal(blob, &env)
	env.Claims.AccountID = "acc-2"
	tampered, _ := json.Marshal(env)
	_, err := iss.Verify(tampered)
	if !errors.Is(err, ErrCredentialSignature) {
		t.Errorf("Verify on tampered claims returned %v, want ErrCredentialSignature", err)
	}
}

func TestIssuer_RejectsExpired(t *testing.T) {
	iss := newTestIssuer()
	iss.TTL = 1 * time.Millisecond
	blob, _ := iss.Issue("acc-1", "invite")
	time.Sleep(20 * time.Millisecond)
	_, err := iss.Verify(blob)
	if !errors.Is(err, ErrCredentialExpired) {
		t.Errorf("Verify on expired credential returned %v, want ErrCredentialExpired", err)
	}
}

func TestIssuer_DifferentIssuersIncompatible(t *testing.T) {
	a := newTestIssuer()
	b := NewIssuer("ares-other-v1", a.SigningKey)
	blob, _ := a.Issue("acc-1", "invite")
	if _, err := b.Verify(blob); err == nil {
		t.Errorf("expected Verify to reject credential from a different issuer name")
	}
}

func TestIssuer_DifferentKeysIncompatible(t *testing.T) {
	a := NewIssuer("ares-test-v1", []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	b := NewIssuer("ares-test-v1", []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	blob, _ := a.Issue("acc-1", "invite")
	if _, err := b.Verify(blob); !errors.Is(err, ErrCredentialSignature) {
		t.Errorf("Verify with wrong key returned %v, want ErrCredentialSignature", err)
	}
}

func TestIssuer_MissingKeyFails(t *testing.T) {
	iss := NewIssuer("ares-test-v1", nil)
	if _, err := iss.Issue("acc", "invite"); !errors.Is(err, ErrMissingSigningKey) {
		t.Errorf("Issue with empty key returned %v, want ErrMissingSigningKey", err)
	}
}

func TestSigningKeyFromEnv_DevDefault(t *testing.T) {
	t.Setenv("ARES_CREDENTIAL_SIGNING_KEY", "")
	if k := SigningKeyFromEnv(false); len(k) == 0 {
		t.Errorf("dev default should be non-empty")
	}
	if k := SigningKeyFromEnv(true); k != nil {
		t.Errorf("production with no env should return nil")
	}
}

func TestSigningKeyFromEnv_HexDecode(t *testing.T) {
	t.Setenv("ARES_CREDENTIAL_SIGNING_KEY",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	k := SigningKeyFromEnv(true)
	if len(k) != 32 {
		t.Errorf("hex decode produced %d bytes, want 32", len(k))
	}
}
