// SPDX-License-Identifier: Apache-2.0

package onion_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/onion"
)

func TestECIES_RoundTrip(t *testing.T) {
	priv, pub, err := onion.GenerateSlotKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := []byte("winner-package-bytes")
	env, err := onion.ECIESEncrypt(pub, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(env) < 32+12+16 {
		t.Fatalf("envelope too short: %d", len(env))
	}
	got, err := onion.ECIESDecrypt(priv, env)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, msg)
	}
}

func TestECIES_WrongKeyFails(t *testing.T) {
	_, pub, _ := onion.GenerateSlotKey()
	otherPriv, _, _ := onion.GenerateSlotKey()
	env, _ := onion.ECIESEncrypt(pub, []byte("secret"))
	if _, err := onion.ECIESDecrypt(otherPriv, env); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}
}

// Cross-language parity: decrypt an envelope produced by an independent
// Python reference for a fixed recipient key. Regenerate via the
// self-contained snippet in the plan if the wire format ever changes.
func TestECIES_PythonParityVector(t *testing.T) {
	recipPrivHex := "d08907b3fee6522e958524d0161270c9487bac1739aa4bf350f6dfb3b371b265"
	envHex := "7717a9c5088369046cf0e767020ad765f0f3f3537c4d1592b91eb174110959099e200abc556a2de80017314525375fb4e2edcb651d35e89cba92072a7f073fb8cbbb7e5a6ecdd0fa037cc6e99d539335"
	wantPlain := "parity-check-payload"

	recipPriv, _ := hex.DecodeString(recipPrivHex)
	env, _ := hex.DecodeString(envHex)
	got, err := onion.ECIESDecrypt(recipPriv, env)
	if err != nil {
		t.Fatalf("decrypt python vector: %v", err)
	}
	if string(got) != wantPlain {
		t.Fatalf("parity mismatch: got %q want %q", got, wantPlain)
	}
}
