// SPDX-License-Identifier: Apache-2.0

package transport

import "testing"

func TestAuthMiddleware_RoundTrip(t *testing.T) {
	m := &AuthMiddleware{Secret: []byte("test-secret-32-bytes-long-key-xx")}
	tok := m.GenerateToken("pseudo-A")
	if !m.ValidateToken("pseudo-A", tok) {
		t.Errorf("ValidateToken rejected its own GenerateToken output")
	}
}

func TestAuthMiddleware_RejectsWrongPseudonym(t *testing.T) {
	m := &AuthMiddleware{Secret: []byte("secret")}
	tok := m.GenerateToken("pseudo-A")
	if m.ValidateToken("pseudo-B", tok) {
		t.Errorf("token bound to A should not validate for B")
	}
}

func TestAuthMiddleware_RejectsWrongSecret(t *testing.T) {
	m1 := &AuthMiddleware{Secret: []byte("secret-1")}
	m2 := &AuthMiddleware{Secret: []byte("secret-2")}
	tok := m1.GenerateToken("p")
	if m2.ValidateToken("p", tok) {
		t.Errorf("token signed by one secret should not validate under another")
	}
}

func TestAuthMiddleware_EmptySecretBypass(t *testing.T) {
	m := &AuthMiddleware{Secret: nil, AllowDevBypass: true}
	if !m.ValidateToken("anyone", "anything") {
		t.Errorf("empty secret with AllowDevBypass=true should accept any token")
	}

	m.AllowDevBypass = false
	if m.ValidateToken("anyone", "anything") {
		t.Errorf("empty secret with AllowDevBypass=false should reject all tokens")
	}
}
