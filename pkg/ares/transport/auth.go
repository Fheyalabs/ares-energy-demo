// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// AuthMiddleware validates the per-connection WebSocket auth token.
//
// The token is HMAC-SHA256(secret, pseudonym) hex-encoded. The same scheme
// is used by the existing ARES Python client and by the Fheya auth service,
// so example apps can reuse either side of the existing wire.
//
// When Secret is empty, AllowDevBypass controls whether any token is
// accepted. Production deployments must set a non-empty Secret.
type AuthMiddleware struct {
	Secret         []byte
	AllowDevBypass bool
}

// ValidateToken returns true if the supplied token matches the expected
// HMAC over the pseudonym.
func (m *AuthMiddleware) ValidateToken(pseudonym, token string) bool {
	if len(m.Secret) == 0 {
		return m.AllowDevBypass
	}
	mac := hmac.New(sha256.New, m.Secret)
	mac.Write([]byte(pseudonym))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(token))
}

// GenerateToken returns the canonical token for the given pseudonym. Used
// by the auth-service (and by tests that need to forge a valid token).
func (m *AuthMiddleware) GenerateToken(pseudonym string) string {
	mac := hmac.New(sha256.New, m.Secret)
	mac.Write([]byte(pseudonym))
	return hex.EncodeToString(mac.Sum(nil))
}
