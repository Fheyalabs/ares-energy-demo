// SPDX-License-Identifier: Apache-2.0

// Package authclient implements the credential-issuance and verification
// primitives an ARES auth-service needs.
//
// A credential is a JSON envelope of claims plus an HMAC signature over
// those claims, returned to the participant on registration. The
// participant later presents the credential to the session-service,
// which verifies the signature and the expiration window before issuing
// a per-session pseudonym + WS auth token.
//
// The scheme is intentionally simple: HMAC-SHA256 over a canonical
// concatenation of claim fields, hex-encoded. It mirrors the wire format
// of a credential-issuance + WS-token derivation flow any ARES app can adopt; the same Python client works
// against either.
package authclient

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// CredentialVersion is bumped on incompatible wire-format changes.
const CredentialVersion = 1

// Errors returned by Verify.
var (
	ErrCredentialExpired   = errors.New("credential expired")
	ErrCredentialSignature = errors.New("credential signature mismatch")
	ErrMissingSigningKey   = errors.New("missing credential signing key")
)

// Claims is the body of a credential. Provider is a free-form tag
// (typically the credential type — "invite", "anonymous", "test").
type Claims struct {
	Version     int    `json:"version"`
	Issuer      string `json:"issuer"`
	AccountID   string `json:"account_id,omitempty"`
	SubjectHash string `json:"subject_hash"`
	Provider    string `json:"provider"`
	TokenHash   string `json:"token_hash"`
	Nonce       string `json:"nonce"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
}

// Envelope is the on-the-wire shape: Claims + Signature.
type Envelope struct {
	Claims    Claims `json:"claims"`
	Signature string `json:"signature"`
}

// Issuer signs credentials. Construct with NewIssuer.
type Issuer struct {
	Issuer     string // identifier baked into Claims.Issuer (e.g. "ares-auction-v1")
	SigningKey []byte
	Now        func() time.Time
	TTL        time.Duration
}

// NewIssuer returns an Issuer with default TTL (30 days). Caller must
// supply a non-empty signingKey; Issuer string identifies the deployment
// (changing it invalidates all outstanding credentials).
func NewIssuer(issuerName string, signingKey []byte) *Issuer {
	return &Issuer{
		Issuer:     issuerName,
		SigningKey: append([]byte(nil), signingKey...),
		Now:        time.Now,
		TTL:        30 * 24 * time.Hour,
	}
}

// SigningKeyFromEnv reads ARES_CREDENTIAL_SIGNING_KEY. Accepts a hex
// string (length >= 64 = 32 bytes) or any raw string. Returns a default
// dev key when production is false and the env var is unset; returns
// nil in production with no env var so callers can fail fast.
func SigningKeyFromEnv(production bool) []byte {
	if raw := os.Getenv("ARES_CREDENTIAL_SIGNING_KEY"); raw != "" {
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) >= 32 {
			return decoded
		}
		return []byte(raw)
	}
	if production {
		return nil
	}
	return []byte("ares-dev-credential-signing-key-do-not-use")
}

// Issue mints a credential for accountID with the given provider tag.
// The TokenHash field is set to a hash of accountID+provider (callers
// that need provider-supplied token hashes — e.g. Apple/Google sign-in —
// should use the lower-level IssueWithTokenHash.
func (s *Issuer) Issue(accountID, provider string) ([]byte, error) {
	return s.IssueWithTokenHash(accountID, provider, hashString(accountID+"|"+provider))
}

// IssueWithTokenHash mints a credential, allowing the caller to supply
// the TokenHash directly. Useful when the provider returns its own
// opaque subject identifier.
func (s *Issuer) IssueWithTokenHash(accountID, provider, tokenHash string) ([]byte, error) {
	if len(s.SigningKey) == 0 {
		return nil, ErrMissingSigningKey
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	now := s.now()
	ttl := s.TTL
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	claims := Claims{
		Version:     CredentialVersion,
		Issuer:      s.Issuer,
		AccountID:   accountID,
		SubjectHash: hashString(s.Issuer + "|" + provider + "|" + accountID + "|" + nonce),
		Provider:    provider,
		TokenHash:   tokenHash,
		Nonce:       nonce,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(ttl).Unix(),
	}
	env := Envelope{
		Claims:    claims,
		Signature: sign(s.SigningKey, claims),
	}
	return json.Marshal(env)
}

// Verify checks the signature and expiration of a credential blob.
// Returns the parsed Claims on success.
func (s *Issuer) Verify(blob []byte) (*Claims, error) {
	if len(s.SigningKey) == 0 {
		return nil, ErrMissingSigningKey
	}
	var env Envelope
	decoded := blob
	if maybe, err := base64.StdEncoding.DecodeString(string(blob)); err == nil && json.Valid(maybe) {
		decoded = maybe
	}
	if err := json.Unmarshal(decoded, &env); err != nil {
		return nil, fmt.Errorf("decode credential: %w", err)
	}
	expected := sign(s.SigningKey, env.Claims)
	if !hmac.Equal([]byte(expected), []byte(env.Signature)) {
		return nil, ErrCredentialSignature
	}
	if env.Claims.ExpiresAt <= s.now().Unix() {
		return nil, ErrCredentialExpired
	}
	if env.Claims.Version != CredentialVersion {
		return nil, fmt.Errorf("unsupported credential version %d", env.Claims.Version)
	}
	if env.Claims.Issuer != s.Issuer {
		return nil, fmt.Errorf("unexpected issuer %q (want %q)", env.Claims.Issuer, s.Issuer)
	}
	return &env.Claims, nil
}

func (s *Issuer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func sign(key []byte, claims Claims) string {
	mac := hmac.New(sha256.New, key)
	for _, part := range canonical(claims) {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func canonical(claims Claims) []string {
	parts := []string{
		fmt.Sprintf("account_id=%s", claims.AccountID),
		fmt.Sprintf("expires_at=%d", claims.ExpiresAt),
		fmt.Sprintf("issued_at=%d", claims.IssuedAt),
		fmt.Sprintf("issuer=%s", claims.Issuer),
		fmt.Sprintf("nonce=%s", claims.Nonce),
		fmt.Sprintf("provider=%s", claims.Provider),
		fmt.Sprintf("subject_hash=%s", claims.SubjectHash),
		fmt.Sprintf("token_hash=%s", claims.TokenHash),
		fmt.Sprintf("version=%d", claims.Version),
	}
	sort.Strings(parts)
	return parts
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
