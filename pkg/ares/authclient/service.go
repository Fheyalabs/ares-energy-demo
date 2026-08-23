// SPDX-License-Identifier: Apache-2.0

package authclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Service is an HTTP authentication service. It issues credentials,
// verifies them, and derives the per-session WS auth token a participant
// presents to the session-service.
//
// Routes:
//
//	POST /auth/issue                  — issue a credential for an account
//	POST /auth/verify                 — verify a credential, return claims
//	POST /auth/ws-token               — derive WS auth token for a pseudonym
//
// The wire token is HMAC-SHA256(wsSecret, pseudonym) hex-encoded, matching
// transport.AuthMiddleware so the session-service can validate without
// calling back to the auth-service.
type Service struct {
	Issuer   *Issuer
	WSSecret []byte
}

// NewService returns an HTTP auth service.
func NewService(issuer *Issuer, wsSecret []byte) *Service {
	return &Service{
		Issuer:   issuer,
		WSSecret: append([]byte(nil), wsSecret...),
	}
}

// RegisterRoutes mounts /auth/* on mux.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/issue", s.handleIssue)
	mux.HandleFunc("POST /auth/verify", s.handleVerify)
	mux.HandleFunc("POST /auth/ws-token", s.handleWSToken)
	mux.HandleFunc("GET /admin/health", s.handleHealth)
}

type issueRequest struct {
	AccountID string `json:"account_id"`
	Provider  string `json:"provider"`
}

type issueResponse struct {
	Credential string `json:"credential"`
}

func (s *Service) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.AccountID == "" {
		http.Error(w, "account_id is required", http.StatusBadRequest)
		return
	}
	if req.Provider == "" {
		req.Provider = "anonymous"
	}
	blob, err := s.Issuer.Issue(req.AccountID, req.Provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, issueResponse{Credential: string(blob)})
}

type verifyRequest struct {
	Credential string `json:"credential"`
}

type verifyResponse struct {
	Valid  bool    `json:"valid"`
	Claims *Claims `json:"claims,omitempty"`
	Error  string  `json:"error,omitempty"`
}

func (s *Service) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	claims, err := s.Issuer.Verify([]byte(req.Credential))
	if err != nil {
		writeJSON(w, http.StatusOK, verifyResponse{Valid: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: true, Claims: claims})
}

type wsTokenRequest struct {
	Pseudonym  string `json:"pseudonym"`
	Credential string `json:"credential"`
}

type wsTokenResponse struct {
	Pseudonym string `json:"pseudonym"`
	Token     string `json:"token"`
}

// handleWSToken: caller presents a valid credential + a chosen
// pseudonym; service returns the WS token (HMAC over pseudonym). The
// pseudonym is opaque to the auth service — the participant picks it.
func (s *Service) handleWSToken(w http.ResponseWriter, r *http.Request) {
	var req wsTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Pseudonym == "" {
		http.Error(w, "pseudonym is required", http.StatusBadRequest)
		return
	}
	if _, err := s.Issuer.Verify([]byte(req.Credential)); err != nil {
		http.Error(w, "invalid credential: "+err.Error(), http.StatusUnauthorized)
		return
	}
	token := wsTokenFor(s.WSSecret, req.Pseudonym)
	writeJSON(w, http.StatusOK, wsTokenResponse{
		Pseudonym: req.Pseudonym,
		Token:     token,
	})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "auth-service",
	})
}

// wsTokenFor is exported indirectly so tests can build expected values.
func wsTokenFor(secret []byte, pseudonym string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(pseudonym))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveWSToken returns the WS token that wsTokenFor would mint for the
// given pseudonym. Useful for clients that want to skip the HTTP
// round-trip when they already have the WS secret.
func DeriveWSToken(wsSecret []byte, pseudonym string) string {
	return wsTokenFor(wsSecret, pseudonym)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
