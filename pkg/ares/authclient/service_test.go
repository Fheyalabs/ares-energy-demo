// SPDX-License-Identifier: Apache-2.0

package authclient

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestService() (*Service, *httptest.Server) {
	iss := NewIssuer("ares-test-v1", []byte("test-signing-key-32-bytes-long!!"))
	svc := NewService(iss, []byte("ws-secret-also-32-bytes-long!!ab"))
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux)
	return svc, httptest.NewServer(mux)
}

func post(t *testing.T, srv *httptest.Server, path string, body any) *http.Response {
	t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func TestService_IssueVerifyRoundTrip(t *testing.T) {
	_, srv := newTestService()
	defer srv.Close()

	resp := post(t, srv, "/auth/issue", issueRequest{
		AccountID: "user-1",
		Provider:  "invite",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issue status = %d", resp.StatusCode)
	}
	var ir issueResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		t.Fatalf("decode issue: %v", err)
	}
	if ir.Credential == "" {
		t.Fatalf("empty credential")
	}

	vresp := post(t, srv, "/auth/verify", verifyRequest{Credential: ir.Credential})
	defer vresp.Body.Close()
	var vr verifyResponse
	_ = json.NewDecoder(vresp.Body).Decode(&vr)
	if !vr.Valid {
		t.Errorf("Verify reported invalid: %s", vr.Error)
	}
	if vr.Claims == nil || vr.Claims.AccountID != "user-1" {
		t.Errorf("Verify claims = %+v", vr.Claims)
	}
}

func TestService_IssueRequiresAccountID(t *testing.T) {
	_, srv := newTestService()
	defer srv.Close()
	resp := post(t, srv, "/auth/issue", issueRequest{Provider: "invite"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestService_VerifyRejectsTampered(t *testing.T) {
	_, srv := newTestService()
	defer srv.Close()
	resp := post(t, srv, "/auth/verify", verifyRequest{
		Credential: `{"claims":{"version":1,"issuer":"ares-test-v1","account_id":"u","subject_hash":"x","provider":"invite","token_hash":"x","nonce":"n","issued_at":1,"expires_at":9999999999},"signature":"deadbeef"}`,
	})
	defer resp.Body.Close()
	var vr verifyResponse
	_ = json.NewDecoder(resp.Body).Decode(&vr)
	if vr.Valid {
		t.Errorf("Verify should reject obviously-bad signature")
	}
}

func TestService_WSTokenDerivation(t *testing.T) {
	svc, srv := newTestService()
	defer srv.Close()

	// Issue a real credential to use.
	resp := post(t, srv, "/auth/issue", issueRequest{AccountID: "u", Provider: "invite"})
	var ir issueResponse
	_ = json.NewDecoder(resp.Body).Decode(&ir)
	resp.Body.Close()

	tokResp := post(t, srv, "/auth/ws-token", wsTokenRequest{
		Pseudonym:  "ps-alpha",
		Credential: ir.Credential,
	})
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", tokResp.StatusCode)
	}
	var tr wsTokenResponse
	_ = json.NewDecoder(tokResp.Body).Decode(&tr)

	want := DeriveWSToken(svc.WSSecret, "ps-alpha")
	if tr.Token != want {
		t.Errorf("server token != DeriveWSToken; %q vs %q", tr.Token, want)
	}
}

func TestService_WSTokenRejectsBadCredential(t *testing.T) {
	_, srv := newTestService()
	defer srv.Close()
	resp := post(t, srv, "/auth/ws-token", wsTokenRequest{
		Pseudonym:  "ps",
		Credential: "not-a-real-credential",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestService_Health(t *testing.T) {
	_, srv := newTestService()
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/admin/health")
	if err != nil {
		t.Fatalf("GET health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	body, _ := io_readall(resp)
	if !strings.Contains(body, "ok") {
		t.Errorf("body = %q", body)
	}
}

func io_readall(resp *http.Response) (string, error) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf), nil
}
