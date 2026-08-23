// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// DefaultMaxArtifactSize caps PUT /v2/artifacts/{key} body bytes when the
// AdminHandlers is constructed without an explicit limit. 64 MiB
// accommodates large CKKS bundles (collective public keys, eval-key
// rounds, fused scoring artifacts) while preventing a single request
// from filling server memory.
const DefaultMaxArtifactSize int64 = 64 << 20

// AdminHandlers exposes the HTTP admin surface:
//
//	GET  /admin/health             — liveness probe
//	GET  /admin/stats              — connected count, sessions started
//	POST /admin/sessions           — start a session (SessionTrigger.Start)
//	GET  /admin/sessions/{id}      — current state of a session
//	PUT  /v2/artifacts/{key}       — upload an artifact
//	GET  /v2/artifacts/{key}       — download an artifact
//
// All admin endpoints are auth-bypassed in dev mode; production
// deployments should sit them behind a reverse proxy that enforces
// access control.
type AdminHandlers struct {
	ServiceName string
	Hub         *Hub
	Runner      *phase.SessionRunner
	Trigger     SessionTrigger
	Artifacts   *ArtifactStore
	EventRing   *SessionEventRing

	// MaxArtifactSize caps PUT /v2/artifacts/{key} body bytes. Zero
	// means DefaultMaxArtifactSize. Negative disables the cap (not
	// recommended outside tests).
	MaxArtifactSize int64
}

// RegisterRoutes mounts the admin endpoints on mux.
func (a *AdminHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/health", a.handleHealth)
	mux.HandleFunc("GET /admin/stats", a.handleStats)
	mux.HandleFunc("POST /admin/sessions", a.handleSessionStart)
	mux.HandleFunc("GET /admin/sessions/{id}", a.handleSessionGet)
	mux.HandleFunc("GET /admin/sessions/{id}/results", a.handleSessionResults)
	mux.HandleFunc("GET /admin/sessions/{id}/events", a.handleSessionEvents)
	mux.HandleFunc("PUT /v2/artifacts/{key}", a.handleArtifactPut)
	mux.HandleFunc("GET /v2/artifacts/{key}", a.handleArtifactGet)
}

func (a *AdminHandlers) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": a.ServiceName,
	})
}

type statsResponse struct {
	Service         string `json:"service"`
	ConnectedClients int   `json:"connected_clients"`
}

func (a *AdminHandlers) handleStats(w http.ResponseWriter, r *http.Request) {
	connected := 0
	if a.Hub != nil {
		connected = a.Hub.ConnectedCount()
	}
	writeJSON(w, http.StatusOK, statsResponse{
		Service:          a.ServiceName,
		ConnectedClients: connected,
	})
}

type sessionStartRequest struct {
	SessionID    string         `json:"session_id"`
	Participants []string       `json:"participants"`
	Attrs        map[string]any `json:"attrs,omitempty"`
}

type sessionStartResponse struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
}

func (a *AdminHandlers) handleSessionStart(w http.ResponseWriter, r *http.Request) {
	if a.Trigger == nil {
		http.Error(w, "no SessionTrigger configured", http.StatusServiceUnavailable)
		return
	}
	var req sessionStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}
	if err := a.Trigger.Start(req.SessionID, req.Participants, req.Attrs); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	state, _ := a.Runner.CurrentState(req.SessionID)
	writeJSON(w, http.StatusCreated, sessionStartResponse{
		SessionID: req.SessionID,
		State:     string(state),
	})
}

func (a *AdminHandlers) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	state, ok := a.Runner.CurrentState(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sessionStartResponse{
		SessionID: id,
		State:     string(state),
	})
}

// handleSessionResults exports named session-context entries for the
// given session. Query param `keys` is a comma-separated list of
// context key names. Values are hex-encoded for []byte, JSON-encoded
// for map[string]any, and string-form for scalars. Keys absent from
// the context are silently omitted from the response.
func (a *AdminHandlers) handleSessionResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := a.Runner.CurrentState(id); !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	keys := strings.Split(r.URL.Query().Get("keys"), ",")
	if len(keys) == 0 || (len(keys) == 1 && keys[0] == "") {
		http.Error(w, "?keys= is required (comma-separated context key names)", http.StatusBadRequest)
		return
	}
	results := a.Runner.SessionContextKeys(id, keys)
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": id,
		"results":    results,
	})
}

func (a *AdminHandlers) handleSessionEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := a.Runner.CurrentState(id); !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	events := a.EventRing.Events(id)
	if events == nil {
		events = make([]SessionEvent, 0)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": id,
		"events":     events,
	})
}

func (a *AdminHandlers) handleArtifactPut(w http.ResponseWriter, r *http.Request) {
	if a.Artifacts == nil {
		http.Error(w, "no artifact store configured", http.StatusServiceUnavailable)
		return
	}
	key := r.PathValue("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	limit := a.MaxArtifactSize
	if limit == 0 {
		limit = DefaultMaxArtifactSize
	}
	body := r.Body
	if limit > 0 {
		body = http.MaxBytesReader(w, r.Body, limit)
	}
	buf, err := io.ReadAll(body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "artifact exceeds size limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	a.Artifacts.Put(key, buf)
	w.WriteHeader(http.StatusNoContent)
}

func (a *AdminHandlers) handleArtifactGet(w http.ResponseWriter, r *http.Request) {
	if a.Artifacts == nil {
		http.Error(w, "no artifact store configured", http.StatusServiceUnavailable)
		return
	}
	key := r.PathValue("key")
	data, ok := a.Artifacts.Get(key)
	if !ok {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
