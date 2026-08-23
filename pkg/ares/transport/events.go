// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"sync"
	"time"
)

// SessionEvent is one dispatch event recorded per session.
type SessionEvent struct {
	Time      time.Time `json:"time"`
	SessionID string    `json:"session_id"`
	Type      string    `json:"type"`
	From      string    `json:"from"`
	Error     string    `json:"error,omitempty"`
}

// SessionEventRing stores at most N events per session, dropping the
// oldest when the ring fills.
type SessionEventRing struct {
	mu   sync.Mutex
	cap  int
	ring map[string][]SessionEvent // session_id → events
}

// NewSessionEventRing creates a ring with the given per-session
// capacity. cap=0 disables recording; cap<0 means unlimited.
func NewSessionEventRing(cap int) *SessionEventRing {
	if cap <= 0 {
		cap = 128
	}
	return &SessionEventRing{
		cap:  cap,
		ring: make(map[string][]SessionEvent),
	}
}

// Record appends an event for the given session. If the ring is full,
// the oldest event is dropped.
func (r *SessionEventRing) Record(sessionID, msgType, from, errStr string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ev := SessionEvent{
		Time:      time.Now().UTC(),
		SessionID: sessionID,
		Type:      msgType,
		From:      from,
	}
	if errStr != "" {
		ev.Error = errStr
	}

	events := r.ring[sessionID]
	if len(events) >= r.cap && r.cap > 0 {
		events = events[1:] // drop oldest
	}
	events = append(events, ev)
	r.ring[sessionID] = events
}

// Events returns the recorded events for sessionID.
func (r *SessionEventRing) Events(sessionID string) []SessionEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	events := r.ring[sessionID]
	if events == nil {
		return nil
	}
	out := make([]SessionEvent, len(events))
	copy(out, events)
	return out
}

// Prune removes events for sessions no longer tracked by the runner.
// Call periodically to bound memory.
func (r *SessionEventRing) Prune(activeSessionIDs map[string]bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.ring {
		if !activeSessionIDs[id] {
			delete(r.ring, id)
		}
	}
}
