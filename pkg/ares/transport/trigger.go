// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"sync"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// SessionTrigger decides when a SessionRunner should call BeginSession
// for a given set of participants.
//
// Different applications need different triggers:
//   - a matchmaking trigger watches cohort fill across a city and triggers
//     when N compatible participants are queued.
//   - The sealed-bid auction triggers when the auctioneer pushes a
//     "start auction" button (admin POST).
//   - The recurring-cohort ranker triggers on a weekly cron.
//   - Smoke tests trigger via a simple admin POST that names the
//     session_id and the participants directly.
//
// The transport package ships ManualAdminTrigger (the smoke/admin case)
// as a sensible default. Applications that need richer triggering
// implement the interface themselves and supply their implementation
// when constructing the Service.
type SessionTrigger interface {
	// Start begins a new session with the given session_id and
	// participant pseudonyms. Implementations typically call
	// runner.BeginSession, seed any per-session context, and broadcast
	// an invitation message via the Hub. Returns an error if the
	// session cannot be started (duplicate id, runner refuses, etc).
	Start(sessionID string, participants []string, attrs map[string]any) error
}

// ManualAdminTrigger is the simplest possible trigger: it calls
// runner.BeginSession and broadcasts an "invite" message to each
// participant. Suitable for the example apps' admin-driven smoke runs.
type ManualAdminTrigger struct {
	Runner       *phase.SessionRunner
	Hub          *Hub
	InviteType   string // WS message type for the invitation (e.g., "auction.invitation")
	mu           sync.Mutex
	startedCount int
}

// NewManualAdminTrigger returns a trigger that calls BeginSession and
// broadcasts an invitation. The invite message type is app-specific.
func NewManualAdminTrigger(runner *phase.SessionRunner, hub *Hub, inviteType string) *ManualAdminTrigger {
	return &ManualAdminTrigger{
		Runner:     runner,
		Hub:        hub,
		InviteType: inviteType,
	}
}

// Start implements SessionTrigger.
func (t *ManualAdminTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	if len(participants) == 0 {
		return fmt.Errorf("trigger: no participants supplied")
	}
	t.mu.Lock()
	t.startedCount++
	t.mu.Unlock()

	ctx, err := t.Runner.BeginSession(sessionID, "")
	if err != nil {
		return fmt.Errorf("trigger: BeginSession(%q): %w", sessionID, err)
	}
	// Seed any caller-supplied attributes into context for the first
	// phase's Enter hook to find.
	for k, v := range attrs {
		ctx.Set(k, v)
	}

	if t.Hub != nil && t.InviteType != "" {
		t.Hub.BroadcastToSession(sessionID, participants, WSMessage{
			Type: t.InviteType,
		})
	}
	return nil
}

// StartedCount returns the number of sessions this trigger has begun.
// Useful for /admin/stats and smoke-test assertions.
func (t *ManualAdminTrigger) StartedCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.startedCount
}
