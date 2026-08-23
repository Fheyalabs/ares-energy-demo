// SPDX-License-Identifier: Apache-2.0

// Command session-service runs the voting example (onion-shuffle +
// SC-10 lineage variant) as a standalone HTTP+WebSocket service.
//
// Env vars:
//
//	SESSION_PORT     listen port (default 8000)
//	ARES_WS_SECRET   HMAC key for WS auth tokens (empty ⇒ dev-bypass).
//
// To start a session:
//
//	curl -sS http://localhost:8000/admin/sessions -d '{
//	  "session_id": "vote-001",
//	  "participants": ["voter-A","voter-B","voter-C"]
//	}'
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Fheyalabs/ares-core/examples/voting"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	signer, err := sign.NewEd25519Signer()
	if err != nil {
		log.Fatalf("voting: signer: %v", err)
	}
	verifiers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}

	runner, err := voting.PipelineWithShuffle(signer, verifiers)
	if err != nil {
		log.Fatalf("voting: build runner: %v", err)
	}

	ctx, cancel := signalContext()
	defer cancel()

	logStream := transport.NewLogStream()
	innerTrigger := transport.NewManualAdminTrigger(runner, nil, "vote.invitation")
	trigger := &votingTrigger{inner: innerTrigger}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "voting-session-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         runner,
		Trigger:        trigger,
		InviteType:     "vote.invitation",
		LogStream:      logStream,
		// PostDispatchHook drives the sequential onion-peel relay:
		// after all onion.batch arrive, broadcast the assembled batch
		// to participants[0]; when a peeler sends onion.peel_forward,
		// relay it to the next peeler.  The hub handle is injected
		// below after NewService returns (trigger.hub is set then).
		PostDispatchHook: func(c *transport.Client, msg transport.WSMessage, _ error) {
			peelRelayIfNeeded(runner, trigger.hub, msg.SessionID, msg.Type, c.Pseudonym, msg.Payload)
		},
	})
	if err != nil {
		log.Fatalf("voting: build service: %v", err)
	}
	hub := svc.Hub()
	innerTrigger.Hub = hub
	trigger.hub = hub

	log.Printf("[voting] session-service on :%s (shuffle+lineage, dev_bypass=%v)", port, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("voting: service.Run: %v", err)
	}
}

// onionBatchPayload is the wire shape of onion.batch / onion.peel_forward.
type onionBatchPayload struct {
	Onions []string `json:"onions"` // base64-encoded onion bytes
}

// peelRelayIfNeeded drives the sequential onion-peel chain.
//
//   - onion.batch quorum met → assemble all N onions in participant order
//     and send the merged batch to participants[0] as onion.peel_forward.
//   - onion.peel_forward from participants[k] → relay the batch to
//     participants[k+1] so the next peeler can strip its layer.
//     The final peeler's peel_forward completes the runner's quorum;
//     no further relay is needed.
func peelRelayIfNeeded(runner *phase.SessionRunner, hub *transport.Hub,
	sessionID, msgType, from string, payload json.RawMessage) {

	if hub == nil {
		return
	}
	sctx := runner.SessionContext(sessionID)
	if sctx == nil {
		return
	}

	participants, ok := phase.TryGet[[]string](sctx, anon.CtxParticipants)
	if !ok || len(participants) == 0 {
		return
	}
	n := len(participants)

	switch msgType {
	case anon.MsgOnionBatch:
		// Check if all N batches have been collected.
		bucket := anon.AccumulatedOnions(sctx)
		if len(bucket) < n {
			return
		}
		// All N batches collected.  Assemble in participant order and
		// send to participants[0] to start the sequential peel chain.
		assembled, err := assembleBatch(participants, bucket)
		if err != nil {
			log.Printf("[onion-relay] assemble batch session=%s: %v", sessionID, err)
			return
		}
		log.Printf("[onion-relay] batch complete session=%s — sending to %s to start peel",
			sessionID, participants[0])
		hub.SendTo(participants[0], transport.WSMessage{
			Type:      anon.MsgPeelForward,
			SessionID: sessionID,
			Payload:   assembled,
		})

	case anon.MsgPeelForward:
		// Determine which peeler just forwarded.
		peelerIdx := -1
		for i, p := range participants {
			if p == from {
				peelerIdx = i
				break
			}
		}
		if peelerIdx < 0 || peelerIdx >= n-1 {
			// Last peeler; runner's quorum will complete naturally.
			return
		}
		// Relay the peeled batch to the next participant.
		nextPeer := participants[peelerIdx+1]
		log.Printf("[onion-relay] peel from %s session=%s — forwarding to %s",
			from, sessionID, nextPeer)
		hub.SendTo(nextPeer, transport.WSMessage{
			Type:      anon.MsgPeelForward,
			SessionID: sessionID,
			Payload:   payload,
		})
	}
}

// assembleBatch builds the ordered onion list from N individual
// single-onion batches keyed by participant pseudonym.
func assembleBatch(participants []string, bucket map[string][]byte) (json.RawMessage, error) {
	onions := make([]string, 0, len(participants))
	for _, p := range participants {
		raw, ok := bucket[p]
		if !ok {
			return nil, fmt.Errorf("missing onion batch from %s", p)
		}
		var bp onionBatchPayload
		if err := json.Unmarshal(raw, &bp); err != nil {
			return nil, fmt.Errorf("decode batch from %s: %w", p, err)
		}
		if len(bp.Onions) == 0 {
			return nil, fmt.Errorf("empty onion list from %s", p)
		}
		if _, err := base64.StdEncoding.DecodeString(bp.Onions[0]); err != nil {
			return nil, fmt.Errorf("invalid base64 from %s: %w", p, err)
		}
		onions = append(onions, bp.Onions[0])
	}
	assembled, err := json.Marshal(onionBatchPayload{Onions: onions})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(assembled), nil
}

// votingTrigger wraps ManualAdminTrigger to seed the three participant
// context keys the shuffle arc requires, then advances the session into
// the GOSSIP state so PhaseGShuffle.Enter is called immediately.
type votingTrigger struct {
	inner *transport.ManualAdminTrigger
	hub   *transport.Hub
}

func (t *votingTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	if len(participants) < 2 {
		return fmt.Errorf("voting needs at least 2 participants, got %d", len(participants))
	}
	// PhaseInvite.Provides() declares all three keys; seed them here so
	// the session context is populated before PhaseGShuffle.Requires()
	// is consulted during the state advance.
	canonical := map[string]any{
		voting.CtxVoteParticipants: participants,
		defaults.CtxParticipants:   participants,
		anon.CtxParticipants:       participants,
	}
	for k, v := range attrs {
		canonical[k] = v
	}
	if err := t.inner.Start(sessionID, participants, canonical); err != nil {
		return err
	}
	// Advance past INVITING (PhaseInvite) and LOCKED (PlaintextKeygen)
	// into GOSSIP, which is PhaseGShuffle's EntryState.
	return t.inner.Runner.AdvanceToState(sessionID, defaults.StateGossip)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Printf("shutdown signal received")
		cancel()
	}()
	return ctx, cancel
}
