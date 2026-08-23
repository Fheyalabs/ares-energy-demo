// SPDX-License-Identifier: Apache-2.0

// Command session-service runs the bounded-admission example as a
// standalone HTTP+WebSocket service.
//
// Wiring:
//   - One SessionRunner built from the bounded-admission phase pipeline.
//   - One ManualAdminTrigger that seeds participants, crypto keys, and
//     per-session ContextHandle+fuse into each new session before broadcasting
//     the "admission.invitation" frame.
//   - A PostDispatchHook that unicasts each party's enc_check + commitment
//     as a bound_check.challenge message after the boundcheck phase's Enter
//     populates CtxBoundCheckCiphers.
//   - transport.Service for the HTTP admin surface and WebSocket hub.
//
// Env vars:
//
//	SESSION_PORT             listen port (default 8000)
//	ARES_WS_SECRET           HMAC key for WS auth tokens. If empty,
//	                         AllowDevBypass is enabled.
//	ADMISSION_CRYPTO_DEPTH   CKKS depth (default 8).
//	ADMISSION_RING_DIM       CKKS ring dimension (default 16384).
//	ADMISSION_DIM            Input vector dimension (default 8).
//
// To start a session:
//
//	curl -sS http://localhost:8000/admin/sessions -d '{
//	  "session_id": "admission-001",
//	  "participants": ["party-1","party-2","party-3"],
//	  "attrs": {
//	    "collective_pk": "<hex>",
//	    "eval_mult_final": "<hex>",
//	    "eval_sum_final": "<hex>",
//	    "dim": 8,
//	    "ring_dim": 16384,
//	    "depth": 8
//	  }
//	}'
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Fheyalabs/ares-core/examples/bounded_admission"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/boundcheck"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	depth, _ := strconv.Atoi(getEnv("ADMISSION_CRYPTO_DEPTH", "8"))
	ringDim, _ := strconv.Atoi(getEnv("ADMISSION_RING_DIM", "16384"))
	inDim, _ := strconv.Atoi(getEnv("ADMISSION_DIM", "8"))
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	logStream := transport.NewLogStream()

	ctx, cancel := signalContext()
	defer cancel()

	admissionRunner, err := bounded_admission.PipelineWithCrypto()
	if err != nil {
		log.Fatalf("build bounded-admission runner: %v", err)
	}

	// The trigger wraps ManualAdminTrigger to seed the canonical
	// context keys (participants, crypto contract, per-session
	// ContextHandle + fuse) from friendly admin POST attrs.
	innerTrigger := transport.NewManualAdminTrigger(admissionRunner, nil, "admission.invitation")
	trigger := &admissionTrigger{
		inner:   innerTrigger,
		runner:  admissionRunner,
		ringDim: ringDim,
		depth:   depth,
		inDim:   inDim,
	}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "bounded-admission-session-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         admissionRunner,
		Trigger:        trigger,
		InviteType:     "admission.invitation",
		LogStream:      logStream,
		PostDispatchHook: func(c *transport.Client, msg transport.WSMessage, _ error) {
			challengeUnicastIfNeeded(admissionRunner, trigger.hub, msg.SessionID)
		},
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}
	hub := svc.Hub()
	innerTrigger.Hub = hub
	trigger.hub = hub

	mode := "stub"
	log.Printf("[bounded-admission] session-service starting on :%s (mode=%s depth=%d ring_dim=%d dim=%d dev_bypass=%v)",
		port, mode, depth, ringDim, inDim, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("service.Run: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Trigger
// ---------------------------------------------------------------------------

// admissionTrigger wraps ManualAdminTrigger to inject the canonical
// per-session context keys from friendly admin POST attrs, including
// the boundcheck handle and fuse for per-session FHE.
type admissionTrigger struct {
	inner    *transport.ManualAdminTrigger
	hub      *transport.Hub
	runner   *phase.SessionRunner
	ringDim  int
	depth    int
	inDim    int
}

func (t *admissionTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	dim := t.inDim
	ringDim := t.ringDim
	depth := t.depth

	// Decode pre-shared hex keys from attrs.
	var jointPK, evalMultFinal, evalSumFinal []byte
	if v, ok := attrs["collective_pk"]; ok {
		if s, isStr := v.(string); isStr && s != "" {
			decoded, err := hex.DecodeString(s)
			if err != nil {
				return fmt.Errorf("decode collective_pk hex: %w", err)
			}
			jointPK = decoded
		}
	}
	if v, ok := attrs["eval_mult_final"]; ok {
		if s, isStr := v.(string); isStr && s != "" {
			decoded, err := hex.DecodeString(s)
			if err != nil {
				return fmt.Errorf("decode eval_mult_final hex: %w", err)
			}
			evalMultFinal = decoded
		}
	}
	if v, ok := attrs["eval_sum_final"]; ok {
		if s, isStr := v.(string); isStr && s != "" {
			decoded, err := hex.DecodeString(s)
			if err != nil {
				return fmt.Errorf("decode eval_sum_final hex: %w", err)
			}
			evalSumFinal = decoded
		}
	}

	// Override dim from attrs if provided.
	if v, ok := attrs["dim"]; ok {
		switch val := v.(type) {
		case int:
			dim = val
		case float64:
			dim = int(val)
		}
	}

	canonical := map[string]any{
		defaults.CtxParticipants:   participants,
		boundcheck.CtxInputDim:     dim,
	}
	if len(jointPK) > 0 {
		canonical[boundcheck.CtxJointPublicKey] = jointPK
	}
	if len(evalMultFinal) > 0 {
		canonical[boundcheck.CtxEvalKeyBundle] = evalMultFinal
	}

	// Start the session (BeginSession + broadcast invitation).
	if err := t.inner.Start(sessionID, participants, canonical); err != nil {
		return err
	}

	// Build per-session crypto and inject handle+fuse into the session
	// context for the boundcheck phase's B0 fallback path.
	if len(jointPK) > 0 && len(evalMultFinal) > 0 && len(evalSumFinal) > 0 {
		sctx := t.runner.SessionContext(sessionID)
		if sctx == nil {
			return fmt.Errorf("session context not found after BeginSession")
		}
		handle, fuse, err := bounded_admission.BuildSessionCrypto(ringDim, depth, dim,
			jointPK, evalMultFinal, evalSumFinal)
		if err != nil {
			return fmt.Errorf("build session crypto: %w", err)
		}
		if handle != nil {
			sctx.Set(boundcheck.CtxBoundCheckHandle, handle)
			sctx.Set(boundcheck.CtxBoundCheckFuse, fuse)
		}
	}

	// Walk past PhaseInvitation (pure-compute) and PhaseKeygen (pre-shared)
	// so the session lands at StateSubmitting, ready to accept MsgInput.
	return t.runner.AdvanceToState(sessionID, bounded_admission.StateSubmitting)
}

// ---------------------------------------------------------------------------
// PostDispatchHook — unicast bound_check.challenge after boundcheck.Enter
// ---------------------------------------------------------------------------

// challengeUnicastIfNeeded broadcasts the FULL set of check ciphertexts +
// commitments to EVERY participant after the boundcheck phase's Enter populates
// CtxBoundCheckCiphers. Each party needs every check CT because boundcheck.Exit
// fuses an N-of-N quorum per ciphertext — so every party must partial-decrypt
// every check CT and reply with a map[checkedParty]→partial.
// Duplicate sends are prevented by a sentinel flag in the session context.
func challengeUnicastIfNeeded(runner *phase.SessionRunner, hub *transport.Hub, sessionID string) {
	if hub == nil || runner == nil {
		return
	}
	sctx := runner.SessionContext(sessionID)
	if sctx == nil {
		return
	}
	// Guard: only send challenges once per session.
	if sctx.Has("_admission_challenges_sent") {
		return
	}

	checks, ok := phase.TryGet[map[string][]byte](sctx, boundcheck.CtxBoundCheckCiphers)
	if !ok || len(checks) == 0 {
		return
	}
	commitments, _ := phase.TryGet[map[string][]byte](sctx, boundcheck.CtxBoundCheckCommitments)
	participants, _ := phase.TryGet[[]string](sctx, defaults.CtxParticipants)

	// Build the full challenge once: all parties' enc_check + commitment (hex).
	allChecks := make(map[string]string, len(checks))
	for party, ec := range checks {
		allChecks[party] = hex.EncodeToString(ec)
	}
	allCommitments := make(map[string]string, len(commitments))
	for party, cm := range commitments {
		allCommitments[party] = hex.EncodeToString(cm)
	}
	payload, err := json.Marshal(map[string]any{
		"checks":      allChecks,      // party -> enc_check hex
		"commitments": allCommitments, // party -> commitment hex
	})
	if err != nil {
		log.Printf("[challenge] marshal (session=%s): %v", sessionID, err)
		return
	}
	for _, p := range participants {
		if err := hub.SendTo(p, transport.WSMessage{
			Type:      bounded_admission.MsgChallenge,
			SessionID: sessionID,
			Payload:   payload,
		}); err != nil {
			log.Printf("[challenge] send to %s (session=%s): %v", p, sessionID, err)
		}
	}

	// Set sentinel to prevent re-sending on subsequent WS messages.
	sctx.Set("_admission_challenges_sent", true)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
