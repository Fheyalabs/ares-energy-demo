// SPDX-License-Identifier: Apache-2.0

// Command session-service runs the recurring-cohort-ranking example as
// a standalone HTTP+WebSocket service.
//
// Two runners exist for this app. The COHORT_MODE env var picks one:
//
//	COHORT_MODE=formation   cohort-form → keygen (run once per cohort)
//	COHORT_MODE=weekly      invite → key-lookup → submit → argmax →
//	                        decrypt → settle (run per session, reusing
//	                        the formation's key bundle)
//
// The weekly mode prepends a "seeder" bridge phase so the runner can be
// constructed without the key bundle present at construction time; the
// trigger seeds the real bytes into the SessionContext at runtime and
// advances past the seeder. The cohort key bundle is in-memory only; in
// a real deployment the formation service would persist it (Redis, KMS).
//
// Env vars:
//
//	SESSION_PORT          listen port (default 8000)
//	ARES_WS_SECRET        HMAC key for WS auth tokens
//	COHORT_MODE           "formation" | "weekly" (default formation)
//	COHORT_CRYPTO_DEPTH   CKKS depth (default 30 — reuses helper kernel)
//	COHORT_RING_DIM       CKKS ring dimension (default 16384)
//
// Formation start:
//
//	curl http://localhost:8000/admin/sessions -d '{
//	  "session_id": "cohort-A-init",
//	  "participants": ["m-1","m-2","m-3","m-4"]
//	}'
//
// Weekly start:
//
//	curl http://localhost:8000/admin/sessions -d '{
//	  "session_id": "cohort-A-week-12",
//	  "participants": ["m-1","m-2","m-3","m-4"],
//	  "attrs": {
//	    "ranking.collective_pk":  "<base64 blob>",
//	    "ranking.secret_shares": {"m-1":"...","m-2":"..."},
//	    "ranking.eval_keys":     "<base64 blob>"
//	  }
//	}'
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Fheyalabs/ares-core/examples/recurring_cohort_ranking"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	mode := getEnv("COHORT_MODE", "formation")
	// Cohort defaults match the example's canonical contract
	// (PhaseCohortKeygen.Provides{depth: 10, ring_dim: 2048}). These
	// are Mac-safe (~500 KiB keys) — bump via env vars on prod hosts.
	depth, _ := strconv.Atoi(getEnv("COHORT_CRYPTO_DEPTH", "10"))
	ringDim, _ := strconv.Atoi(getEnv("COHORT_RING_DIM", "2048"))
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	logStream := transport.NewLogStream()

	ctx, cancel := signalContext()
	defer cancel()

	var helper *helperclient.Client
	helperPath := os.Getenv("ARES_HELPER_BINARY")
	if helperPath != "" {
		c, err := helperclient.Start(ctx, helperPath)
		if err != nil {
			log.Fatalf("start helper: %v", err)
		}
		helper = c
		defer helper.Close()
	}

	runner, trigger, inviteType, err := buildRunner(mode, depth, ringDim, helper)
	if err != nil {
		log.Fatalf("build runner (%s): %v", mode, err)
	}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "cohort-" + mode + "-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         runner,
		Trigger:        trigger,
		InviteType:     inviteType,
		LogStream:      logStream,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}
	if w, ok := trigger.(hubWiring); ok {
		w.setHub(svc.Hub())
	}

	hmode := "stub"
	if helper != nil {
		hmode = "helper"
	}
	log.Printf("[cohort] %s-service starting on :%s (scoring=%s depth=%d ring_dim=%d dev_bypass=%v)",
		mode, port, hmode, depth, ringDim, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("service.Run: %v", err)
	}
}

type hubWiring interface {
	setHub(*transport.Hub)
}

func buildRunner(mode string, depth, ringDim int, helper *helperclient.Client) (*phase.SessionRunner, transport.SessionTrigger, string, error) {
	cryptoCtx := map[string]any{
		"depth":            depth,
		"ring_dim":         ringDim,
		"scaling_mod_size": 50,
	}
	switch mode {
	case "formation":
		var runner *phase.SessionRunner
		var err error
		if helper != nil {
			runner, err = cohort.FormationPipelineWithHelper(helper)
		} else {
			runner, err = cohort.FormationPipeline()
		}
		if err != nil {
			return nil, nil, "", err
		}
		inner := transport.NewManualAdminTrigger(runner, nil, "cohort.formation.invitation")
		return runner, &formationTrigger{inner: inner, cryptoCtx: cryptoCtx}, "cohort.formation.invitation", nil

	case "weekly":
		argmax := cohort.NewPhaseArgmaxScoring()
		if helper != nil {
			argmax = cohort.NewPhaseArgmaxScoringWithHelper(helper, helperclient.EvalPolyParams{
				Coefficients: []float64{0.5, 0.75, 0, -0.25},
				LowerBound:   -1, UpperBound: 1,
			})
		}
		runner, err := phase.Compose(
			&weeklyKeySeeder{},
			cohort.NewPhaseRankingInvitation(),
			cohort.NewPhasePreSharedKeyLookup(),
			cohort.NewPhaseSubmitRating(),
			argmax,
			cohort.NewPhaseThresholdDecrypt(),
			cohort.NewPhaseSettleRanking(),
		)
		if err != nil {
			return nil, nil, "", fmt.Errorf("build weekly pipeline: %w", err)
		}
		inner := transport.NewManualAdminTrigger(runner, nil, "ranking.invitation")
		return runner, &weeklyTrigger{
			inner:     inner,
			runner:    runner,
			cryptoCtx: cryptoCtx,
		}, "ranking.invitation", nil

	default:
		return nil, nil, "", fmt.Errorf("unknown COHORT_MODE %q (want formation|weekly)", mode)
	}
}

// stateWeeklySeeded is the initial state of the weekly pipeline (held by
// the bridge phase below).
const stateWeeklySeeded phase.SessionState = "WEEKLY_SEEDED"

// weeklyKeySeeder is the bridge phase that lets the weekly runner be
// constructed before the cohort's key bundle is loaded. It promises to
// Provide the three key-bundle context entries; at runtime the trigger
// supplies the actual bytes via ctx.Set before advancing the runner
// past this phase.
type weeklyKeySeeder struct{}

func (weeklyKeySeeder) Name() string                         { return "weekly-key-seeder" }
func (weeklyKeySeeder) Lifetime() phase.Lifetime             { return phase.LifetimePerCohort }
func (weeklyKeySeeder) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (weeklyKeySeeder) EntryState() phase.SessionState       { return stateWeeklySeeded }
func (weeklyKeySeeder) ExitState() phase.SessionState        { return cohort.StateRankingInviting }
func (weeklyKeySeeder) InternalStates() []phase.SessionState { return nil }
func (weeklyKeySeeder) ConsumedMessageTypes() []string       { return nil }
func (weeklyKeySeeder) Requires() phase.ContextSchema        { return nil }
func (weeklyKeySeeder) Provides() phase.ContextSchema {
	return phase.ContextSchema{
		cohort.CtxParticipants: {TypeName: "[]string"},
		cohort.CtxCollectivePK: {
			TypeName:    "[]byte",
			Constraints: map[string]any{"topology": "preshared"},
		},
		cohort.CtxSecretShares: {
			TypeName:    "map[string][]byte",
			Constraints: map[string]any{"topology": "preshared"},
		},
		cohort.CtxEvalKeys:       {TypeName: "OpenFHEEvalKeys"},
		cohort.CtxCryptoContract: {TypeName: "OpenFHEContract", Constraints: map[string]any{"depth": 30, "ring_dim": 16384}},
	}
}
func (weeklyKeySeeder) Enter(*phase.SessionContext) error { return nil }
func (weeklyKeySeeder) OnMessage(*phase.SessionContext, string, string, []byte) error {
	return nil
}
func (weeklyKeySeeder) CheckComplete(*phase.SessionContext) bool { return true }
func (weeklyKeySeeder) Exit(*phase.SessionContext) error         { return nil }

// formationTrigger seeds CtxParticipants for the cohort-formation
// pipeline.
type formationTrigger struct {
	inner     *transport.ManualAdminTrigger
	cryptoCtx map[string]any
}

func (t *formationTrigger) setHub(h *transport.Hub) { t.inner.Hub = h }

func (t *formationTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	canonical := map[string]any{
		cohort.CtxParticipants:   participants,
		cohort.CtxCryptoContract: t.cryptoCtx,
	}
	for k, v := range attrs {
		canonical[k] = v
	}
	// Optional pre-shared bundle: an operator can re-seed an existing
	// cohort by passing the previous bundle. PhaseCohortKeygen.Exit
	// detects it and skips generating a new one.
	if err := decodeHexAttrs(canonical, []string{
		cohort.CtxCollectivePK,
		cohort.CtxEvalKeys,
	}); err != nil {
		return err
	}
	if err := t.inner.Start(sessionID, participants, canonical); err != nil {
		return err
	}
	return t.inner.Runner.AdvanceToState(sessionID, cohort.StateCohortKeygen)
}

// weeklyTrigger seeds the cohort's pre-shared key bundle (supplied via
// admin POST attrs) plus CtxParticipants. After BeginSession + ctx
// seeding, it advances past the bridge phase so PhasePreSharedKeyLookup
// (next state RANKING_LOCKED) runs and validates the seeded keys.
type weeklyTrigger struct {
	inner     *transport.ManualAdminTrigger
	runner    *phase.SessionRunner
	cryptoCtx map[string]any
}

func (t *weeklyTrigger) setHub(h *transport.Hub) { t.inner.Hub = h }

func (t *weeklyTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	required := []string{
		cohort.CtxCollectivePK,
		cohort.CtxSecretShares,
		cohort.CtxEvalKeys,
	}
	for _, key := range required {
		if _, ok := attrs[key]; !ok {
			return fmt.Errorf("weekly trigger: missing required attr %q (load from formation output)", key)
		}
	}

	canonical := map[string]any{
		cohort.CtxParticipants:   participants,
		cohort.CtxCryptoContract: t.cryptoCtx,
	}
	for k, v := range attrs {
		canonical[k] = v
	}
	// Pre-shared bundle (required for weekly mode): hex-decode the
	// public key + eval keys so PhasePreSharedKeyLookup finds typed
	// []byte values, not strings.
	if err := decodeHexAttrs(canonical, []string{
		cohort.CtxCollectivePK,
		cohort.CtxEvalKeys,
	}); err != nil {
		return err
	}
	if err := t.inner.Start(sessionID, participants, canonical); err != nil {
		return err
	}
	// Advance past the bridge phase + invitation + key-lookup so the
	// session lands at RANKING_BIDDING, ready for participants to
	// submit ranking.rating messages. PhasePreSharedKeyLookup's Enter
	// runs against the freshly-seeded context here.
	if err := t.runner.AdvanceToState(sessionID, cohort.StateRankingBidding); err != nil {
		return fmt.Errorf("weekly trigger: advance to bidding: %w", err)
	}
	return nil
}

// decodeHexAttrs hex-decodes any string-typed entry in attrs at the
// listed keys into []byte. Non-string and absent entries are left
// alone.
func decodeHexAttrs(attrs map[string]any, keys []string) error {
	for _, key := range keys {
		v, ok := attrs[key]
		if !ok {
			continue
		}
		s, isString := v.(string)
		if !isString || s == "" {
			continue
		}
		decoded, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("decode %s as hex: %w", key, err)
		}
		attrs[key] = decoded
	}
	return nil
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
