// SPDX-License-Identifier: Apache-2.0

// Command session-service runs the sealed-bid auction example as a
// standalone HTTP+WebSocket service.
//
// Wiring:
//   - One SessionRunner built from the auction phase pipeline.
//   - One ManualAdminTrigger that seeds CtxAuctionParticipants and
//     CtxAuctionCryptoContract into each new session before broadcasting
//     the "auction.invitation" frame.
//   - transport.Service for the HTTP admin surface and WebSocket hub.
//
// Env vars:
//
//	SESSION_PORT             listen port (default 8000)
//	ARES_WS_SECRET           HMAC key for WS auth tokens. If empty,
//	                         AllowDevBypass is enabled.
//	AUCTION_CRYPTO_DEPTH     CKKS depth (default 30).
//	AUCTION_RING_DIM         CKKS ring dimension (default 16384).
//	ARES_HELPER_BINARY       Path to the openfhe-contract-helper. If
//	                         set, PhaseArgmax runs real CKKS scoring
//	                         against the helper subprocess (depth=30
//	                         indicator sharpening polynomial by
//	                         default). If unset, the runner uses the
//	                         stub argmax for wire-only smokes.
//
// To start a session:
//
//	curl -sS http://localhost:8000/admin/sessions -d '{
//	  "session_id": "auction-001",
//	  "participants": ["bidder-1","bidder-2","bidder-3"]
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

	"github.com/Fheyalabs/ares-core/examples/sealed_bid_auction"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func main() {
	port := getEnv("SESSION_PORT", "8000")
	depth, _ := strconv.Atoi(getEnv("AUCTION_CRYPTO_DEPTH", "12"))
	ringDim, _ := strconv.Atoi(getEnv("AUCTION_RING_DIM", "2048"))
	secret := []byte(os.Getenv("ARES_WS_SECRET"))
	devBypass := len(secret) == 0

	logStream := transport.NewLogStream()

	ctx, cancel := signalContext()
	defer cancel()

	var (
		runner     interface{ /* placeholder, see below */ }
		helper     *helperclient.Client
		helperPath = os.Getenv("ARES_HELPER_BINARY")
	)
	_ = runner

	auctionRunner, err := buildAuctionRunner(ctx, helperPath, &helper)
	if err != nil {
		log.Fatalf("build auction runner: %v", err)
	}
	if helper != nil {
		defer helper.Close()
	}

	cryptoCtx := map[string]any{
		"depth":            depth,
		"ring_dim":         ringDim,
		"scaling_mod_size": 50,
	}

	// The default ManualAdminTrigger is wrapped so that the canonical
	// context keys are seeded automatically when the smoke driver posts
	// just (session_id, participants).
	innerTrigger := transport.NewManualAdminTrigger(auctionRunner, nil, "auction.invitation")
	trigger := &auctionTrigger{
		inner:     innerTrigger,
		cryptoCtx: cryptoCtx,
	}

	svc, err := transport.NewService(transport.Config{
		Addr:           ":" + port,
		ServiceName:    "auction-session-service",
		Secret:         secret,
		AllowDevBypass: devBypass,
		Runner:         auctionRunner,
		Trigger:        trigger,
		InviteType:     "auction.invitation",
		LogStream:      logStream,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}
	// Re-point the trigger's hub to the live one so the invitation
	// broadcast actually reaches connected clients.
	innerTrigger.Hub = svc.Hub()

	mode := "stub"
	if helper != nil {
		mode = "helper"
	}
	log.Printf("[auction] session-service starting on :%s (mode=%s depth=%d ring_dim=%d dev_bypass=%v)",
		port, mode, depth, ringDim, devBypass)
	if err := svc.Run(ctx); err != nil {
		log.Fatalf("service.Run: %v", err)
	}
}

// buildAuctionRunner picks stub-mode or helper-mode based on whether
// ARES_HELPER_BINARY is set. On helper mode the started Client is
// returned via helperOut so main can defer its Close.
func buildAuctionRunner(
	ctx context.Context,
	helperPath string,
	helperOut **helperclient.Client,
) (*phase.SessionRunner, error) {
	if helperPath == "" {
		return auction.Pipeline()
	}
	client, err := helperclient.Start(ctx, helperPath)
	if err != nil {
		return nil, err
	}
	*helperOut = client
	// [0,1]-mapped degree-3 sign approximation, the recommended
	// default for normalized scalar bids on [-1, 1].
	sharpening := helperclient.EvalPolyParams{
		Coefficients: []float64{0.5, 0.75, 0, -0.25},
		LowerBound:   -1, UpperBound: 1,
	}
	return auction.PipelineWithHelper(client, sharpening)
}

// auctionTrigger wraps ManualAdminTrigger to inject the canonical
// CtxAuction* context keys from a friendly admin POST body.
type auctionTrigger struct {
	inner     *transport.ManualAdminTrigger
	cryptoCtx map[string]any
}

func (t *auctionTrigger) Start(sessionID string, participants []string, attrs map[string]any) error {
	canonical := map[string]any{
		auction.CtxAuctionParticipants:   participants,
		auction.CtxAuctionCryptoContract: t.cryptoCtx,
	}
	for k, v := range attrs {
		canonical[k] = v
	}
	// PreSharedKeygen: if the smoke client supplied a pre-generated
	// key bundle (hex-encoded) in attrs, decode the strings into
	// []byte so PhaseKeygen.Exit detects them and skips its own
	// keygen call. The smoke encrypts under these keys client-side,
	// so the server MUST use the same bundle (not generate its own).
	for _, key := range []string{
		auction.CtxAuctionCollectivePublicKey,
		auction.CtxAuctionEvalKeys,
	} {
		if v, ok := canonical[key]; ok {
			if s, isString := v.(string); isString && s != "" {
				decoded, err := hex.DecodeString(s)
				if err != nil {
					return fmt.Errorf("decode %s as hex: %w", key, err)
				}
				canonical[key] = decoded
			}
		}
	}
	if err := t.inner.Start(sessionID, participants, canonical); err != nil {
		return err
	}
	// Walk past PhaseInvitation (pure-compute, CheckComplete=true) so
	// the session is at AUCTION_LOCKED — the state where PhaseKeygen
	// consumes auction.keygen.share messages.
	return t.inner.Runner.AdvanceToState(sessionID, auction.StateAuctionLocked)
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

