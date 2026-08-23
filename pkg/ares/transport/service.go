// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
)

// Config wires a SessionRunner into a runnable HTTP+WebSocket service.
//
// Required fields: Addr, Runner. Everything else has a sensible default
// (RealClock, no-op trigger, empty secret with dev bypass) for the
// minimum useful service.
type Config struct {
	// Addr is the listen address (e.g. ":8000").
	Addr string

	// ServiceName tags health/stats responses (e.g. "auction-service").
	ServiceName string

	// Secret is the shared HMAC key for WS auth tokens. If empty,
	// AllowDevBypass must be true.
	Secret         []byte
	AllowDevBypass bool

	// Runner is the SessionRunner that owns the phase pipeline.
	Runner *phase.SessionRunner

	// Trigger decides when sessions start. If nil, a ManualAdminTrigger
	// with no invitation broadcast is installed.
	Trigger SessionTrigger

	// InviteType is the WS message type the default ManualAdminTrigger
	// broadcasts when a session starts. Ignored if Trigger is supplied.
	InviteType string

	// Clock is the time source. If nil, RealClock is used.
	Clock Clock

	// LogStream, if non-nil, is registered on the HTTP mux at
	// /v2/debug/logs. Construct it via NewLogStream at process start.
	LogStream *LogStream

	// EventRing, if non-nil, records per-session dispatch events for
	// retrieval via GET /admin/sessions/{id}/events. nil disables recording.
	EventRing *SessionEventRing

	// AllowedOrigins is the WebSocket Origin whitelist. Empty + dev bypass
	// preserves the historical "accept any origin" behavior; production
	// must set this to a non-empty list (e.g. ["https://fheya.de"]).
	AllowedOrigins []string

	// MaxWSMessageSize caps inbound WebSocket frame bytes. Zero falls back
	// to DefaultMaxMessageSize.
	MaxWSMessageSize int64

	// MaxArtifactSize caps the request body of PUT /v2/artifacts/{key}.
	// Zero falls back to DefaultMaxArtifactSize.
	MaxArtifactSize int64

	// DebugLogsAuth, if non-nil, gates access to the SSE log stream at
	// GET /v2/debug/logs. nil preserves the historical unauthenticated
	// access (intended for trusted reverse-proxy deployments only).
	DebugLogsAuth func(*http.Request) bool

	// PostDispatchHook, if non-nil, is called after every inbound WS
	// frame has been dispatched to the runner (HandleLineageMessage or
	// HandleMessage). The hook receives the original client, message,
	// and any dispatch error. The hook runs synchronously in the hub's
	// readPump goroutine; it must not block.
	//
	// Intended for applications that need side effects after dispatch —
	// for example, the anon-shuffle relay: once all onion.batch messages
	// are accumulated the hook broadcasts the assembled batch to start
	// the sequential peel chain.
	PostDispatchHook func(c *Client, msg WSMessage, dispatchErr error)
}

// Service composes Hub + Artifacts + Admin + LogStream into a runnable
// HTTP server. Build it with NewService, then call Run.
type Service struct {
	cfg       Config
	hub       *Hub
	artifacts *ArtifactStore
	admin     *AdminHandlers
	mux       *http.ServeMux
}

// NewService validates the config and assembles the service. Returns an
// error if Addr or Runner is missing or if Secret is empty without
// AllowDevBypass.
func NewService(cfg Config) (*Service, error) {
	if cfg.Addr == "" {
		return nil, errors.New("transport: Config.Addr is required")
	}
	if cfg.Runner == nil {
		return nil, errors.New("transport: Config.Runner is required")
	}
	if len(cfg.Secret) == 0 && !cfg.AllowDevBypass {
		return nil, errors.New("transport: empty Secret requires AllowDevBypass=true")
	}
	// Hard refusal of dev-bypass when the host explicitly says we're
	// in production. Set ARES_ENV=production in the systemd / docker
	// environment to make this guard active. The dev-bypass mode
	// accepts any token; allowing it in production would let any
	// browser open a WS connection as any pseudonym.
	if cfg.AllowDevBypass && os.Getenv("ARES_ENV") == "production" {
		return nil, errors.New("transport: AllowDevBypass=true refused when ARES_ENV=production")
	}

	// Default event ring if caller didn't supply one. 128 events per
	// session gives ~2 min of visibility at 1 msg/s.
	if cfg.EventRing == nil {
		cfg.EventRing = NewSessionEventRing(128)
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock()
	}

	auth := &AuthMiddleware{Secret: cfg.Secret, AllowDevBypass: cfg.AllowDevBypass}
	hub := NewHubWithOptions(cfg.Clock, auth, HubOptions{
		AllowedOrigins: cfg.AllowedOrigins,
		// Preserve the dev-friendly "accept any Origin" default only
		// when no whitelist is set AND auth is in dev-bypass mode.
		// In production (Secret set, no AllowedOrigins), browser
		// origins are rejected — non-browser clients (Go/Python) omit
		// Origin entirely and are unaffected.
		AllowAnyOrigin: len(cfg.AllowedOrigins) == 0 && cfg.AllowDevBypass,
		MaxMessageSize: cfg.MaxWSMessageSize,
	})
	artifacts := NewArtifactStore()

	if cfg.Trigger == nil {
		cfg.Trigger = NewManualAdminTrigger(cfg.Runner, hub, cfg.InviteType)
	}

	admin := &AdminHandlers{
		ServiceName:     cfg.ServiceName,
		Hub:             hub,
		Runner:          cfg.Runner,
		Trigger:         cfg.Trigger,
		Artifacts:       artifacts,
		EventRing:       cfg.EventRing,
		MaxArtifactSize: cfg.MaxArtifactSize,
	}

	mux := http.NewServeMux()
	admin.RegisterRoutes(mux)
	if cfg.LogStream != nil {
		cfg.LogStream.RegisterRoutes(mux, cfg.DebugLogsAuth)
	}
	mux.HandleFunc("/v2/ws", hub.HandleWS)

	// Dispatch every WS frame into the runner.
	// v2 frames (Lineage != nil) go through HandleLineageMessage so the
	// runner verifies the SC-10 lineage node before calling OnMessage.
	// v1 frames fall through to the legacy HandleMessage path.
	postHook := cfg.PostDispatchHook
	hub.SetMessageHandler(func(c *Client, msg WSMessage) {
		if msg.SessionID == "" {
			// Frames without a session_id are non-routable (control
			// messages, future client→server pings). Ignore.
			return
		}
		var err error
		if msg.Lineage != nil {
			_, err = cfg.Runner.HandleLineageMessage(msg.SessionID, msg.Type, c.Pseudonym, msg.Payload, msg.Lineage)
		} else {
			_, err = cfg.Runner.HandleMessage(msg.SessionID, msg.Type, c.Pseudonym, msg.Payload)
		}
		if cfg.EventRing != nil {
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			cfg.EventRing.Record(msg.SessionID, msg.Type, c.Pseudonym, errStr)
		}
		if err != nil && !isPhaseDoesNotConsume(err) {
			log.Printf("[dispatch] session=%s type=%s from=%s err=%v",
				shortID(msg.SessionID), msg.Type, shortID(c.Pseudonym), err)
		}
		if postHook != nil {
			postHook(c, msg, err)
		}
	})

	return &Service{
		cfg:       cfg,
		hub:       hub,
		artifacts: artifacts,
		admin:     admin,
		mux:       mux,
	}, nil
}

// Hub returns the underlying Hub for app-specific wiring (typically a
// phase Exit hook that broadcasts a result message).
func (s *Service) Hub() *Hub { return s.hub }

// Artifacts returns the artifact store. Phase hooks Put/Get blobs that
// don't fit in WS frames.
func (s *Service) Artifacts() *ArtifactStore { return s.artifacts }

// Mux returns the HTTP mux for additional app-specific routes.
func (s *Service) Mux() *http.ServeMux { return s.mux }

// Run starts the HTTP server and blocks until ctx is cancelled or the
// server fails. Performs a graceful shutdown on ctx cancellation.
func (s *Service) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:    s.cfg.Addr,
		Handler: s.mux,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("[service] %s listening on %s", s.cfg.ServiceName, s.cfg.Addr)
		errCh <- srv.ListenAndServe()
	}()

	// Sweep the artifact store every 5 minutes.
	sweep := time.NewTicker(5 * time.Minute)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutCtx)
		case <-sweep.C:
			if n := s.artifacts.Sweep(); n > 0 {
				log.Printf("[service] swept %d expired artifacts", n)
			}
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}
	}
}

func isPhaseDoesNotConsume(err error) bool {
	if err == nil {
		return false
	}
	// runner.HandleMessage returns "phase X: does not consume message
	// type Y in state Z" when the current phase does not claim the
	// message type. This is benign — the engine has already advanced
	// past that phase, or the message is a late-arriving accumulation
	// event whose phase has already completed.
	return strings.Contains(err.Error(), "does not consume message type")
}
