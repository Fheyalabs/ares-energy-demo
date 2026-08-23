// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
	"github.com/gorilla/websocket"
)

// twoStatePhase consumes "advance" messages and transitions when one
// arrives. Used to exercise the end-to-end dispatch path from a WS
// frame through Service into SessionRunner.HandleMessage.
type twoStatePhase struct {
	name      string
	entry     phase.SessionState
	exit      phase.SessionState
	consumes  []string
	mu        sync.Mutex
	gotMsgsFn func()
}

func (p *twoStatePhase) Name() string                         { return p.name }
func (p *twoStatePhase) Lifetime() phase.Lifetime             { return phase.LifetimePerSession }
func (p *twoStatePhase) RunsAt() phase.RunsAt                 { return phase.RunsAtInline }
func (p *twoStatePhase) EntryState() phase.SessionState       { return p.entry }
func (p *twoStatePhase) ExitState() phase.SessionState        { return p.exit }
func (p *twoStatePhase) InternalStates() []phase.SessionState { return nil }
func (p *twoStatePhase) ConsumedMessageTypes() []string       { return p.consumes }
func (p *twoStatePhase) Requires() phase.ContextSchema        { return nil }
func (p *twoStatePhase) Provides() phase.ContextSchema        { return nil }
func (p *twoStatePhase) Enter(*phase.SessionContext) error    { return nil }
func (p *twoStatePhase) OnMessage(*phase.SessionContext, string, string, []byte) error {
	p.mu.Lock()
	if p.gotMsgsFn != nil {
		p.gotMsgsFn()
	}
	p.mu.Unlock()
	return nil
}
func (p *twoStatePhase) CheckComplete(*phase.SessionContext) bool { return true }
func (p *twoStatePhase) Exit(*phase.SessionContext) error         { return nil }

func newDispatchRunner(t *testing.T, gotMsg func()) *phase.SessionRunner {
	t.Helper()
	first := &twoStatePhase{
		name:     "first",
		entry:    "FIRST",
		exit:     "SECOND",
		consumes: []string{"advance"},
		gotMsgsFn: gotMsg,
	}
	// `second` declares a consumed type to stop the runner's cascade
	// behavior at this state (without a consumed type, CheckComplete=
	// true would auto-advance through this phase too).
	second := &twoStatePhase{
		name:     "second",
		entry:    "SECOND",
		exit:     phase.StateNone,
		consumes: []string{"finalize"},
	}
	r, err := phase.Compose(first, second)
	if err != nil {
		t.Fatalf("NewSessionRunner: %v", err)
	}
	return r
}

// freePort picks an available TCP port for the test service.
func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestService_EndToEnd_AdminStartAndDispatch(t *testing.T) {
	var (
		mu     sync.Mutex
		seen   int
	)
	runner := newDispatchRunner(t, func() { mu.Lock(); seen++; mu.Unlock() })

	addr := freePort(t)
	svc, err := NewService(Config{
		Addr:           addr,
		ServiceName:    "test-service",
		AllowDevBypass: true,
		Runner:         runner,
		InviteType:     "test.invite",
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()

	// Wait for the listener to come up.
	waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

	// Dial WS so the participant is connected before BeginSession.
	wsURL := url.URL{Scheme: "ws", Host: addr, Path: "/v2/ws"}
	q := wsURL.Query()
	q.Set("pseudonym", "p-alpha")
	wsURL.RawQuery = q.Encode()
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer wsConn.Close()

	waitFor(t, func() bool { return svc.Hub().IsConnected("p-alpha") }, 2*time.Second)

	// POST /admin/sessions to start a session.
	body, _ := json.Marshal(sessionStartRequest{
		SessionID:    "S-1",
		Participants: []string{"p-alpha"},
	})
	resp, err := http.Post("http://"+addr+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// Drain the invite frame.
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := wsConn.ReadMessage(); err != nil {
		t.Fatalf("expected invite, got err=%v", err)
	}

	// Send an "advance" message via WS. The dispatch path should
	// land it in SessionRunner.HandleMessage → phase OnMessage.
	frame := WSMessage{
		Type:      "advance",
		SessionID: "S-1",
	}
	frameBody, _ := json.Marshal(frame)
	if err := wsConn.WriteMessage(websocket.TextMessage, frameBody); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return seen >= 1 }, 2*time.Second)

	// GET /admin/sessions/{id} should now report state=SECOND.
	r, err := http.Get("http://" + addr + "/admin/sessions/S-1")
	if err != nil {
		t.Fatalf("GET session: %v", err)
	}
	defer r.Body.Close()
	var sr sessionStartResponse
	_ = json.NewDecoder(r.Body).Decode(&sr)
	if sr.State != "SECOND" {
		t.Errorf("session state = %q, want SECOND", sr.State)
	}
}

func TestService_RejectsMissingAddr(t *testing.T) {
	_, err := NewService(Config{AllowDevBypass: true, Runner: newDispatchRunner(t, nil)})
	if err == nil {
		t.Errorf("expected NewService to require Addr")
	}
}

func TestService_RejectsEmptySecretWithoutBypass(t *testing.T) {
	_, err := NewService(Config{
		Addr:   ":9999",
		Runner: newDispatchRunner(t, nil),
	})
	if err == nil {
		t.Errorf("expected NewService to reject empty Secret without AllowDevBypass")
	}
}

// TestService_RefusesDevBypassInProduction verifies the production
// env guard: ARES_ENV=production + AllowDevBypass=true is a hard
// configuration error.
func TestService_RefusesDevBypassInProduction(t *testing.T) {
	t.Setenv("ARES_ENV", "production")
	_, err := NewService(Config{
		Addr:           ":9999",
		Runner:         newDispatchRunner(t, nil),
		AllowDevBypass: true,
	})
	if err == nil {
		t.Fatalf("expected NewService to reject AllowDevBypass=true under ARES_ENV=production")
	}
	if !strings.Contains(err.Error(), "ARES_ENV=production") {
		t.Errorf("expected error to mention ARES_ENV=production, got: %v", err)
	}
}

func TestService_ArtifactPutGet(t *testing.T) {
	runner := newDispatchRunner(t, nil)
	addr := freePort(t)
	svc, err := NewService(Config{
		Addr:           addr,
		AllowDevBypass: true,
		Runner:         runner,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.Run(ctx)
	waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

	// PUT artifact.
	req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/v2/artifacts/blob-1", bytes.NewReader([]byte("hello")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT status = %d", resp.StatusCode)
	}

	// GET it back.
	r, err := http.Get("http://" + addr + "/v2/artifacts/blob-1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer r.Body.Close()
	buf := make([]byte, 64)
	n, _ := r.Body.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Errorf("artifact body = %q, want hello", buf[:n])
	}
}

func waitForHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("HTTP %s did not become reachable within %s", url, timeout)
}

// TestService_PostDispatchHook_CalledAfterDispatch verifies that
// Config.PostDispatchHook fires after every dispatched WS frame with the
// originating client and message. The test sends one "advance" frame and
// asserts the hook recorded matching session_id and type fields.
func TestService_PostDispatchHook_CalledAfterDispatch(t *testing.T) {
	type hookCall struct {
		pseudonym string
		sessionID string
		msgType   string
		dispErr   error
	}
	var (
		mu    sync.Mutex
		calls []hookCall
	)

	runner := newDispatchRunner(t, nil)
	addr := freePort(t)
	svc, err := NewService(Config{
		Addr:           addr,
		ServiceName:    "hook-test",
		AllowDevBypass: true,
		Runner:         runner,
		InviteType:     "hook.invite",
		PostDispatchHook: func(c *Client, msg WSMessage, dispatchErr error) {
			mu.Lock()
			calls = append(calls, hookCall{
				pseudonym: c.Pseudonym,
				sessionID: msg.SessionID,
				msgType:   msg.Type,
				dispErr:   dispatchErr,
			})
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go svc.Run(ctx)
	waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

	wsURL := url.URL{Scheme: "ws", Host: addr, Path: "/v2/ws"}
	q := wsURL.Query()
	q.Set("pseudonym", "hook-peer")
	wsURL.RawQuery = q.Encode()
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer wsConn.Close()
	waitFor(t, func() bool { return svc.Hub().IsConnected("hook-peer") }, 2*time.Second)

	// Start a session.
	body, _ := json.Marshal(sessionStartRequest{
		SessionID:    "hook-s1",
		Participants: []string{"hook-peer"},
	})
	resp, err := http.Post("http://"+addr+"/admin/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST sessions: %v", err)
	}
	resp.Body.Close()

	// Drain the invite frame (it also fires the hook with type "hook.invite").
	wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	wsConn.ReadMessage() //nolint:errcheck

	// Send an "advance" frame — this is the one the hook must record.
	frame := WSMessage{Type: "advance", SessionID: "hook-s1"}
	raw, _ := json.Marshal(frame)
	if err := wsConn.WriteMessage(websocket.TextMessage, raw); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range calls {
			if c.msgType == "advance" {
				return true
			}
		}
		return false
	}, 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	var found *hookCall
	for i := range calls {
		if calls[i].msgType == "advance" {
			found = &calls[i]
			break
		}
	}
	if found == nil {
		t.Fatal("PostDispatchHook: no call recorded for 'advance' frame")
	}
	if found.pseudonym != "hook-peer" {
		t.Errorf("hook client.Pseudonym = %q, want hook-peer", found.pseudonym)
	}
	if found.sessionID != "hook-s1" {
		t.Errorf("hook msg.SessionID = %q, want hook-s1", found.sessionID)
	}
}

// TestService_V2FrameRoutesThroughLineage verifies that a v2 WS frame
// (Version="2", Lineage!=nil) is dispatched via HandleLineageMessage and
// reaches Phase.OnMessage after lineage verification, while a v1 frame
// (no Lineage) is routed through the plain HandleMessage path.
//
// The two paths are verified in independent sub-tests to avoid session-state
// collision: once a twoStatePhase's CheckComplete returns true the session
// advances to StateNone and the current phase pointer becomes nil — a second
// frame to the same session would panic. Each sub-test owns its own runner
// and service.
//
// This test exercises the msg.Lineage != nil branch inside the service's
// SetMessageHandler closure using a full WS round-trip — the same seam
// used by TestService_EndToEnd_AdminStartAndDispatch — since that closure
// is the only place the branch lives.
func TestService_V2FrameRoutesThroughLineage(t *testing.T) {
	t.Run("v1_plain_HandleMessage", func(t *testing.T) {
		signer, _ := sign.NewEd25519Signer()
		peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
		store := lineage.NewInMemoryStore()

		var (
			mu      sync.Mutex
			hookSaw bool
		)
		runner, _ := phase.ComposeWith(
			[]phase.Phase{&twoStatePhase{
				name:     "ltest",
				entry:    "FIRST",
				exit:     phase.StateNone,
				consumes: []string{"v1.frame"},
			}},
			phase.WithSigner(signer),
			phase.WithStore(store),
			phase.WithPeerVerifiers(peers),
		)
		addr := freePort(t)
		svc, err := NewService(Config{
			Addr:           addr,
			ServiceName:    "ltest-v1",
			AllowDevBypass: true,
			Runner:         runner,
			InviteType:     "ltest.invite",
			PostDispatchHook: func(c *Client, msg WSMessage, _ error) {
				if msg.Lineage == nil && msg.Type == "v1.frame" {
					mu.Lock()
					hookSaw = true
					mu.Unlock()
				}
			},
		})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go svc.Run(ctx)
		waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

		wsURL := url.URL{Scheme: "ws", Host: addr, Path: "/v2/ws"}
		q := wsURL.Query()
		q.Set("pseudonym", "v1-peer")
		wsURL.RawQuery = q.Encode()
		wsConn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer wsConn.Close()
		waitFor(t, func() bool { return svc.Hub().IsConnected("v1-peer") }, 2*time.Second)

		body, _ := json.Marshal(sessionStartRequest{SessionID: "v1-s1", Participants: []string{"v1-peer"}})
		resp, err := http.Post("http://"+addr+"/admin/sessions", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST sessions: %v", err)
		}
		resp.Body.Close()
		wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		wsConn.ReadMessage() //nolint:errcheck // drain invite

		raw, _ := json.Marshal(WSMessage{
			Version: WireProtocolVersion, Type: "v1.frame", SessionID: "v1-s1",
			Payload: json.RawMessage(`"hello"`),
		})
		if err := wsConn.WriteMessage(websocket.TextMessage, raw); err != nil {
			t.Fatalf("write: %v", err)
		}
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return hookSaw }, 2*time.Second)
		mu.Lock()
		if !hookSaw {
			t.Error("v1 frame: PostDispatchHook not fired with nil Lineage")
		}
		mu.Unlock()
	})

	t.Run("v2_lineage_HandleLineageMessage", func(t *testing.T) {
		signer, _ := sign.NewEd25519Signer()
		peers := map[string]sign.Signer{sign.Ed25519Algorithm: signer}
		store := lineage.NewInMemoryStore()

		var (
			mu      sync.Mutex
			hookSaw bool
		)
		runner, _ := phase.ComposeWith(
			[]phase.Phase{&twoStatePhase{
				name:     "ltest",
				entry:    "FIRST",
				exit:     phase.StateNone,
				consumes: []string{"v2.frame"},
			}},
			phase.WithSigner(signer),
			phase.WithStore(store),
			phase.WithPeerVerifiers(peers),
		)
		addr := freePort(t)
		svc, err := NewService(Config{
			Addr:           addr,
			ServiceName:    "ltest-v2",
			AllowDevBypass: true,
			Runner:         runner,
			InviteType:     "ltest.invite",
			PostDispatchHook: func(c *Client, msg WSMessage, dispErr error) {
				// dispErr may be non-nil if the phase already completed;
				// we only care that the hook fired with a non-nil Lineage.
				if msg.Lineage != nil && msg.Type == "v2.frame" {
					mu.Lock()
					hookSaw = true
					mu.Unlock()
				}
			},
		})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go svc.Run(ctx)
		waitForHTTP(t, "http://"+addr+"/admin/health", 2*time.Second)

		wsURL := url.URL{Scheme: "ws", Host: addr, Path: "/v2/ws"}
		q := wsURL.Query()
		q.Set("pseudonym", "v2-peer")
		wsURL.RawQuery = q.Encode()
		wsConn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer wsConn.Close()
		waitFor(t, func() bool { return svc.Hub().IsConnected("v2-peer") }, 2*time.Second)

		body, _ := json.Marshal(sessionStartRequest{SessionID: "v2-s1", Participants: []string{"v2-peer"}})
		resp, err := http.Post("http://"+addr+"/admin/sessions", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST sessions: %v", err)
		}
		resp.Body.Close()
		wsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		wsConn.ReadMessage() //nolint:errcheck // drain invite

		payload := []byte(`"hello-v2"`)
		node, nodeErr := lineage.Commit("v2-s1", "ltest", "test-role", payload, nil, signer)
		if nodeErr != nil {
			t.Fatalf("lineage.Commit: %v", nodeErr)
		}
		raw, _ := json.Marshal(WSMessage{
			Version:   WireProtocolVersionLineage,
			Type:      "v2.frame",
			SessionID: "v2-s1",
			Payload:   json.RawMessage(payload),
			Lineage:   &node,
		})
		if err := wsConn.WriteMessage(websocket.TextMessage, raw); err != nil {
			t.Fatalf("write: %v", err)
		}
		waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return hookSaw }, 2*time.Second)
		mu.Lock()
		if !hookSaw {
			t.Error("v2 frame: PostDispatchHook not fired with non-nil Lineage")
		}
		mu.Unlock()
	})

}
