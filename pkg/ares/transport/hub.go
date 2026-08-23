// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
)

const (
	// HeartbeatPongWait is how long the server waits for a pong response
	// from the client before considering the connection dead. Must be
	// longer than HeartbeatPingPeriod.
	HeartbeatPongWait = 60 * time.Second

	// HeartbeatPingPeriod is how often the server sends a ping to the
	// client.
	HeartbeatPingPeriod = 40 * time.Second

	// HeartbeatWriteWait is the write deadline on the WebSocket
	// connection. Matches HeartbeatPongWait so a single write has ample
	// time to ride out transient TCP congestion from the client side
	// (Mac event-loop starvation, full receive window).
	HeartbeatWriteWait = 60 * time.Second

	// SendBufferSize is the per-client outbound queue depth. Validated
	// at 256 against the Mac n=6 dim=128 smoke; lower values dropped
	// messages under bursty broadcast.
	SendBufferSize = 256

	// DefaultMaxMessageSize caps inbound WebSocket frame size when the
	// hub is constructed without an explicit limit. 32 MiB accommodates
	// a single ARES collective public-key or eval-key bundle while
	// preventing a single peer from exhausting server memory with one
	// frame. Apps with smaller payloads should set a tighter cap.
	DefaultMaxMessageSize int64 = 32 << 20
)

// WireProtocolVersion is the version emitted by phase.Compose(...)
// (lineage-disabled) pipelines. Existing apps that have not migrated
// to ComposeWith continue speaking version "1".
const WireProtocolVersion = "1"

// WireProtocolVersionLineage is the version emitted by
// phase.ComposeWith(...) pipelines. Frames at this version MUST
// carry a non-nil Lineage field; the hub's strict-mode validator
// (ValidateInboundMessage) rejects v2 frames missing it. SC-10.
const WireProtocolVersionLineage = "2"

// WSMessage is the JSON envelope every WebSocket frame carries. Type and
// SessionID are the dispatch keys; Payload is the app-specific body.
// Version is the wire-format major; empty is treated as "1" for
// backward compatibility with pre-v0.3 clients.
type WSMessage struct {
	Version   string          `json:"version,omitempty"`
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Seq       int64           `json:"seq,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Timestamp string          `json:"timestamp"`

	// Lineage carries the producer's signed DAGNode binding this
	// message's Payload to (SessionID, PhaseID, Role) per SC-10.
	// Required when Version == WireProtocolVersionLineage; ignored
	// when Version is empty or "1" (Compose-built pipelines never
	// set it). The full node rides inline rather than via a
	// separate frame to eliminate ordering windows between payload
	// and commit.
	Lineage *lineage.DAGNode `json:"lineage,omitempty"`
}

// Client is one connected participant. Pseudonym is the auth identity;
// Send is the outbound queue (writePump drains it).
type Client struct {
	Pseudonym string
	Conn      *websocket.Conn
	Send      chan []byte

	// limiter, when non-nil, gates inbound frames to a token-bucket
	// budget. Nil means no per-connection rate limit (the default).
	limiter *rateLimiter
}

// Hub is the WebSocket hub: connect, authenticate, heartbeat, broadcast.
// One Hub serves many concurrent clients. The Hub itself is safe for
// concurrent use; per-client state is owned by readPump and writePump.
type Hub struct {
	mu             sync.RWMutex
	clients        map[string]*Client
	clock          Clock
	auth           *AuthMiddleware
	upgrader       websocket.Upgrader
	maxMessageSize int64
	inboundRate    float64 // frames/sec; 0 disables the per-conn limiter
	inboundBurst   float64 // token-bucket capacity; 0 disables the limiter
	onMsg          func(client *Client, msg WSMessage)
	onClose        func(pseudonym string)

	// seqMu guards seqHigh. Separate from `mu` because the seq tracker
	// is touched on every inbound frame; rolling it into the
	// client-map lock would serialize unrelated traffic.
	seqMu   sync.Mutex
	seqHigh map[string]int64 // key = "session_id|pseudonym|type" -> highest seq accepted
}

// HubOptions tunes the per-hub upgrade and read limits without forcing
// every NewHub caller to pass them.
type HubOptions struct {
	// AllowedOrigins is the whitelist of Origin headers accepted on the
	// WebSocket upgrade handshake. An empty list combined with
	// AllowAnyOrigin=true preserves the historical dev-friendly behavior
	// of accepting any browser origin; production deployments should
	// supply an explicit list (e.g. ["https://fheya.de"]).
	AllowedOrigins []string

	// AllowAnyOrigin keeps the legacy "accept any Origin" behavior.
	// Required when AllowedOrigins is empty.
	AllowAnyOrigin bool

	// MaxMessageSize caps inbound WS frame bytes. Zero means
	// DefaultMaxMessageSize.
	MaxMessageSize int64

	// InboundRate caps the per-connection inbound frame rate, in
	// frames per second, via a token-bucket limiter applied in
	// readPump after JSON parsing. Zero disables the limiter (the
	// historical default).
	InboundRate float64

	// InboundBurst is the token-bucket capacity: the maximum number
	// of consecutive frames a client may send at the head of a
	// burst before being throttled to InboundRate. Zero disables the
	// limiter. A reasonable production default is a small multiple
	// of InboundRate (e.g. rate=10, burst=20).
	InboundBurst float64
}

// NewHub constructs a Hub with permissive defaults. Equivalent to
// NewHubWithOptions(clk, auth, HubOptions{AllowAnyOrigin: true}).
//
// Production deployments should prefer NewHubWithOptions and supply an
// explicit AllowedOrigins list.
func NewHub(clk Clock, auth *AuthMiddleware) *Hub {
	return NewHubWithOptions(clk, auth, HubOptions{AllowAnyOrigin: true})
}

// NewHubWithOptions constructs a Hub with the supplied upgrade/read
// limits. If clk is nil, the real clock is used.
func NewHubWithOptions(clk Clock, auth *AuthMiddleware, opts HubOptions) *Hub {
	if clk == nil {
		clk = RealClock()
	}
	maxMsg := opts.MaxMessageSize
	if maxMsg <= 0 {
		maxMsg = DefaultMaxMessageSize
	}
	allowed := append([]string(nil), opts.AllowedOrigins...)
	allowAny := opts.AllowAnyOrigin
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Non-browser clients (Go/Python WS libraries) often
				// omit Origin entirely. Token auth still gates access.
				return true
			}
			if allowAny && len(allowed) == 0 {
				return true
			}
			for _, a := range allowed {
				if a == origin {
					return true
				}
			}
			return false
		},
	}
	return &Hub{
		clients:        make(map[string]*Client),
		clock:          clk,
		auth:           auth,
		upgrader:       upgrader,
		maxMessageSize: maxMsg,
		inboundRate:    opts.InboundRate,
		inboundBurst:   opts.InboundBurst,
		seqHigh:        make(map[string]int64),
	}
}

// checkAndRecordSeq enforces per-(session, pseudonym, type) monotonic
// sequence numbers. Returns true if msg.Seq is accepted (strictly
// greater than the highest seen, or zero/missing — bypassed). Returns
// false if the frame is a replay or out-of-order.
//
// Empty Seq (zero) is treated as "client doesn't speak the replay
// protocol" and bypasses the check. Apps that want hard enforcement
// should reject Seq=0 in a higher-level handler.
func (h *Hub) checkAndRecordSeq(pseudonym string, msg WSMessage) bool {
	if msg.Seq == 0 {
		return true
	}
	key := msg.SessionID + "|" + pseudonym + "|" + msg.Type
	h.seqMu.Lock()
	defer h.seqMu.Unlock()
	if last, ok := h.seqHigh[key]; ok && msg.Seq <= last {
		return false
	}
	h.seqHigh[key] = msg.Seq
	return true
}

// SetMessageHandler installs the callback invoked for every inbound WS
// frame. Typically the handler dispatches into SessionRunner.HandleMessage.
func (h *Hub) SetMessageHandler(fn func(*Client, WSMessage)) { h.onMsg = fn }

// SetCloseHandler installs the callback invoked when a client disconnects.
func (h *Hub) SetCloseHandler(fn func(string)) { h.onClose = fn }

// HandleWS upgrades an HTTP request to a WebSocket. Authentication is via
// ?pseudonym=...&auth=... query parameters.
func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	pseudonym := r.URL.Query().Get("pseudonym")
	token := r.URL.Query().Get("auth")
	if pseudonym == "" {
		http.Error(w, "missing pseudonym", http.StatusBadRequest)
		return
	}
	if !h.auth.ValidateToken(pseudonym, token) {
		http.Error(w, "invalid auth", http.StatusUnauthorized)
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}

	conn.SetReadLimit(h.maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(HeartbeatPongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(HeartbeatPongWait))
		return nil
	})

	client := &Client{
		Pseudonym: pseudonym,
		Conn:      conn,
		Send:      make(chan []byte, SendBufferSize),
		limiter:   newRateLimiter(h.inboundRate, h.inboundBurst, h.clock.Now()),
	}

	h.mu.Lock()
	h.clients[pseudonym] = client
	h.mu.Unlock()

	go h.writePump(client)
	go h.readPump(client)
}

func (h *Hub) readPump(c *Client) {
	defer func() {
		h.mu.Lock()
		delete(h.clients, c.Pseudonym)
		h.mu.Unlock()
		c.Conn.Close()
		log.Printf("[hub] client removed pseudo=%s", shortID(c.Pseudonym))
		if h.onClose != nil {
			h.onClose(c.Pseudonym)
		}
	}()

	for {
		_, data, err := c.Conn.ReadMessage()
		if err != nil {
			if isTimeout(err) {
				log.Printf("[hub] heartbeat timeout pseudo=%s — client silently dropped",
					shortID(c.Pseudonym))
			}
			return
		}
		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		// Accept v1 (Compose-built pipelines) and v2 (ComposeWith
		// pipelines, SC-10). Empty Version is treated as v1 for
		// backward compat with pre-v0.3 clients. The stricter
		// per-version invariants (v2 requires non-nil Lineage)
		// are checked by ValidateInboundMessage.
		if err := ValidateInboundMessage(msg); err != nil {
			log.Printf("[hub] frame validation pseudo=%s type=%s: %v — frame dropped",
				shortID(c.Pseudonym), msg.Type, err)
			continue
		}
		// Replay protection: per-(session, pseudonym, type) monotonic
		// seq. Empty Seq is bypassed for backward compat.
		if !h.checkAndRecordSeq(c.Pseudonym, msg) {
			log.Printf("[hub] replay drop pseudo=%s session=%s type=%s seq=%d — frame dropped",
				shortID(c.Pseudonym), msg.SessionID, msg.Type, msg.Seq)
			continue
		}
		// Per-connection rate limit: drop the frame on bucket-empty
		// rather than tearing down the connection. A truly hostile
		// client keeps burning network for nothing; legitimate
		// bursts (key publication, big batch broadcast) refill
		// against the InboundRate within seconds.
		if !c.limiter.Allow(h.clock.Now()) {
			log.Printf("[hub] rate-limit drop pseudo=%s session=%s type=%s — frame dropped",
				shortID(c.Pseudonym), msg.SessionID, msg.Type)
			continue
		}
		if h.onMsg != nil {
			h.onMsg(c, msg)
		}
	}
}

func (h *Hub) writePump(c *Client) {
	ping := time.NewTicker(HeartbeatPingPeriod)
	defer func() {
		ping.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case data, ok := <-c.Send:
			if !ok {
				return
			}
			if err := writeWithRetry(c, data); err != nil {
				log.Printf("[hub] writePump exit pseudo=%s err=%v backlog=%d",
					shortID(c.Pseudonym), err, len(c.Send))
				return
			}
		case <-ping.C:
			c.Conn.SetWriteDeadline(time.Now().Add(HeartbeatWriteWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[hub] ping failed pseudo=%s err=%v",
					shortID(c.Pseudonym), err)
				return
			}
		}
	}
}

// writeWithRetry: 3 attempts with 200ms/400ms backoff. Transient TCP
// errors (Mac event-loop starvation) clear within a few hundred ms;
// retrying keeps the client alive rather than killing writePump.
func writeWithRetry(c *Client, data []byte) error {
	backoff := 200 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		c.Conn.SetWriteDeadline(time.Now().Add(HeartbeatWriteWait))
		if err := c.Conn.WriteMessage(websocket.TextMessage, data); err != nil {
			lastErr = err
			if attempt < 2 {
				time.Sleep(backoff)
				backoff *= 2
			}
			continue
		}
		return nil
	}
	return lastErr
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(interface{ Timeout() bool }); ok {
		return netErr.Timeout()
	}
	return false
}

// SendTo enqueues msg for delivery to one pseudonym. Drops (logged) if
// the client's Send queue is full. Returns nil even when the client is
// not connected — sessions tolerate participant churn.
func (h *Hub) SendTo(pseudonym string, msg WSMessage) error {
	msg.Timestamp = h.clock.Now().Format(time.RFC3339Nano)
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	h.mu.RLock()
	client, ok := h.clients[pseudonym]
	h.mu.RUnlock()
	if !ok {
		return nil
	}
	select {
	case client.Send <- data:
	default:
		log.Printf("[hub] SendTo DROP type=%s to=%s session=%s backlog=%d",
			msg.Type, shortID(pseudonym), shortID(msg.SessionID), len(client.Send))
	}
	return nil
}

// Broadcast sends msg to every currently-connected client.
func (h *Hub) Broadcast(msg WSMessage) {
	msg.Timestamp = h.clock.Now().Format(time.RFC3339Nano)
	data, _ := json.Marshal(msg)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, client := range h.clients {
		select {
		case client.Send <- data:
		default:
			log.Printf("[hub] Broadcast DROP type=%s to=%s backlog=%d",
				msg.Type, shortID(client.Pseudonym), len(client.Send))
		}
	}
}

// BroadcastToSession enqueues msg for delivery to each pseudonym in the
// participant list. The SessionID field on msg is overwritten with the
// argument so callers don't have to.
func (h *Hub) BroadcastToSession(sessionID string, pseudonyms []string, msg WSMessage) {
	msg.Timestamp = h.clock.Now().Format(time.RFC3339Nano)
	msg.SessionID = sessionID
	data, _ := json.Marshal(msg)
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, p := range pseudonyms {
		if client, ok := h.clients[p]; ok {
			select {
			case client.Send <- data:
			default:
				log.Printf("[hub] BroadcastToSession DROP type=%s to=%s session=%s backlog=%d",
					msg.Type, shortID(p), shortID(sessionID), len(client.Send))
			}
		} else {
			log.Printf("[hub] BroadcastToSession SKIP type=%s to=%s session=%s reason=not_in_hub",
				msg.Type, shortID(p), shortID(sessionID))
		}
	}
}

// IsConnected reports whether pseudonym currently has a live WebSocket.
func (h *Hub) IsConnected(pseudonym string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.clients[pseudonym]
	return ok
}

// ConnectedCount returns the number of live clients.
func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
