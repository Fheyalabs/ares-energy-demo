// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// wsServer stands up the hub on an httptest server and returns a
// connected client. Caller defers teardown.
func wsServer(t *testing.T, hub *Hub, pseudonym, token string) (*websocket.Conn, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	q := u.Query()
	q.Set("pseudonym", pseudonym)
	q.Set("auth", token)
	u.RawQuery = q.Encode()
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial: %v", err)
	}
	return conn, func() {
		conn.Close()
		srv.Close()
	}
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s", timeout)
}

func TestHub_ConnectAndReceiveBroadcast(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	conn, teardown := wsServer(t, hub, "alice", "")
	defer teardown()

	waitFor(t, func() bool { return hub.IsConnected("alice") }, 2*time.Second)

	hub.Broadcast(WSMessage{Type: "hello", Payload: json.RawMessage(`"world"`)})

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	var got WSMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != "hello" {
		t.Errorf("got Type=%q, want hello", got.Type)
	}
}

func TestHub_DispatchInboundMessage(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})

	var (
		mu   sync.Mutex
		seen WSMessage
		got  bool
	)
	hub.SetMessageHandler(func(_ *Client, msg WSMessage) {
		mu.Lock()
		seen = msg
		got = true
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "bob", "")
	defer teardown()

	waitFor(t, func() bool { return hub.IsConnected("bob") }, 2*time.Second)

	payload := WSMessage{Type: "ride.bid", SessionID: "S1", Payload: json.RawMessage(`{"price":99}`)}
	body, _ := json.Marshal(payload)
	if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return got }, 2*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if seen.Type != "ride.bid" || seen.SessionID != "S1" {
		t.Errorf("dispatch saw type=%q session=%q", seen.Type, seen.SessionID)
	}
}

// TestHub_DropsReplayedSeq verifies per-(session, pseudonym, type)
// monotonic sequence enforcement: a frame whose Seq is <= the
// highest accepted for the same tuple is silently dropped at the
// hub before reaching the message handler.
func TestHub_DropsReplayedSeq(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})

	var (
		mu   sync.Mutex
		seen []int64
	)
	hub.SetMessageHandler(func(_ *Client, msg WSMessage) {
		mu.Lock()
		seen = append(seen, msg.Seq)
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "dave", "")
	defer teardown()
	waitFor(t, func() bool { return hub.IsConnected("dave") }, 2*time.Second)

	send := func(seq int64) {
		body, _ := json.Marshal(WSMessage{Type: "ride.bid", SessionID: "S1", Seq: seq})
		if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
			t.Fatalf("WriteMessage seq=%d: %v", seq, err)
		}
	}

	send(1)
	send(2)
	send(2) // replay: same seq as previous
	send(1) // replay: lower than highest
	send(3)

	// Wait until at least three legitimate frames arrived. Replayed
	// frames must not appear.
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) >= 3 }, 2*time.Second)
	time.Sleep(100 * time.Millisecond) // give any spurious frames a chance to land

	mu.Lock()
	defer mu.Unlock()
	if got, want := seen, []int64{1, 2, 3}; !equalSeqs(got, want) {
		t.Errorf("handler saw seqs %v, want %v", got, want)
	}
}

// TestHub_AllowsRepeatedSeqAcrossTypes verifies the seq scope is
// per-(session, pseudonym, TYPE): seq=1 on type=A and seq=1 on type=B
// are both accepted because they don't share a tracker key.
func TestHub_AllowsRepeatedSeqAcrossTypes(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})

	var (
		mu   sync.Mutex
		seen []string
	)
	hub.SetMessageHandler(func(_ *Client, msg WSMessage) {
		mu.Lock()
		seen = append(seen, msg.Type)
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "erin", "")
	defer teardown()
	waitFor(t, func() bool { return hub.IsConnected("erin") }, 2*time.Second)

	send := func(typ string, seq int64) {
		body, _ := json.Marshal(WSMessage{Type: typ, SessionID: "S1", Seq: seq})
		if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
			t.Fatalf("WriteMessage type=%s seq=%d: %v", typ, seq, err)
		}
	}

	send("ride.bid", 1)
	send("ride.decrypt.partial", 1) // different type, same seq — allowed

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(seen) >= 2 }, 2*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Errorf("handler saw %v, want exactly 2 distinct-type frames", seen)
	}
}

// TestHub_AllowsSeqZero verifies the backward-compat bypass: clients
// that don't set Seq (or set it to 0) skip the replay check.
func TestHub_AllowsSeqZero(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})

	var (
		mu  sync.Mutex
		got int
	)
	hub.SetMessageHandler(func(_ *Client, _ WSMessage) {
		mu.Lock()
		got++
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "frank", "")
	defer teardown()
	waitFor(t, func() bool { return hub.IsConnected("frank") }, 2*time.Second)

	body, _ := json.Marshal(WSMessage{Type: "ride.bid", SessionID: "S1"}) // Seq omitted
	for i := 0; i < 3; i++ {
		if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
	}

	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return got >= 3 }, 2*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if got != 3 {
		t.Errorf("handler saw %d frames, want 3 (Seq=0 must bypass replay check)", got)
	}
}

func equalSeqs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHub_DropsMismatchedWireVersion(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})

	var (
		mu  sync.Mutex
		got bool
	)
	hub.SetMessageHandler(func(_ *Client, _ WSMessage) {
		mu.Lock()
		got = true
		mu.Unlock()
	})

	conn, teardown := wsServer(t, hub, "carol", "")
	defer teardown()

	waitFor(t, func() bool { return hub.IsConnected("carol") }, 2*time.Second)

	// Send a frame with a bogus wire version. The hub should drop it
	// silently (log a warning) and never invoke the message handler.
	payload := WSMessage{Version: "99", Type: "ride.bid", SessionID: "S1"}
	body, _ := json.Marshal(payload)
	if err := conn.WriteMessage(websocket.TextMessage, body); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	// Wait a beat to make sure the hub had a chance to process — and
	// then verify the handler was NOT invoked.
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if got {
		t.Errorf("expected handler not to be invoked for wire-version-mismatched frame")
	}
}

func TestHub_RejectsUnauthorized(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{
		Secret:         []byte("real-secret"),
		AllowDevBypass: false,
	})
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	u.Scheme = "ws"
	q := u.Query()
	q.Set("pseudonym", "mallory")
	q.Set("auth", "wrong-token")
	u.RawQuery = q.Encode()

	_, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err == nil {
		t.Fatalf("expected dial to fail")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %v", resp)
	}
	if !strings.Contains(err.Error(), "bad handshake") && !strings.Contains(err.Error(), "401") {
		t.Errorf("unexpected dial error: %v", err)
	}
}

func TestHub_SendToDisconnectedReturnsNil(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	err := hub.SendTo("ghost", WSMessage{Type: "x"})
	if err != nil {
		t.Errorf("SendTo to disconnected pseudonym returned err=%v, want nil", err)
	}
}

func TestHub_BroadcastToSessionRoutesByPseudonym(t *testing.T) {
	hub := NewHub(RealClock(), &AuthMiddleware{AllowDevBypass: true})
	aConn, aDown := wsServer(t, hub, "a", "")
	defer aDown()
	bConn, bDown := wsServer(t, hub, "b", "")
	defer bDown()
	cConn, cDown := wsServer(t, hub, "c", "")
	defer cDown()

	waitFor(t, func() bool { return hub.ConnectedCount() == 3 }, 2*time.Second)

	hub.BroadcastToSession("S2", []string{"a", "b"}, WSMessage{Type: "session.start"})

	// a and b should each receive one frame; c should time out.
	for _, conn := range []*websocket.Conn{aConn, bConn} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("expected message, got err=%v", err)
		}
	}
	cConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := cConn.ReadMessage()
	if err == nil {
		t.Errorf("c received a message it should not have")
	}
}
