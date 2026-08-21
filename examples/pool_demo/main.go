// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// The WASM module is served from disk rather than embedded: it is a 2.7 MB
// build artifact, kept out of git (see .gitignore) and rebuilt by
// wasm/build.sh.
//
//go:embed static/index.html
var staticFS embed.FS

var wasmDir *string

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true }, // local demo only
}

type hub struct {
	mu      sync.Mutex
	conns   map[*websocket.Conn]string // conn -> participant id
	session *Session
	nextID  int
}

func (h *hub) broadcast() {
	snap := h.session.Snapshot()
	h.mu.Lock()
	defer h.mu.Unlock()
	for c, id := range h.conns {
		payload := map[string]any{"type": "state", "you": id, "state": snap}
		if err := c.WriteJSON(payload); err != nil {
			_ = c.Close()
			delete(h.conns, c)
		}
	}
}

func (h *hub) sendErr(c *websocket.Conn, msg string) {
	_ = c.WriteJSON(map[string]any{"type": "error", "message": msg})
}

func (h *hub) serveWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.nextID++
	id := "p" + strconv.Itoa(h.nextID)
	h.conns[c] = id
	h.mu.Unlock()

	h.session.Join(id)
	h.broadcast()

	defer func() {
		h.mu.Lock()
		delete(h.conns, c)
		h.mu.Unlock()
		h.session.Leave(id)
		_ = c.Close()
		h.broadcast()
	}()

	for {
		var msg struct {
			Type     string  `json:"type"`
			Side     string  `json:"side"`
			PriceCt  float64 `json:"price_ct"`
			Quantity float64 `json:"quantity_kwh"`
			Hour     int     `json:"hour"`
		}
		if err := c.ReadJSON(&msg); err != nil {
			return
		}
		switch msg.Type {
		case "side":
			side := SideSeller
			if msg.Side == "buyer" {
				side = SideBuyer
			}
			h.session.Update(id, func(p *Participant) {
				p.Side = side
				p.Submitted = false
			})
			h.broadcast()

		case "offer":
			h.session.Update(id, func(p *Participant) {
				p.PriceCt = msg.PriceCt
				p.QuantityKWh = msg.Quantity
				p.Submitted = true
			})
			h.broadcast()

		case "withdraw":
			h.session.Update(id, func(p *Participant) { p.Submitted = false })
			h.broadcast()

		case "hour":
			h.session.SetHour(msg.Hour)
			h.broadcast()

		case "clear":
			go func() {
				if _, err := h.session.RunClearing(); err != nil {
					h.sendErr(c, err.Error())
					log.Printf("clearing: %v", err)
				}
				h.broadcast()
			}()
		}
	}
}

// wasmMIME labels .wasm responses so the browser will instantiate them.
func wasmMIME(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	addr := flag.String("addr", "localhost:8080", "listen address")
	wasmDir = flag.String("wasm", "examples/pool_demo/static/wasm", "directory holding pool_wasm.js/.wasm")
	flag.Parse()

	h := &hub{conns: map[*websocket.Conn]string{}, session: NewSession()}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.serveWS)

	// Serve the WASM module so every tab can run its own FHE. Go's
	// default content sniffing does not know application/wasm, and
	// browsers refuse to instantiate a module served as anything else.
	mux.Handle("/wasm/", http.StripPrefix("/wasm/",
		wasmMIME(http.FileServer(http.Dir(*wasmDir)))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	log.Printf("pool demo on http://%s  (client encryption: %s)", *addr, ClientEncryption)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
