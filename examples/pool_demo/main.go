// SPDX-License-Identifier: Apache-2.0

package main

import (
	"embed"
	"flag"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
)

//go:embed static/index.html
var staticFS embed.FS

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

func main() {
	addr := flag.String("addr", "localhost:8080", "listen address")
	flag.Parse()

	h := &hub{conns: map[*websocket.Conn]string{}, session: NewSession()}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.serveWS)
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
