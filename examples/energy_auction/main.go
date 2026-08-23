// SPDX-License-Identifier: Apache-2.0

// Command energy_auction runs a browser demo of a sealed-bid energy
// auction: one seller, up to five buyers, one tab each.
//
// Every cryptographic operation happens in a browser tab, in WebAssembly.
// This process is a relay. It holds no keys, performs no encryption or
// decryption, and never sees a bid. The ciphertexts it forwards are
// opaque bytes to it. That property is structural rather than promised:
// there is no crypto library linked into this binary at all.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// The WASM module is served from disk rather than embedded: it is a ~3 MB
// build artifact, gitignored, produced by wasm/build.sh.
//
//go:embed static/index.html
var staticFS embed.FS

var wasmDir *string

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true }, // local demo only
}

// peer wraps one websocket with the single-writer discipline gorilla
// requires: "no more than one goroutine calls the write methods
// concurrently."
//
// Every connection is served by its own goroutine, and any of them can
// trigger a broadcast, so without this lock two goroutines interleave
// frames on the same socket. The client then sees a truncated frame and
// fails to parse it, which surfaces far from here as corrupted key
// material, a failed fusion, or a round that simply never completes.
type peer struct {
	ws  *websocket.Conn
	wmu sync.Mutex
}

func (p *peer) writeJSON(m msg) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return p.ws.WriteJSON(m)
}

type hub struct {
	mu      sync.Mutex
	conns   map[string]*peer
	order   []string
	auction *Auction
	nextID  int
}

// msg is the wire shape. Blob carries base64 ciphertext or key material;
// the relay moves it without looking inside.
type msg struct {
	Type  string   `json:"type"`
	Blob  string   `json:"blob,omitempty"`
	Blobs []string `json:"blobs,omitempty"`
	Bids  []string `json:"bids,omitempty"`
	Seat  int      `json:"seat,omitempty"`
	Price float64  `json:"price_ct,omitempty"`
	Hour  int      `json:"hour,omitempty"`
	KeyID int      `json:"key_id,omitempty"`
	Ok    bool     `json:"ok,omitempty"`
	You   string   `json:"you,omitempty"`
	State any      `json:"state,omitempty"`
	Note  string   `json:"note,omitempty"`
}

func (h *hub) send(id string, m msg) {
	h.mu.Lock()
	c := h.conns[id]
	h.mu.Unlock()
	if c == nil {
		return
	}
	if err := c.writeJSON(m); err != nil {
		log.Printf("send %s: %v", id, err)
	}
}

func (h *hub) broadcast() {
	snap := h.auction.Snapshot()
	h.mu.Lock()
	ids := append([]string(nil), h.order...)
	h.mu.Unlock()
	for _, id := range ids {
		h.send(id, msg{Type: "state", You: id, State: snap})
	}
}

func (h *hub) serveWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.nextID++
	id := "p" + strconv.Itoa(h.nextID)
	p := &peer{ws: c}
	h.conns[id] = p
	h.order = append(h.order, id)
	h.mu.Unlock()

	h.auction.Join(id)
	h.broadcast()

	defer func() {
		h.mu.Lock()
		delete(h.conns, id)
		for i, v := range h.order {
			if v == id {
				h.order = append(h.order[:i], h.order[i+1:]...)
				break
			}
		}
		h.mu.Unlock()
		h.auction.Leave(id)
		_ = c.Close()
		h.broadcast()
	}()

	for {
		var m msg
		if err := c.ReadJSON(&m); err != nil {
			return
		}
		h.handle(id, m)
	}
}

func (h *hub) handle(id string, m msg) {
	switch m.Type {

	// Seller published its public key and relin key. Broadcast the public
	// key to everyone; the relin key goes only to the evaluator, which is
	// all it needs to compute and still cannot decrypt with.
	case "keys":
		h.auction.PublishKeys([]byte(m.Blob), []byte(m.Note))
		h.broadcast()
		kid := h.auction.KeyID()
		for _, pid := range h.peerIDs() {
			h.send(pid, msg{Type: "pubkey", Blob: m.Blob, KeyID: kid})
		}
		if ev := h.auction.Evaluator(); ev != nil {
			h.send(ev.ID, msg{Type: "evalkey", Blob: m.Note})
		}

	// A buyer sealed a bid in its own tab. Once every seat has sealed,
	// hand the whole set to the evaluator.
	case "bid":
		switch h.auction.SubmitBid(id, m.KeyID, []byte(m.Blob)) {
		case BidRejected:
			// Tell the buyer so it re-seals under the current key rather
			// than silently never appearing in the round.
			h.send(id, msg{Type: "bidrejected", KeyID: h.auction.KeyID()})
			h.broadcast()
			return
		case BidStored:
			h.broadcast()
			return
		}
		h.broadcast()
		cts, seats := h.auction.OrderedBids()
		ev := h.auction.Evaluator()
		if ev == nil {
			return
		}
		blobs := make([]string, len(cts))
		for i, ct := range cts {
			blobs[i] = string(ct)
		}
		seatJSON, _ := json.Marshal(seats)
		h.send(ev.ID, msg{Type: "evaluate", Blobs: blobs, Note: string(seatJSON)})

	// The evaluator finished the blind argmax. Masks go to the seller,
	// which is the only party holding a key that can open them.
	//
	// The bid ciphertexts go with them. The seller has to open the winning
	// one to learn the price, and the evaluator cannot pick it out. Being
	// blind is the whole point, so it has no idea which mask won. Sending
	// the set costs nothing the trust model did not already concede: the
	// seller holds the secret key and could open any of them. What the
	// protocol says is that it opens exactly one.
	case "masks":
		blobs := make([][]byte, len(m.Blobs))
		for i, b := range m.Blobs {
			blobs[i] = []byte(b)
		}
		h.auction.SetMasks(blobs)
		if s := h.auction.SellerID(); s != "" {
			cts, seats := h.auction.OrderedBids()
			bids := make([]string, len(cts))
			for i, ct := range cts {
				bids[i] = string(ct)
			}
			seatJSON, _ := json.Marshal(seats)
			h.send(s, msg{Type: "masks", Blobs: m.Blobs, Bids: bids, Note: string(seatJSON)})
		}
		h.broadcast()

	// The seller opened the winning bid and is deciding.
	case "offer":
		h.auction.Offer(m.Seat, m.Price)
		h.broadcast()

	// The seller decided. Only the winning buyer is told it won; every
	// other tab sees a settled trade in the log with no name on it.
	case "settle":
		seat := h.auction.Settle(m.Ok)
		if seat >= 0 && m.Ok {
			if w := h.auction.PeerAtSeat(seat); w != "" {
				h.send(w, msg{Type: "won", Seat: seat, Price: m.Price})
			}
		}
		h.broadcast()

	// ---- epoch audit ------------------------------------------------
	// After EpochSize trades the books are checked in aggregate. Each tab
	// encrypts its own net position for the epoch; a blind peer sums the
	// ciphertexts; the seller opens the sum and nothing else. No
	// individual total, and no individual trade, is ever reopened.

	// The epoch key is generated N-of-N across every tab, so no single
	// party can open a total under it, the seller included. The relay
	// walks the chain one peer at a time.
	case "epochstart":
		if first := h.auction.StartEpochChain(); first != "" {
			h.send(first, msg{Type: "epochchain", Blob: ""})
		}
		h.broadcast()

	case "epochchained":
		next, done := h.auction.AdvanceEpochChain([]byte(m.Blob))
		if !done {
			h.send(next, msg{Type: "epochchain", Blob: m.Blob})
			h.broadcast()
			return
		}
		h.broadcast()
		for _, pid := range h.peerIDs() {
			h.send(pid, msg{Type: "epochkey", Blob: m.Blob})
		}

	case "epochtotal":
		if !h.auction.SubmitEpochTotal(id, []byte(m.Blob)) {
			h.broadcast()
			return
		}
		cts := h.auction.EpochCiphertexts()
		blobs := make([]string, len(cts))
		for i, ct := range cts {
			blobs[i] = string(ct)
		}
		if ev := h.auction.Evaluator(); ev != nil {
			h.send(ev.ID, msg{Type: "epochsum", Blobs: blobs})
		}
		h.broadcast()

	// The blind peer returns the summed ciphertext. Nobody can open it
	// alone: every tab contributes a decryption share.
	case "epochsummed":
		for _, pid := range h.peerIDs() {
			h.send(pid, msg{Type: "epochdecrypt", Blob: m.Blob})
		}

	case "epochpartial":
		if !h.auction.SubmitEpochPartial(id, []byte(m.Blob)) {
			h.broadcast()
			return
		}
		// Every share is in. Hand the whole set to every tab so each one
		// fuses and checks the books for itself, rather than taking one
		// party's word for the result.
		parts := h.auction.EpochPartials()
		blobs := make([]string, len(parts))
		for i, ct := range parts {
			blobs[i] = string(ct)
		}
		for _, pid := range h.peerIDs() {
			h.send(pid, msg{Type: "epochfuse", Blobs: blobs})
		}
		h.broadcast()

	case "epochresult":
		h.auction.CloseEpoch(m.Price, m.Ok)
		h.broadcast()

	// A new epoch has to reset every tab's local ledger, not just the one
	// that pressed the button. Each tab tracks its own net position, so a
	// tab that keeps last epoch's figure reports a total covering two
	// epochs while the others report one, and the audit shows an
	// imbalance exactly equal to the epoch that was left behind.
	case "newepoch":
		h.auction.NewEpoch()
		for _, pid := range h.peerIDs() {
			h.send(pid, msg{Type: "epochreset"})
		}
		h.broadcast()

	case "reset":
		h.auction.Reset()
		h.broadcast()

	case "hour":
		h.auction.SetHour(m.Hour)
		h.broadcast()
	}
}

func (h *hub) peerIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.order...)
}

// wasmMIME labels .wasm responses; browsers refuse to instantiate a module
// served as anything else, and Go's sniffing does not know the type.
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
	wasmDir = flag.String("wasm", "examples/energy_auction/static/wasm",
		"directory holding pool_wasm.js/.wasm")
	flag.Parse()

	h := &hub{conns: map[string]*peer{}, auction: NewAuction()}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.serveWS)
	mux.Handle("/wasm/", http.StripPrefix("/wasm/",
		wasmMIME(http.FileServer(http.Dir(*wasmDir)))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})

	log.Printf("energy auction on http://%s  (relay only, this process holds no keys)", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
