// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sync"
	"time"
)

// MaxBuyers caps the cohort at one seller plus five buyers.
//
// Six is not arbitrary: it is the cohort size ARES validates against, and
// the soft-mask argmax separation decays roughly as 0.5^(n-1), so a wider
// cohort would need a deeper comparator than the browser should carry.
const MaxBuyers = 5

// Role is what a tab is. The first tab to join sells; the rest bid.
type Role string

const (
	RoleSeller Role = "seller"
	RoleBuyer  Role = "buyer"
	RoleFull   Role = "full" // cohort is complete; this tab only observes
)

// Phase is where the auction has got to. It advances in one direction.
type Phase string

const (
	PhaseWaiting    Phase = "waiting"    // cohort still forming
	PhaseBidding    Phase = "bidding"    // buyers sealing bids in their own tabs
	PhaseEvaluating Phase = "evaluating" // a keyless peer is running the argmax
	PhaseOffer      Phase = "offer"      // seller has the winning price, deciding
	PhaseSettled    Phase = "settled"    // accepted or declined; result is logged
)

// Peer is one connected tab.
type Peer struct {
	ID     string `json:"id"`
	Role   Role   `json:"role"`
	Seat   int    `json:"seat"`   // buyer seat 0..4; -1 for the seller
	Sealed bool   `json:"sealed"` // has submitted a bid ciphertext
}

// Trade is one settled auction, for the log.
type Trade struct {
	At       string  `json:"at"`
	Hour     int     `json:"hour"`
	PriceCt  float64 `json:"price_ct"`
	Seat     int     `json:"seat"`
	Accepted bool    `json:"accepted"`
	Bidders  int     `json:"bidders"`
}

// Auction is the whole demo state. The server holds ciphertexts and
// routes them; it holds no key material and performs no cryptography.
type Auction struct {
	mu sync.Mutex

	Hour  int
	phase Phase
	peers map[string]*Peer
	order []string

	// Relayed crypto material. Opaque bytes to this process.
	pubKey  []byte // seller's public key, broadcast to buyers
	evalKey []byte // relin key, sent only to the evaluator
	bids    map[int][]byte
	masks   [][]byte

	// Outcome of the current round.
	winnerSeat int
	priceCt    float64

	trades []Trade
}

func NewAuction() *Auction {
	return &Auction{
		Hour:       13,
		phase:      PhaseWaiting,
		peers:      map[string]*Peer{},
		bids:       map[int][]byte{},
		winnerSeat: -1,
	}
}

// Join seats a tab. The first becomes the seller; the next five bid.
func (a *Auction) Join(id string) *Peer {
	a.mu.Lock()
	defer a.mu.Unlock()

	p := &Peer{ID: id, Seat: -1}
	switch {
	case a.seller() == nil:
		p.Role = RoleSeller
	case a.buyerCount() < MaxBuyers:
		p.Role = RoleBuyer
		p.Seat = a.buyerCount()
	default:
		p.Role = RoleFull
	}
	a.peers[id] = p
	a.order = append(a.order, id)
	return p
}

func (a *Auction) Leave(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.peers[id]
	delete(a.peers, id)
	for i, v := range a.order {
		if v == id {
			a.order = append(a.order[:i], a.order[i+1:]...)
			break
		}
	}
	// Losing the seller or a bidder mid-round invalidates it: the key
	// material and the ciphertexts under it are gone.
	if p != nil && (p.Role == RoleSeller || p.Sealed) {
		a.resetLocked()
	}
}

func (a *Auction) seller() *Peer {
	for _, p := range a.peers {
		if p.Role == RoleSeller {
			return p
		}
	}
	return nil
}

func (a *Auction) buyerCount() int {
	n := 0
	for _, p := range a.peers {
		if p.Role == RoleBuyer {
			n++
		}
	}
	return n
}

// Evaluator returns the peer that runs the argmax: a buyer, chosen
// because buyers hold no secret key and therefore cannot read the
// ciphertexts they are computing on.
func (a *Auction) Evaluator() *Peer {
	for _, id := range a.order {
		if p, ok := a.peers[id]; ok && p.Role == RoleBuyer {
			return p
		}
	}
	return nil
}

func (a *Auction) resetLocked() {
	a.phase = PhaseWaiting
	a.pubKey = nil
	a.evalKey = nil
	a.bids = map[int][]byte{}
	a.masks = nil
	a.winnerSeat = -1
	a.priceCt = 0
	for _, p := range a.peers {
		p.Sealed = false
	}
}

func (a *Auction) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resetLocked()
}

func (a *Auction) SetHour(h int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Hour = ((h % 24) + 24) % 24
	a.resetLocked()
}

// PublishKeys records the seller's public key and relin key and opens
// bidding.
func (a *Auction) PublishKeys(pk, ek []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pubKey, a.evalKey = pk, ek
	a.bids = map[int][]byte{}
	a.masks = nil
	a.winnerSeat = -1
	for _, p := range a.peers {
		p.Sealed = false
	}
	a.phase = PhaseBidding
}

// SubmitBid stores one buyer's ciphertext. Returns true once every seated
// buyer has sealed, which is when evaluation can begin.
func (a *Auction) SubmitBid(id string, ct []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.peers[id]
	if !ok || p.Role != RoleBuyer || a.phase != PhaseBidding {
		return false
	}
	a.bids[p.Seat] = ct
	p.Sealed = true
	if len(a.bids) < a.buyerCount() || a.buyerCount() == 0 {
		return false
	}
	a.phase = PhaseEvaluating
	return true
}

// OrderedBids returns the sealed ciphertexts by seat, which is the order
// the mask vector will come back in.
func (a *Auction) OrderedBids() ([][]byte, []int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var cts [][]byte
	var seats []int
	for seat := 0; seat < MaxBuyers; seat++ {
		if ct, ok := a.bids[seat]; ok {
			cts = append(cts, ct)
			seats = append(seats, seat)
		}
	}
	return cts, seats
}

func (a *Auction) SetMasks(masks [][]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.masks = masks
	a.phase = PhaseOffer
}

// Offer records what the seller opened: the winning seat and its price.
func (a *Auction) Offer(seat int, price float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.winnerSeat = seat
	a.priceCt = price
	a.phase = PhaseOffer
}

// Settle logs the seller's decision and ends the round.
func (a *Auction) Settle(accepted bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.winnerSeat < 0 {
		return
	}
	a.trades = append([]Trade{{
		At:       time.Now().Format("15:04:05"),
		Hour:     a.Hour,
		PriceCt:  a.priceCt,
		Seat:     a.winnerSeat,
		Accepted: accepted,
		Bidders:  len(a.bids),
	}}, a.trades...)
	if len(a.trades) > 8 {
		a.trades = a.trades[:8]
	}

	// Clear the round's crypto state as part of settling rather than
	// waiting for an explicit reset. The keys and ciphertexts belong to
	// the round that just ended; leaving them in place invites a second
	// round to run against stale material. The trade log survives.
	trades := a.trades
	a.resetLocked()
	a.trades = trades
	a.phase = PhaseSettled
}

// Snapshot is what every tab renders from. Ciphertexts are deliberately
// absent: they are routed point-to-point, not broadcast in state.
func (a *Auction) Snapshot() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()

	peers := make([]*Peer, 0, len(a.order))
	for _, id := range a.order {
		if p, ok := a.peers[id]; ok {
			peers = append(peers, p)
		}
	}
	ev := ""
	if p := a.evaluatorLocked(); p != nil {
		ev = p.ID
	}
	return map[string]any{
		"hour":        a.Hour,
		"band":        BandAt(a.Hour),
		"phase":       a.phase,
		"peers":       peers,
		"buyers":      a.buyerCount(),
		"max_buyers":  MaxBuyers,
		"sealed":      len(a.bids),
		"evaluator":   ev,
		"winner_seat": a.winnerSeat,
		"price_ct":    a.priceCt,
		"trades":      a.trades,
		"has_keys":    len(a.pubKey) > 0,
	}
}

func (a *Auction) evaluatorLocked() *Peer {
	for _, id := range a.order {
		if p, ok := a.peers[id]; ok && p.Role == RoleBuyer {
			return p
		}
	}
	return nil
}

func (a *Auction) String() string {
	return fmt.Sprintf("auction(hour=%d phase=%s buyers=%d)", a.Hour, a.phase, a.buyerCount())
}

// SellerID returns the seller's connection id, or "" if none is seated.
func (a *Auction) SellerID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p := a.seller(); p != nil {
		return p.ID
	}
	return ""
}
