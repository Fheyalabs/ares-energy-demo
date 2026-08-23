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

// Trade is one settled auction, as it appears in the public log.
//
// The winning seat is deliberately NOT serialised. Broadcasting it would
// contradict the property the auction exists to demonstrate: in ARES only
// the winner learns it won. The seat is kept unexported so the relay can
// tell that one tab privately, and every other tab sees a settled trade
// with a price and no name attached.
type Trade struct {
	At       string  `json:"at"`
	Slot     int     `json:"slot"`
	PriceCt  float64 `json:"price_ct"`
	Accepted bool    `json:"accepted"`
	Bidders  int     `json:"bidders"`

	seat int // never marshalled
}

// EpochSize is how many settled trades close an epoch. At that point the
// books are audited in aggregate rather than trade by trade.
const EpochSize = 5

// EpochPhase tracks the aggregate audit.
type EpochPhase string

const (
	EpochOpen  EpochPhase = "open"  // still collecting trades
	EpochReady EpochPhase = "ready" // enough trades; audit can be run
	EpochAudit EpochPhase = "audit" // participants submitting encrypted totals
	EpochDone  EpochPhase = "done"  // aggregate opened
)

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

	// Epoch audit. Totals are encrypted per participant and summed
	// homomorphically; only the sum is ever opened.
	epoch       EpochPhase
	epochKey    []byte
	epochTotals map[string][]byte
	epochNet    float64
	epochOK     bool
	epochOpened bool
}

func NewAuction() *Auction {
	return &Auction{
		Hour:        13,
		phase:       PhaseWaiting,
		peers:       map[string]*Peer{},
		bids:        map[int][]byte{},
		winnerSeat:  -1,
		epoch:       EpochOpen,
		epochTotals: map[string][]byte{},
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
//
// Returns the winning seat so the caller can tell that one buyer,
// privately, that it won. Nobody else is told: the public log carries a
// price and no name.
func (a *Auction) Settle(accepted bool) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.winnerSeat < 0 {
		return -1
	}
	seat := a.winnerSeat
	a.trades = append([]Trade{{
		At:       time.Now().Format("15:04:05"),
		Slot:     a.Hour,
		PriceCt:  a.priceCt,
		Accepted: accepted,
		Bidders:  len(a.bids),
		seat:     seat,
	}}, a.trades...)

	// Each trade in an epoch clears the next delivery slot, so the log
	// reads as a sequence of hours rather than the same one repeatedly.
	a.Hour = (a.Hour + 1) % 24

	trades := a.trades
	a.resetLocked()
	a.trades = trades
	a.phase = PhaseSettled

	if a.epoch == EpochOpen && len(a.trades) >= EpochSize {
		a.epoch = EpochReady
	}
	return seat
}

// OpenEpochAudit publishes a fresh key for the aggregate audit and starts
// collecting encrypted per-participant totals.
func (a *Auction) OpenEpochAudit(key []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.epochKey = key
	a.epochTotals = map[string][]byte{}
	a.epoch = EpochAudit
	a.epochOpened = false
}

// SubmitEpochTotal stores one participant's encrypted net position for the
// epoch. Returns true once every seated tab has submitted.
func (a *Auction) SubmitEpochTotal(id string, ct []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.epoch != EpochAudit {
		return false
	}
	a.epochTotals[id] = ct
	return len(a.epochTotals) >= len(a.peers)
}

// EpochCiphertexts returns the encrypted totals to be summed. Only their
// sum is ever opened; no individual total is decrypted.
func (a *Auction) EpochCiphertexts() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([][]byte, 0, len(a.epochTotals))
	for _, id := range a.order {
		if ct, ok := a.epochTotals[id]; ok {
			out = append(out, ct)
		}
	}
	return out
}

// CloseEpoch records the opened aggregate. net is the sum of every
// participant's signed position: buyers positive, seller negative. The
// books balance when it is zero.
func (a *Auction) CloseEpoch(net float64, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.epochNet = net
	a.epochOK = ok
	a.epochOpened = true
	a.epoch = EpochDone
}

// NewEpoch clears the log and starts collecting again.
func (a *Auction) NewEpoch() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trades = nil
	a.epoch = EpochOpen
	a.epochKey = nil
	a.epochTotals = map[string][]byte{}
	a.epochNet = 0
	a.epochOK = false
	a.epochOpened = false
	a.resetLocked()
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
		"epoch":       a.epoch,
		"epoch_size":  EpochSize,
		"epoch_net":   a.epochNet,
		"epoch_ok":    a.epochOK,
		"epoch_open":  a.epochOpened,
		"epoch_have":  len(a.epochTotals),
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

// PeerAtSeat returns the connection id of the buyer in a seat, so the
// relay can tell exactly one tab that it won.
func (a *Auction) PeerAtSeat(seat int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.Role == RoleBuyer && p.Seat == seat {
			return p.ID
		}
	}
	return ""
}
