// SPDX-License-Identifier: Apache-2.0

//go:build openfhe

package main

import (
	"fmt"
	"time"

	cgo "github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/fhecalib"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/helperclient"
	"github.com/Fheyalabs/ares-core/pkg/ares/pool"
)

// Crypto parameters. Depth comes from the calibrated constant rather than
// a guess. Ring 16384 (not 8192): a depth-6 chain at scaling 2^50 needs
// 60+6*50 = 360 modulus bits, and 8192 admits only ~220 — enough for the
// tiny test grids but not for a 64-bucket curve carrying real quantities.
const (
	demoRing = 16384

	demoGain      = 4.0
	demoCompDeg   = 13
	demoCircuitID = "pool-uniform-price-clearing"
)

// ClientEncryption marks the one place this demo departs from the
// deployed design.
//
// In the deployed scheme each participant encodes and encrypts its own
// offer curve on its own device, so no plaintext bid ever reaches the
// operator. Doing that in a browser needs OpenFHE compiled to
// WebAssembly, which is not yet built. Until it is, the server performs
// the encoding and encryption on the tab's behalf.
//
// Everything downstream of this seam is real: real threshold keygen, real
// homomorphic aggregation, a real comparator, real threshold decryption,
// and per-participant allocations derived locally from the public
// clearing price. What is simulated is *where* encryption happens, not
// whether it happens.
const ClientEncryption = "server-side (WASM client not yet built)"

// committee is the decryption quorum. Two shares, N-of-N, so no single
// share can open anything. In the deployed scheme the shares sit with
// separate institutions; here both live in this process, which is the
// second thing the demo simulates rather than enforces.
type committee struct {
	handle fhecalib.ContextHandle
	params cgo.ContractParams
	shares []cgo.DistributedKeyShare
}

func newCommittee(depth uint32) (*committee, error) {
	if err := cgo.SmokeCKKS(); err != nil {
		return nil, fmt.Errorf("OpenFHE unavailable: %w", err)
	}
	cp := cgo.ContractParams{
		RingDim:       demoRing,
		ScalingFactor: float64(uint64(1) << 50),
		Depth:         depth,
	}
	first, err := cgo.DistributedKeyGenFirst(cp)
	if err != nil {
		return nil, fmt.Errorf("keygen first: %w", err)
	}
	second, err := cgo.DistributedKeyGenNext(cp, first.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keygen next: %w", err)
	}
	shares := []cgo.DistributedKeyShare{first, second}
	keys, err := buildJointEvalKeys(cp, shares)
	if err != nil {
		return nil, fmt.Errorf("eval keys: %w", err)
	}
	h := fhecalib.NewContextHandle(helperclient.ContractParams{
		RingDim:        demoRing,
		ScalingFactor:  cp.ScalingFactor,
		ScalingModSize: 50,
		Depth:          depth,
	}, keys, second.PublicKey)
	return &committee{handle: h, params: cp, shares: shares}, nil
}

func (c *committee) decryptNamed(name string, ct []byte, n int) ([]float64, error) {
	partials := make([][]byte, 0, len(c.shares))
	for _, s := range c.shares {
		p, err := cgo.PartialDecryptCKKSForContract(c.params, ct, s.SecretKeyShare, s.Lead)
		if err != nil {
			return nil, fmt.Errorf("partial decrypt: %w", err)
		}
		partials = append(partials, p)
	}
	v, err := cgo.FuseCKKSPartialsForContract(c.params, partials, n)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", name, err)
	}
	return v, nil
}

func buildJointEvalKeys(params cgo.ContractParams, shares []cgo.DistributedKeyShare) (cgo.EvalKeyFinal, error) {
	finalPK := shares[len(shares)-1].PublicKey
	lead, err := cgo.EvalKeyRound1Lead(params, shares[0].SecretKeyShare)
	if err != nil {
		return cgo.EvalKeyFinal{}, err
	}
	pks := [][]byte{shares[0].PublicKey}
	multShares := [][]byte{lead.EvalMultBase}
	sumShares := [][]byte{lead.EvalSumBase}
	for i := 1; i < len(shares); i++ {
		r1, err := cgo.EvalKeyRound1Participant(params, shares[i].SecretKeyShare,
			lead.EvalMultBase, lead.EvalSumBase, shares[i].PublicKey)
		if err != nil {
			return cgo.EvalKeyFinal{}, err
		}
		pks = append(pks, shares[i].PublicKey)
		multShares = append(multShares, r1.EvalMultSwitchShare)
		sumShares = append(sumShares, r1.EvalSumShare)
	}
	combined, err := cgo.CombineEvalKeyRound1(params, pks, multShares, sumShares)
	if err != nil {
		return cgo.EvalKeyFinal{}, err
	}
	var finalShares [][]byte
	for i, s := range shares {
		r2, err := cgo.EvalKeyRound2Participant(params, s.SecretKeyShare,
			combined.EvalMultJoined, finalPK, i == 0)
		if err != nil {
			return cgo.EvalKeyFinal{}, err
		}
		finalShares = append(finalShares, r2.EvalMultFinalShare)
	}
	return cgo.CombineEvalKeyRound2(params, finalPK, finalShares, combined.EvalSumFinal)
}

// RunClearing aggregates every submitted offer under encryption, runs the
// clearing circuit, and threshold-decrypts only the result.
func (s *Session) RunClearing() (*Outcome, error) {
	s.mu.Lock()
	hour := s.Hour
	band := BandAt(hour)
	type bid struct {
		side  Side
		price float64
		qty   float64
	}
	var bids []bid
	sellers, buyers := 0, 0
	for _, p := range s.participants {
		if !p.Submitted || p.QuantityKWh <= 0 {
			continue
		}
		bids = append(bids, bid{p.Side, p.PriceCt, p.QuantityKWh})
		if p.Side == SideSeller {
			sellers++
		} else {
			buyers++
		}
	}
	s.mu.Unlock()

	out := &Outcome{
		Hour: hour, SpotCt: band.SpotCt, FloorCt: band.FloorCt, CapCt: band.CapCt,
		Sellers: sellers, Buyers: buyers,
		CircuitName: demoCircuitID, Depth: pool.PinnedDepth,
	}
	if sellers == 0 || buyers == 0 {
		out.Note = "needs at least one seller and one buyer"
		s.mu.Lock()
		s.last = out
		s.applyAllocations(out)
		s.mu.Unlock()
		return out, nil
	}

	start := time.Now()
	g := DemoGrid()

	// Every participant's own curve, plus the two public grid curves. The
	// grid participants are what make the price guarantee structural: the
	// pool can always clear inside [floor, cap] because both edges are
	// perfectly elastic.
	var sellOffers, buyOffers []pool.Offer
	total := 0.0
	for _, b := range bids {
		total += b.qty
		if b.side == SideSeller {
			sellOffers = append(sellOffers, pool.Offer{Slot: 0, PriceCt: b.price, Quantity: b.qty})
		} else {
			buyOffers = append(buyOffers, pool.Offer{Slot: 0, PriceCt: b.price, Quantity: b.qty})
		}
	}
	elastic := total + 1
	sellOffers = append(sellOffers, pool.Offer{Slot: 0, PriceCt: band.CapCt, Quantity: elastic})
	buyOffers = append(buyOffers, pool.Offer{Slot: 0, PriceCt: band.FloorCt, Quantity: elastic})

	supply, err := pool.EncodeSupply(g, sellOffers)
	if err != nil {
		return nil, err
	}
	demand, err := pool.EncodeDemand(g, buyOffers)
	if err != nil {
		return nil, err
	}

	comm, err := newCommittee(pool.PinnedDepth)
	if err != nil {
		return nil, err
	}

	// ---- the client-encryption seam -------------------------------
	ctS, err := comm.handle.Encrypt(supply)
	if err != nil {
		return nil, fmt.Errorf("encrypt supply: %w", err)
	}
	ctD, err := comm.handle.Encrypt(demand)
	if err != nil {
		return nil, fmt.Errorf("encrypt demand: %w", err)
	}
	// ---------------------------------------------------------------

	// Range control is sized from the actual curves, not a constant: the
	// comparator argument must land in roughly [-0.5, 0.5] so the
	// degree-13 series stays inside its trusted domain.
	maxAbsE := 1.0
	for i := range supply {
		if d := supply[i] - demand[i]; d > maxAbsE {
			maxAbsE = d
		} else if -d > maxAbsE {
			maxAbsE = -d
		}
	}
	scale := 2 * maxAbsE

	res, err := pool.EvalClearing(comm.handle, g,
		pool.ClearingInputs{Supply: ctS, Demand: ctD},
		pool.LogisticCoeffs(demoCompDeg, demoGain), scale)
	if err != nil {
		return nil, fmt.Errorf("clearing circuit: %w", err)
	}

	stepv, err := comm.decryptNamed("step", res.Step, g.Len())
	if err != nil {
		return nil, err
	}
	oneHot, err := comm.decryptNamed("onehot", res.OneHot, g.Len())
	if err != nil {
		return nil, err
	}
	supAt, err := comm.decryptNamed("supplyAt", res.SupplyAt, g.Len())
	if err != nil {
		return nil, err
	}
	supPrev, err := comm.decryptNamed("supplyPrevAt", res.SupplyPrevAt, g.Len())
	if err != nil {
		return nil, err
	}
	demAt, err := comm.decryptNamed("demandAt", res.DemandAt, g.Len())
	if err != nil {
		return nil, err
	}

	decoded := pool.DecodeClearing(g, stepv, oneHot, supAt, supPrev, demAt)[0]
	out.ElapsedMS = time.Since(start).Milliseconds()
	out.SupplyCurve = supply
	out.DemandCurve = demand

	if decoded.Bucket == pool.NoClearing {
		out.Note = "no crossing inside the band"
	} else {
		out.DidClear = true
		out.ClearedPx = decoded.PriceCt
		out.ClearedKWh = decoded.Cleared
	}

	s.mu.Lock()
	s.last = out
	s.applyAllocations(out)
	s.mu.Unlock()
	return out, nil
}
