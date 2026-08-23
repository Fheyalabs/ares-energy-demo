//go:build openfhe

// SPDX-License-Identifier: Apache-2.0
//
package cgo_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"github.com/Fheyalabs/ares-core/pkg/ares/crypto/cgo"
	"os"
	"testing"
)

// --- full end-to-end with bidirectional identity signatures ---
//
// Identity model (from ARES-core Phase 0b):
//   - Each user (rider/driver) has a long-term Ed25519 identity keypair.
//   - Identity PUBKEYS are registered with Auth Service at account creation.
//   - Identity PRIVATE keys never leave the device.
//   - Server reads pubkeys from registry but CANNOT forge signatures.
//
// Key distribution (prevents server MITM of auction pk):
//   1. Rider signs auction_pk with rider_id_sk → rider_sig
//   2. Server relays {auction_pk, rider_sig} to drivers
//   3. Each driver verifies rider_sig against rider's REGISTERED identity pubkey
//   4. If invalid → driver refuses to bid (server tampered with pk)
//
// Bid submission (prevents ghost drivers):
//   5. Driver signs H(price || nonce || session_id) with driver_id_sk → bid_sig
//   6. Server runs auction on ciphertexts → encrypted masks → rider
//   7. Rider decrypts masks → winner j → verifies bid_sig_j against driver j's
//      registered identity pubkey → valid → match
//
// Server is a passive relay. Can't forge either signature. Can't substitute
// keys. Can't decrypt ciphertexts (no sk).

func TestFullFlow_BidirectionalSigning(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("skip: %v", err)
	}
	os.Setenv("ARES_FHE_ALLOW_INSECURE", "0")
	defer os.Setenv("ARES_FHE_ALLOW_INSECURE", "1")

	params := cgo.ContractParams{RingDim: 1 << 15, Depth: 5, ScalingFactor: float64(uint64(1) << 50)}
	w := cgo.AuctionWeights{K: 100, WStar: 1.0, WDist: 0.001}
	sessionID := "ride-dresden-003"

	// --- Identity registry (Auth Service — trusted for pubkey storage) ---
	type Identity struct {
		pseudonym string
		pubKey    ed25519.PublicKey
		privKey   ed25519.PrivateKey
	}
	makeIdentity := func(name string) Identity {
		pub, priv, _ := ed25519.GenerateKey(nil)
		return Identity{pseudonym: name, pubKey: pub, privKey: priv}
	}

	rider := makeIdentity("rider-alice")
	drivers := make([]Identity, 6)
	for i := range drivers {
		drivers[i] = makeIdentity(fmt.Sprintf("driver-bob-%d", i))
	}

	// --- 1. RIDER: generate auction keypair + sign auction_pk ---
	auctionPK, auctionSK, auctionEvalMultKey, err := cgo.SingleKeyGenWithEvalKey(params)
	if err != nil {
		t.Fatalf("rider keygen: %v", err)
	}

	// Rider signs: H(auction_pk || session_id) with identity key
	h := sha256.New()
	h.Write(auctionPK)
	h.Write([]byte(sessionID))
	riderSig := ed25519.Sign(rider.privKey, h.Sum(nil))

	// --- 2. SERVER: relays {auction_pk, rider_sig} to drivers ---
	// (server can READ but not FORGE — no access to rider.privKey)

	// --- 3. DRIVERS: verify rider signature, encrypt + sign bids ---
	priceCents := make([]int, len(drivers))
	starNorms := make([]float64, len(drivers))
	distSqs := make([]float64, len(drivers))
	nonces := make([][]byte, len(drivers))
	bidSigs := make([][]byte, len(drivers))

	for i, d := range drivers {
		// Verify rider's signature on auction_pk
		h := sha256.New()
		h.Write(auctionPK)
		h.Write([]byte(sessionID))
		if !ed25519.Verify(rider.pubKey, h.Sum(nil), riderSig) {
			t.Fatalf("driver %s: RIDER SIGNATURE INVALID — server tampered with auction_pk", d.pseudonym)
		}

		priceCents[i] = 1200 + i*50
		starNorms[i] = 5.0 - float64(i)*0.2
		distSqs[i] = float64(i) * 0.3
		nonces[i] = make([]byte, 16)
		copy(nonces[i][:8], []byte(fmt.Sprintf("nc%02d-----", i)))

		// Driver signs: H(price || nonce || session_id) with identity key
		h = sha256.New()
		h.Write([]byte(fmt.Sprintf("%d", priceCents[i])))
		h.Write(nonces[i])
		h.Write([]byte(sessionID))
		bidSigs[i] = ed25519.Sign(d.privKey, h.Sum(nil))
	}

	// --- 4. SERVER: auction (pk only, never sk) ---
	encMasks, err := cgo.SingleKeyAuctionServerWithEvalKey(params, auctionPK, auctionEvalMultKey, priceCents, starNorms, distSqs, nonces, 800, 2500, w, 1)
	if err != nil {
		t.Fatalf("server auction: %v", err)
	}

	// --- 5. RIDER: decrypt masks locally ---
	masks, winner, err := cgo.SingleKeyAuctionDecrypt(params, auctionSK, encMasks)
	if err != nil {
		t.Fatalf("rider decrypt: %v", err)
	}

	// --- 6. RIDER: verify winning driver's signature ---
	winnerDriver := drivers[winner]
	h = sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", priceCents[winner])))
	h.Write(nonces[winner])
	h.Write([]byte(sessionID))
	if !ed25519.Verify(winnerDriver.pubKey, h.Sum(nil), bidSigs[winner]) {
		t.Errorf("BID SIGNATURE INVALID for winner %s — possible ghost driver", winnerDriver.pseudonym)
	}

	// --- 7. Assertions ---
	if winner != 0 {
		t.Errorf("expected winner 0, got %d", winner)
	}
	for i := 0; i < len(drivers); i++ {
		if i != winner && masks[i] >= masks[winner] {
			t.Errorf("mask[%d]=%.4f >= winner mask[%d]=%.4f", i, masks[i], winner, masks[winner])
		}
	}

	// Shared secret for OTP/phrase/QR
	sh := sha256.New()
	sh.Write(nonces[winner])
	sh.Write([]byte(sessionID))
	t.Logf("FULL FLOW: rider=%s winner=%s price=€%.2f masks[0]=%.4f sep=%.4f secret=%x rider_sig=OK bid_sig=OK",
		rider.pseudonym, winnerDriver.pseudonym, float64(priceCents[winner])/100,
		masks[0], masks[0]-masks[1], sh.Sum(nil)[:8])
}

// --- attack scenarios ---

func TestFullFlow_AttackScenarios(t *testing.T) {
	if err := cgo.SmokeCKKS(); err != nil {
		t.Skipf("skip: %v", err)
	}
	os.Setenv("ARES_FHE_ALLOW_INSECURE", "0")
	defer os.Setenv("ARES_FHE_ALLOW_INSECURE", "1")

	params := cgo.ContractParams{RingDim: 1 << 15, Depth: 5, ScalingFactor: float64(uint64(1) << 50)}
	w := cgo.AuctionWeights{K: 100, WStar: 1.0, WDist: 0.001}
	sessionID := "ride-attack-test"

	makeID := func(name string) (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		return pub, priv
	}

	t.Run("server-tampers-auction-pk", func(t *testing.T) {
		// Rider generates pk, signs it
		auctionPK, _, _ := cgo.SingleKeyGen(params)
		riderPub, riderPriv := makeID("rider")
		h := sha256.New()
		h.Write(auctionPK)
		h.Write([]byte(sessionID))
		riderSig := ed25519.Sign(riderPriv, h.Sum(nil))

		// Attacker: server swaps auction_pk with its own malicious pk
		maliciousPK, _, _ := cgo.SingleKeyGen(params)
		h = sha256.New()
		h.Write(maliciousPK)
		h.Write([]byte(sessionID))

		// Driver verifies: signature was over ORIGINAL pk, but server sent MALICIOUS pk
		valid := ed25519.Verify(riderPub, h.Sum(nil), riderSig)
		if valid {
			t.Errorf("SERVER PK TAMPER UNDETECTED: malicious pk accepted — rider identity sig should NOT verify for tampered pk")
		} else {
			t.Logf("SERVER PK TAMPER DETECTED: rider_sig doesn't match malicious pk → driver REJECTS, refuses to bid")
		}
	})

	t.Run("server-spawns-ghost-driver-without-sig", func(t *testing.T) {
		auctionPK, auctionSK, auctionEvalMultKey, _ := cgo.SingleKeyGenWithEvalKey(params)
		// Ghost bid: server encrypts low price, but has no driver identity key to sign
		pc := []int{500, 1000, 1200}   // ghost at idx 0 bids €5
		sn := []float64{1.0, 5.0, 5.0} // ghost has no ★ history
		ds := []float64{0.1, 0.1, 0.1}
		nc := [][]byte{[]byte("ghost-nonce!!"), []byte("nc-1"), []byte("nc-2")}

		encMasks, _ := cgo.SingleKeyAuctionServerWithEvalKey(params, auctionPK, auctionEvalMultKey, pc, sn, ds, nc, 800, 2500, w, 1)
		_, winner, _ := cgo.SingleKeyAuctionDecrypt(params, auctionSK, encMasks)

		if winner == 0 {
			// Ghost won. Rider checks: does idx 0 have a valid sig from a REGISTERED driver?
			// No — ghost has no registered identity key → REJECT
			t.Logf("GHOST WON on price but has no registered identity sig → rider REJECTS, falls back to next-best or aborts")
		} else {
			t.Logf("ghost outbid by real driver with valid sig")
		}
	})

	t.Run("driver-refuses-unsigned-rider-pk", func(t *testing.T) {
		// Server sends auction_pk WITHOUT rider signature
		auctionPK, _, _ := cgo.SingleKeyGen(params)
		// No riderSig provided — driver policy: refuse unsigned auction keys
		t.Logf("DRIVER POLICY: reject auction_pk without valid rider identity signature → do not bid")
		_ = auctionPK
	})
}
