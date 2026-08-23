// SPDX-License-Identifier: Apache-2.0

package rideshare_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	rideshare "github.com/Fheyalabs/ares-core/examples/ride_share"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestBitflip_DetectedAtEveryLineageStage exercises every
// lineage-protected message type in the ride-share pipeline and
// asserts each is rejected with *lineage.MismatchError when a single
// payload bit is flipped between commit and dispatch. PhaseSubmit
// consumes two distinct message types (ride.bid from drivers,
// ride.request from the rider) so the SUBMIT stage gets two subtests.
//
// See examples/sealed_bid_auction/bitflip_test.go for the canonical
// commentary on the test pattern.
func TestBitflip_DetectedAtEveryLineageStage(t *testing.T) {
	const sessionID = "ride-bitflip"
	participants := []string{"rider", "driver-1", "driver-2"}

	type stage struct {
		name    string
		msgType string
		from    string
		phaseID string
		role    string
		target  phase.SessionState
		payload []byte
		flipFn  func([]byte) int
	}

	stages := []stage{
		{
			name:    "ride.keygen.share at RIDE_KEYGEN (flip byte 0)",
			msgType: "ride.keygen.share",
			from:    "driver-1",
			phaseID: "ride-keygen",
			role:    "share-driver-1",
			target:  rideshare.StateKeygen,
			payload: mustJSON(t, map[string]string{
				"share_ct": hex.EncodeToString([]byte("driver-1-keygen-share")),
			}),
			flipFn: func(_ []byte) int { return 0 },
		},
		{
			name:    "ride.bid at RIDE_SUBMIT (flip middle byte)",
			msgType: "ride.bid",
			from:    "driver-1",
			phaseID: "ride-submit",
			role:    "bid-driver-1",
			target:  rideshare.StateSubmit,
			payload: mustJSON(t, map[string]string{
				"price_ct":     hex.EncodeToString([]byte("driver-1-price")),
				"proximity_ct": hex.EncodeToString([]byte("driver-1-prox")),
			}),
			flipFn: func(b []byte) int { return len(b) / 2 },
		},
		{
			name:    "ride.request at RIDE_SUBMIT (flip near-last byte)",
			msgType: "ride.request",
			from:    "rider",
			phaseID: "ride-submit",
			role:    "request-rider",
			target:  rideshare.StateSubmit,
			payload: mustJSON(t, map[string]string{
				"max_price_ct": hex.EncodeToString([]byte("rider-max-price")),
				"location_ct":  hex.EncodeToString([]byte("rider-location")),
			}),
			flipFn: func(b []byte) int { return len(b) - 2 },
		},
		{
			name:    "ride.decrypt.partial at RIDE_DECRYPT (flip last byte)",
			msgType: "ride.decrypt.partial",
			from:    "driver-1",
			phaseID: "ride-decrypt",
			role:    "partial-driver-1",
			target:  rideshare.StateDecrypt,
			payload: mustJSON(t, map[string]string{
				"partial_ct": hex.EncodeToString([]byte("driver-1-partial-decrypt")),
			}),
			flipFn: func(b []byte) int { return len(b) - 1 },
		},
	}

	for _, s := range stages {
		s := s
		t.Run(s.name, func(t *testing.T) {
			dispatcher, _ := sign.NewEd25519Signer()
			peer, _ := sign.NewEd25519Signer()
			peers := map[string]sign.Signer{sign.Ed25519Algorithm: peer}

			runner, err := rideshare.PipelineWithLineage(dispatcher, peers)
			if err != nil {
				t.Fatalf("PipelineWithLineage: %v", err)
			}
			ctx, err := runner.BeginSession(sessionID, "")
			if err != nil {
				t.Fatalf("BeginSession: %v", err)
			}
			ctx.Set(rideshare.CtxParticipants, participants)
			ctx.Set(rideshare.CtxRoles, map[string]string{
				"rider": "rider", "driver-1": "driver", "driver-2": "driver",
			})
			ctx.Set(rideshare.CtxCryptoContract, map[string]any{
				"depth": 30, "ring_dim": 16384, "scaling_mod_size": 40,
			})

			driveRideShareTo(t, runner, sessionID, participants, s.target)

			node, err := lineage.Commit(sessionID, s.phaseID, s.role, s.payload, nil, peer)
			if err != nil {
				t.Fatalf("lineage.Commit: %v", err)
			}
			tampered := append([]byte{}, s.payload...)
			idx := s.flipFn(tampered)
			tampered[idx] ^= 0x01
			t.Logf("flipped bit at byte %d (of %d): %q → %q",
				idx, len(tampered), s.payload[idx:idx+1], tampered[idx:idx+1])

			_, err = runner.HandleLineageMessage(sessionID, s.msgType, s.from, tampered, &node)
			if err == nil {
				t.Fatalf("%s: expected *MismatchError, got nil (bitflip undetected!)", s.name)
			}
			var me *lineage.MismatchError
			if !errors.As(err, &me) {
				t.Fatalf("%s: expected *MismatchError, got %T: %v", s.name, err, err)
			}
			if me.Field != "PayloadHash" {
				t.Errorf("%s: MismatchError.Field = %q, want %q", s.name, me.Field, "PayloadHash")
			}
		})
	}
}

func driveRideShareTo(t *testing.T, runner *phase.SessionRunner, sessionID string, participants []string, target phase.SessionState) {
	t.Helper()
	if cur, _ := runner.CurrentState(sessionID); cur == target {
		return
	}
	if err := runner.AdvanceToState(sessionID, rideshare.StateKeygen); err != nil {
		t.Fatalf("advance to KEYGEN: %v", err)
	}
	if target == rideshare.StateKeygen {
		return
	}
	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "ride.keygen.share", p, []byte("s-"+p)); err != nil {
			t.Fatalf("drive keygen.share from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != rideshare.StateSubmit {
		t.Fatalf("after keygen drive: state=%q want SUBMIT", s)
	}
	if target == rideshare.StateSubmit {
		return
	}
	// Drive bids/request to advance past SUBMIT → SCORE → DECRYPT.
	// PhaseSubmit accumulates both ride.bid (drivers) and
	// ride.request (rider). The legacy endtoend test only sends bids
	// for all participants — the framework counts unique senders
	// regardless of msg-type. Reproduce that pattern.
	for _, p := range participants {
		if _, err := runner.HandleMessage(sessionID, "ride.bid", p, []byte("b-"+p)); err != nil {
			t.Fatalf("drive bid from %s: %v", p, err)
		}
	}
	if s, _ := runner.CurrentState(sessionID); s != rideshare.StateDecrypt {
		t.Fatalf("after bid drive: state=%q want DECRYPT", s)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}
