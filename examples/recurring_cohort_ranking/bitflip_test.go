// SPDX-License-Identifier: Apache-2.0

package cohort_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	cohort "github.com/Fheyalabs/ares-core/examples/recurring_cohort_ranking"
	"github.com/Fheyalabs/ares-core/pkg/ares/lineage"
	"github.com/Fheyalabs/ares-core/pkg/ares/sign"
)

// TestBitflip_DetectedAtEveryLineageStage exercises the cohort
// formation pipeline's one lineage-protected message type
// (cohort.keygen.share). To demonstrate position-independent bitflip
// detection, the same stage is exercised with the bit flipped at
// multiple byte positions — first byte, middle, last, and a
// double-flip across two arbitrary positions.
//
// The cohort weekly pipeline (WeeklyPipelineWithLineage) is
// standalone-uncomposable by design and so is exercised through the
// bridged-compose pattern in runner_test.go; this file covers the
// formation pipeline.
func TestBitflip_DetectedAtEveryLineageStage(t *testing.T) {
	basePayload, _ := json.Marshal(map[string]string{
		"share_ct": hex.EncodeToString([]byte("participant-1-keygen-share-bytes")),
		"share_id": "share-participant-1",
	})

	type variant struct {
		name   string
		flipFn func(b []byte)
	}
	variants := []variant{
		{name: "flip byte 0", flipFn: func(b []byte) { b[0] ^= 0x01 }},
		{name: "flip middle byte", flipFn: func(b []byte) { b[len(b)/2] ^= 0x80 }},
		{name: "flip last byte", flipFn: func(b []byte) { b[len(b)-1] ^= 0x01 }},
		{name: "double-flip (bytes 5 and 30)", flipFn: func(b []byte) {
			b[5] ^= 0x10
			b[30] ^= 0x20
		}},
	}

	for _, v := range variants {
		v := v
		t.Run("cohort.keygen.share at COHORT_KEYGEN ("+v.name+")", func(t *testing.T) {
			orchestrator, _ := sign.NewEd25519Signer()
			participant, _ := sign.NewEd25519Signer()
			store := lineage.NewInMemoryStore()
			peers := map[string]sign.Signer{sign.Ed25519Algorithm: participant}

			formation, err := cohort.FormationPipelineWithLineage(store, orchestrator, peers)
			if err != nil {
				t.Fatalf("FormationPipelineWithLineage: %v", err)
			}
			sessionID := "cohort-bitflip-" + v.name
			if _, err := formation.BeginSession(sessionID, ""); err != nil {
				t.Fatalf("BeginSession: %v", err)
			}

			// Construct the lineage commit over the untampered payload.
			node, err := lineage.Commit(sessionID, "cohort-keygen", "share-participant-1", basePayload, nil, participant)
			if err != nil {
				t.Fatalf("lineage.Commit: %v", err)
			}

			tampered := append([]byte{}, basePayload...)
			v.flipFn(tampered)
			t.Logf("base len=%d  tampered diff bytes: %d", len(basePayload), countDiff(basePayload, tampered))

			_, err = formation.HandleLineageMessage(sessionID, "cohort.keygen.share", "p1", tampered, &node)
			if err == nil {
				t.Fatalf("%s: expected *MismatchError, got nil", v.name)
			}
			var me *lineage.MismatchError
			if !errors.As(err, &me) {
				t.Fatalf("%s: expected *MismatchError, got %T: %v", v.name, err, err)
			}
			if me.Field != "PayloadHash" {
				t.Errorf("%s: MismatchError.Field = %q, want %q", v.name, me.Field, "PayloadHash")
			}
		})
	}
}

func countDiff(a, b []byte) int {
	if len(a) != len(b) {
		return -1
	}
	n := 0
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}
