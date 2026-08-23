// SPDX-License-Identifier: Apache-2.0

package anon_test

import (
	"encoding/json"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/phase"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/anon"
	"github.com/Fheyalabs/ares-core/pkg/ares/phase/defaults"
)

func submitJSON(t *testing.T, idx int, pubHex string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"slot_index": idx, "slot_dk_pub": pubHex})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestPhaseGVerify_AssemblesOrderedSlotList(t *testing.T) {
	p := anon.NewPhaseGVerify(defaults.StateSubmitting)
	if p.EntryState() != defaults.StateVerifying || p.ExitState() != defaults.StateSubmitting {
		t.Fatalf("arc = %s->%s, want VERIFYING->SUBMITTING", p.EntryState(), p.ExitState())
	}
	ctx := phase.NewSessionContext("s1")
	ctx.Set(anon.CtxParticipants, []string{"a", "b", "c"})

	// Submissions arrive out of slot order and from arbitrary senders.
	_ = p.OnMessage(ctx, anon.MsgSlotSubmit, "a", submitJSON(t, 2, "cccc"))
	_ = p.OnMessage(ctx, anon.MsgSlotSubmit, "b", submitJSON(t, 0, "aaaa"))
	if p.CheckComplete(ctx) {
		t.Fatal("not complete with 2/3 submissions")
	}
	_ = p.OnMessage(ctx, anon.MsgSlotSubmit, "c", submitJSON(t, 1, "bbbb"))
	if !p.CheckComplete(ctx) {
		t.Fatal("complete expected with 3/3")
	}
	if err := p.Exit(ctx); err != nil {
		t.Fatalf("Exit: %v", err)
	}
	got, ok := phase.TryGet[[]byte](ctx, anon.CtxAssembledSlotList)
	if !ok {
		t.Fatal("assembled slot list not set as []byte")
	}
	var list []anon.SlotEntry
	if err := json.Unmarshal(got, &list); err != nil {
		t.Fatalf("decode assembled list: %v", err)
	}
	want := []string{"aaaa", "bbbb", "cccc"} // ordered by slot_index 0,1,2
	if len(list) != 3 {
		t.Fatalf("len = %d want 3", len(list))
	}
	for i, e := range list {
		if e.SlotIndex != i || e.SlotDKPubHex != want[i] {
			t.Fatalf("entry %d = {%d,%s}, want {%d,%s}", i, e.SlotIndex, e.SlotDKPubHex, i, want[i])
		}
	}
}

func TestPhaseGVerify_RejectsDuplicateSlotIndex(t *testing.T) {
	p := anon.NewPhaseGVerify(defaults.StateSubmitting)
	ctx := phase.NewSessionContext("s1")
	ctx.Set(anon.CtxParticipants, []string{"a", "b"})
	_ = p.OnMessage(ctx, anon.MsgSlotSubmit, "a", submitJSON(t, 0, "aaaa"))
	_ = p.OnMessage(ctx, anon.MsgSlotSubmit, "b", submitJSON(t, 0, "bbbb")) // collision
	if err := p.Exit(ctx); err == nil {
		t.Fatal("Exit must reject duplicate slot index")
	}
}
