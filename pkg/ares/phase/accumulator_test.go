// SPDX-License-Identifier: Apache-2.0

package phase

import (
	"sync"
	"testing"
)

func TestAccumulateMessage_StoresByFrom(t *testing.T) {
	ctx := NewSessionContext("s")
	AccumulateMessage(ctx, "k", "alice", []byte("a"))
	AccumulateMessage(ctx, "k", "bob", []byte("b"))
	if got := MessageCount(ctx, "k"); got != 2 {
		t.Errorf("MessageCount = %d, want 2", got)
	}
}

func TestAccumulateMessage_OverwritesSameFrom(t *testing.T) {
	ctx := NewSessionContext("s")
	AccumulateMessage(ctx, "k", "alice", []byte("a1"))
	AccumulateMessage(ctx, "k", "alice", []byte("a2"))
	if got := MessageCount(ctx, "k"); got != 1 {
		t.Errorf("MessageCount = %d, want 1", got)
	}
	msgs := AccumulatedMessages(ctx, "k")
	if string(msgs["alice"]) != "a2" {
		t.Errorf("alice payload = %q, want a2", msgs["alice"])
	}
}

func TestQuorumReached(t *testing.T) {
	ctx := NewSessionContext("s")
	if QuorumReached(ctx, "k", 1) {
		t.Errorf("empty bucket should not reach quorum")
	}
	AccumulateMessage(ctx, "k", "p1", []byte("x"))
	if QuorumReached(ctx, "k", 2) {
		t.Errorf("1 of 2 should not reach quorum")
	}
	AccumulateMessage(ctx, "k", "p2", []byte("y"))
	if !QuorumReached(ctx, "k", 2) {
		t.Errorf("2 of 2 should reach quorum")
	}
}

func TestAccumulateMessage_ConcurrentSafe(t *testing.T) {
	ctx := NewSessionContext("s")
	const senders = 50
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			from := string(rune('a' + i%26)) + string(rune('a'+i/26))
			AccumulateMessage(ctx, "k", from, []byte{byte(i)})
		}(i)
	}
	wg.Wait()
	count := MessageCount(ctx, "k")
	// Up to 26*2 = 52 unique senders. Pigeonhole says count >= some bound.
	if count == 0 {
		t.Errorf("expected at least some accumulated messages, got 0")
	}
}

func TestAccumulatedMessages_ReturnsCopy(t *testing.T) {
	ctx := NewSessionContext("s")
	AccumulateMessage(ctx, "k", "p", []byte("x"))
	m := AccumulatedMessages(ctx, "k")
	m["evil"] = []byte("injection")
	if MessageCount(ctx, "k") != 1 {
		t.Errorf("AccumulatedMessages returned an alias; mutation leaked")
	}
}
