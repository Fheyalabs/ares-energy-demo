// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"testing"
	"time"
)

func TestArtifactStore_PutGetRoundTrip(t *testing.T) {
	s := NewArtifactStore()
	s.Put("k1", []byte("hello"))
	got, ok := s.Get("k1")
	if !ok || string(got) != "hello" {
		t.Errorf("Get(k1) = %q,%v; want hello,true", got, ok)
	}
}

func TestArtifactStore_GetReturnsCopy(t *testing.T) {
	s := NewArtifactStore()
	original := []byte{1, 2, 3}
	s.Put("k", original)
	got, _ := s.Get("k")
	got[0] = 99
	again, _ := s.Get("k")
	if again[0] == 99 {
		t.Errorf("Get returned aliased slice; mutation leaked")
	}
}

func TestArtifactStore_Missing(t *testing.T) {
	s := NewArtifactStore()
	if _, ok := s.Get("nope"); ok {
		t.Errorf("Get on absent key returned ok=true")
	}
	_, err := s.Resolve("nope")
	if err == nil {
		t.Errorf("Resolve on absent key returned nil error")
	}
}

func TestArtifactStore_Expiration(t *testing.T) {
	s := NewArtifactStoreWithTTL(20 * time.Millisecond)
	s.Put("ephemeral", []byte("x"))
	time.Sleep(40 * time.Millisecond)
	if _, ok := s.Get("ephemeral"); ok {
		t.Errorf("expected key to expire after TTL")
	}
}

func TestArtifactStore_Sweep(t *testing.T) {
	s := NewArtifactStoreWithTTL(20 * time.Millisecond)
	s.Put("a", []byte("1"))
	s.Put("b", []byte("2"))
	time.Sleep(40 * time.Millisecond)
	if n := s.Sweep(); n != 2 {
		t.Errorf("Sweep purged %d entries, want 2", n)
	}
	if _, ok := s.Get("a"); ok {
		t.Errorf("a should be gone after sweep")
	}
}

func TestArtifactStore_Delete(t *testing.T) {
	s := NewArtifactStore()
	s.Put("d", []byte("x"))
	s.Delete("d")
	if _, ok := s.Get("d"); ok {
		t.Errorf("Delete did not remove the entry")
	}
}
