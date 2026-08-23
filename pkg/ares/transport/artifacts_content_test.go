// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Fheyalabs/ares-core/pkg/ares/transport"
)

func TestArtifactStore_PutContent_GetContent_RoundTrip(t *testing.T) {
	store := transport.NewArtifactStore()
	data := []byte("opaque blob bytes")
	handle, err := store.PutContent(data)
	if err != nil {
		t.Fatalf("PutContent: %v", err)
	}
	got, err := store.GetContent(handle)
	if err != nil {
		t.Fatalf("GetContent: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("GetContent returned %x, want %x", got, data)
	}
}

func TestArtifactStore_PutContent_Idempotent(t *testing.T) {
	store := transport.NewArtifactStore()
	data := []byte("same blob")
	h1, _ := store.PutContent(data)
	h2, _ := store.PutContent(data)
	if h1 != h2 {
		t.Errorf("PutContent not idempotent: h1=%x h2=%x", h1, h2)
	}
}

func TestArtifactStore_GetContent_HandleNotFound(t *testing.T) {
	store := transport.NewArtifactStore()
	var missing [32]byte
	missing[0] = 0xff
	_, err := store.GetContent(missing)
	if err == nil {
		t.Fatal("expected error on missing handle")
	}
}

func TestArtifactStore_GetContent_DetectsCorruption(t *testing.T) {
	// Simulate in-memory corruption by direct map mutation via the
	// app-keyed Put interface using the content-addressed key.
	// GetContent re-hashes the bytes and compares to the handle;
	// mismatch returns ErrCorrupted.
	store := transport.NewArtifactStore()
	data := []byte("original")
	handle, _ := store.PutContent(data)
	// Overwrite with different bytes under the same content-addressed key.
	store.Put(transport.ContentKey(handle), []byte("tampered"))
	_, err := store.GetContent(handle)
	if !errors.Is(err, transport.ErrCorrupted) {
		t.Fatalf("GetContent: got %v, want ErrCorrupted", err)
	}
}
