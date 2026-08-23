// SPDX-License-Identifier: Apache-2.0

package lineage

import (
	"context"
	"iter"
	"sync"
)

// InMemoryStore is the default Store implementation. Nodes live in
// session-keyed maps; Clear (called by the runner on EndSession)
// drops a session's nodes. Not durable across process restarts —
// production deployments wanting persistence should swap in a
// backend implementation.
//
// Safe for concurrent use.
type InMemoryStore struct {
	mu sync.RWMutex
	// byHash indexes all nodes for fast Get.
	byHash map[NodeRef]DAGNode
	// bySession indexes per-session for fast WalkSession + Clear.
	bySession map[string][]NodeRef
}

// NewInMemoryStore returns a fresh, empty in-memory store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		byHash:    make(map[NodeRef]DAGNode),
		bySession: make(map[string][]NodeRef),
	}
}

// Append implements Store. Returns ErrNodeExists for duplicate
// hashes.
func (s *InMemoryStore) Append(_ context.Context, node DAGNode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byHash[node.Hash]; exists {
		return ErrNodeExists
	}
	s.byHash[node.Hash] = node
	s.bySession[node.SessionID] = append(s.bySession[node.SessionID], node.Hash)
	return nil
}

// Get implements Store.
func (s *InMemoryStore) Get(_ context.Context, hash NodeRef) (DAGNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.byHash[hash]
	if !ok {
		return DAGNode{}, ErrNodeNotFound
	}
	return node, nil
}

// WalkSession implements Store. Returns nodes in Append order.
func (s *InMemoryStore) WalkSession(_ context.Context, sessionID string) iter.Seq2[DAGNode, error] {
	// Snapshot under the lock so iteration is consistent even if
	// the store mutates mid-walk.
	s.mu.RLock()
	refs := append([]NodeRef(nil), s.bySession[sessionID]...)
	snapshot := make([]DAGNode, 0, len(refs))
	for _, r := range refs {
		if n, ok := s.byHash[r]; ok {
			snapshot = append(snapshot, n)
		}
	}
	s.mu.RUnlock()
	return func(yield func(DAGNode, error) bool) {
		for _, n := range snapshot {
			if !yield(n, nil) {
				return
			}
		}
	}
}

// Clear drops all nodes belonging to sessionID. Intended for
// post-EndSession cleanup; persistent backends typically retain
// per their own policy and may implement Clear as a no-op.
func (s *InMemoryStore) Clear(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.bySession[sessionID]
	for _, r := range refs {
		delete(s.byHash, r)
	}
	delete(s.bySession, sessionID)
}

// Compile-time assertion that InMemoryStore satisfies Store.
var _ Store = (*InMemoryStore)(nil)
