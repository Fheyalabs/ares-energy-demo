// SPDX-License-Identifier: Apache-2.0

package onion

import (
	"crypto/sha256"
	"encoding/binary"
)

// SlotPermutation deterministically derives a permutation of [0, n)
// from seed. All parties holding the same seed (e.g.
// SHA-256(pk_joint_tag || session_id)) compute the identical ordering,
// so slot assignment needs no coordinator. Uses Fisher-Yates driven by
// a SHA-256 counter-mode keystream over the seed; unbiased via
// rejection sampling.
func SlotPermutation(seed []byte, n int) []int {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}
	s := &seedStream{seed: seed}
	// Fisher-Yates from the high end.
	for i := n - 1; i > 0; i-- {
		j := s.intn(i + 1)
		perm[i], perm[j] = perm[j], perm[i]
	}
	return perm
}

// seedStream is a deterministic byte source: SHA-256(seed || counter),
// counter incrementing per 32-byte block.
type seedStream struct {
	seed    []byte
	counter uint64
	buf     []byte
	off     int
}

func (s *seedStream) next() byte {
	if s.off >= len(s.buf) {
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], s.counter)
		s.counter++
		h := sha256.Sum256(append(append([]byte{}, s.seed...), ctr[:]...))
		s.buf = h[:]
		s.off = 0
	}
	b := s.buf[s.off]
	s.off++
	return b
}

// intn returns an unbiased value in [0, m) for m >= 1 via rejection
// sampling over 4 stream bytes.
func (s *seedStream) intn(m int) int {
	if m <= 1 {
		return 0
	}
	limit := (uint32(1<<32-1) / uint32(m)) * uint32(m)
	for {
		v := uint32(s.next())<<24 | uint32(s.next())<<16 | uint32(s.next())<<8 | uint32(s.next())
		if v < limit {
			return int(v % uint32(m))
		}
	}
}
