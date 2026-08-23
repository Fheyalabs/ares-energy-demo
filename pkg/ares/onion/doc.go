// SPDX-License-Identifier: Apache-2.0

// Package onion implements the client-side cryptography for ARES slot
// anonymization: X25519 ECIES envelopes, the onion construction, and a
// deterministic slot permutation. It is transport- and
// application-agnostic; the framework's gossip phases drive it, and any
// participant client can reuse it directly.
//
// # Security property
//
// The onion shuffle anonymizes the mapping between an anonymized slot
// index and the participant who produced that slot's delivery key. Its
// purpose is that no participant (and, combined with authenticated
// submission, no honest-but-curious downstream consumer of the shuffle
// output) can link a slot to the identity that created it, so a
// session's selected/winning slot cannot be attributed to a registered
// identity by other participants.
//
// # SC-2: self-layer construction
//
// Each participant wraps its payload in N-1 ECIES layers — one for
// every peeler INCLUDING itself — in the reverse of peel order. An
// earlier construction that skipped the builder's own layer produced
// N-2-layer onions, which let the second-to-last peeler observe a
// fully-peeled plaintext and attribute it to the last participant. The
// self-layer closes that: no item is fully peeled until the final
// round. A builder identifies its own item during peeling by exact
// ciphertext memory match (the bytes captured right after wrapping its
// own layer), not by "cannot decrypt".
//
// # SC-7: collusion resistance
//
// With k colluding peelers and h = (N-1) - k honest peelers, each
// honest party's slot sits uniformly among the h honest positions, so
// the probability a collusion identifies a specific honest party's slot
// is 1/h. Consequently:
//
//   - k <= N-4  -> anonymity set >= 3, identification probability <= 1/3.
//   - k = N-3   -> anonymity set 2, 50% floor (worst case with genuine
//     anonymity).
//   - k >= N-2  -> certain identification (all but one collude).
//
// Certain deanonymization therefore requires k >= N-2 colluding
// peelers, not k = N-1. For a six-party session (five peelers) the 50%
// floor is at k = 3 and certain identification at k >= 4.
package onion
