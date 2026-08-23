// SPDX-License-Identifier: Apache-2.0

// Package helperclient is the Go-side IPC client for
// cmd/openfhe-contract-helper. It spawns the helper as a long-lived
// subprocess in daemon mode (`--daemon`) and exchanges newline-
// delimited JSON envelopes over stdin/stdout, amortizing the helper's
// startup cost across many ops.
//
// Two kinds of ops are exposed:
//
//   - Protocol ops — the helper RPCs the framework smokes
//     uses today: KeygenFirst, KeygenNext, EncryptProfile,
//     EvalKeyRound1Lead, EvalKeyRound1Participant,
//     EvalKeyRound2Participant, PartialDecrypt, FusePartials.
//
//   - Decomposable scoring primitives — the new ops the example apps
//     use for their scoring circuits: EvalAdd, EvalMult, EvalSub,
//     EvalPoly (the swappable sharpening primitive), and Argmax
//     (the composite that uses a caller-supplied polynomial to do
//     pairwise selection).
//
// Polynomials are passed as Go float64 slices in coefficient-ascending
// order (coeffs[0] is the constant term, coeffs[1] is x, coeffs[2] is
// x², …). Both EvalPoly and Argmax accept this shape so apps can swap
// the sharpening function — a low-degree odd polynomial for shallow
// circuits, a degree-9 Chebyshev approximation of sign() for higher
// accuracy at higher depth, or anything else the app's circuit can
// afford.
//
// The argmax composite is built on EvalPoly + the arithmetic
// primitives: pairwise differences, polynomial sharpening, mask
// construction, and a selector tree. Apps that want to write their
// own scoring circuits can ignore Argmax and compose from primitives
// directly.
//
// All ciphertext and key handles are passed as base64-encoded
// serialized OpenFHE objects on the wire. The helper does not retain
// state between ops — every call carries the contract params and
// rebuilds the CryptoContext. A persistent-session protocol that
// caches the context is on the roadmap but not in v1.
package helperclient
