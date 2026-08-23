// SPDX-License-Identifier: Apache-2.0

// Package boundcheck is a generic, application-agnostic homomorphic bound
// check (ARES-BC, generalizing ARES v2.6 SC-5). Between input submission and
// scoring, it computes — per party uniformly — a single safe-to-decrypt
// squared magnitude ‖x - c‖² (public center c) over the party's encrypted
// input, threshold-decrypts it across the participant quorum, and aborts the
// session via an application-supplied ViolationHandler when the value falls
// outside the committed [lo, hi].
//
// NormCircuit (c=0, the SC-5 embedding norm check) and DistanceBoundCircuit
// (geo-radius, multi-dimensional resource budgets) are the built-in
// squared-magnitude circuits. Inputs must be multi-dimensional: the phase
// refuses dim < 2, because for a scalar the squared magnitude reveals the
// value up to a sign (scalar range needs a homomorphic-comparison circuit).
// Circuit depth is determined offline with pkg/ares/crypto/fhecalib.
//
// The phase computes each enc_check and Provides them under
// CtxBoundCheckCiphers; the consuming application is responsible for
// unicasting them to participants, who reply with bound_check.partial
// (their partial decrypt of each check ciphertext).
package boundcheck
