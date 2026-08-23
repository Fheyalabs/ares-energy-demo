// SPDX-License-Identifier: Apache-2.0

// Package fhecalib determines the minimum CKKS multiplicative depth a
// homomorphic circuit needs for a given use case.
//
// Usage: implement CircuitUnderTest for your circuit (provide representative
// Inputs, the plaintext Expected result, and an Eval that runs the circuit via
// the ContextHandle), then call Calibrate (requires the `openfhe` build tag and
// a working OpenFHE install). Calibrate sweeps depth over a minimal two-party
// threshold context — depth and precision are party-count-independent, so the
// result transfers to any party count — and returns the minimum depth whose
// decrypted output matches Expected within the configured tolerance. If a depth
// would exceed the 128-bit-classic ciphertext-modulus budget for the ring
// dimension, Calibrate returns ErrModulusCap so the caller can raise RingDim.
//
// fhecalib is a development / CI calibration tool. Run it once for a use case
// and bake the resulting depth into the production context configuration; do
// not call it on a per-session hot path.
package fhecalib
