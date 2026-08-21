// SPDX-License-Identifier: Apache-2.0

//go:build !openfhe

package main

import "errors"

// ClientEncryption mirrors the openfhe build's seam marker so the
// non-tagged build compiles.
const ClientEncryption = "unavailable (build with -tags openfhe)"

// RunClearing is unavailable without OpenFHE. The demo deliberately has
// no plaintext fallback: a pool demo whose clearing is not actually
// homomorphic would misrepresent the entire point.
func (s *Session) RunClearing() (*Outcome, error) {
	return nil, errors.New("pool_demo: clearing requires the openfhe build tag")
}
