//go:build openfhe

package cgo

import "os"

// Tests deliberately use small, fast, sub-128-bit CKKS rings. The canonical
// bridge is secure-by-default (HEStd_128_classic) and rejects such rings, so the
// test binary opts out here. NEVER set ARES_FHE_ALLOW_INSECURE in production.
// See ares_fhe_allow_insecure in pkg/ares/crypto/cgo/openfhe_wrapper.cpp.
func init() { _ = os.Setenv("ARES_FHE_ALLOW_INSECURE", "1") }
