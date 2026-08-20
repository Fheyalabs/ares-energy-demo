//go:build openfhe

package pool

import "os"

// Tests deliberately use small, fast, sub-128-bit CKKS rings. The canonical
// bridge is secure-by-default (HEStd_128_classic) and rejects such rings, so the
// test binary opts out here. NEVER set ARES_FHE_ALLOW_INSECURE in production.
func init() { _ = os.Setenv("ARES_FHE_ALLOW_INSECURE", "1") }
