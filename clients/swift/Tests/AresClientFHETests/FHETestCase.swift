// SPDX-License-Identifier: Apache-2.0

import XCTest
import Foundation

/// Base class for AresClientFHE tests. These tests use small, fast, deliberately
/// sub-128-bit CKKS rings; the canonical bridge is secure-by-default
/// (`HEStd_128_classic`) and would reject such rings, so the test process opts out
/// via `ARES_FHE_ALLOW_INSECURE`. The bridge prints a one-time warning. NEVER set
/// this in production. See `ares_fhe_allow_insecure` in openfhe_wrapper.cpp.
class FHETestCase: XCTestCase {
    override class func setUp() {
        super.setUp()
        setenv("ARES_FHE_ALLOW_INSECURE", "1", 1)
    }
}
