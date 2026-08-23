// SPDX-License-Identifier: Apache-2.0

import XCTest
import COpenFHEBridge
@testable import AresClientFHE

final class SmokeTests: FHETestCase {
    func testLinkedOpenFHEVersion() {
        XCTAssertEqual(AresFHE.openFHEVersion(), "v1.5.1")
    }
    func testBuiltinSmokeReturnsZero() {
        var err = [CChar](repeating: 0, count: 1024)
        let rc = ARESOpenFHESmoke(&err, 1024)
        XCTAssertEqual(rc, 0, "ARESOpenFHESmoke: \(String(cString: err))")
    }
}
