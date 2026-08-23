// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class ContextLifecycleTests: FHETestCase {
    func testGlobalContextReleaseClearsFactoryAfterContextIsDropped() throws {
        var context: CryptoContext? = try CryptoContext(
            ringDim: 1024,
            scalingFactor: Double(UInt64(1) << 50),
            depth: 2
        )
        XCTAssertGreaterThan(CryptoContext.openFHEContextCount(), 0)
        XCTAssertNotNil(context)

        context = nil
        CryptoContext.releaseOpenFHEGlobalContexts()

        XCTAssertEqual(CryptoContext.openFHEContextCount(), 0)
    }
}
