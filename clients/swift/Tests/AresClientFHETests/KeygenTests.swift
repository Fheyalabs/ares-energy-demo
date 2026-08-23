// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class KeygenTests: FHETestCase {
    func testThreePartyKeygenChain() throws {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        var pks: [PublicKey] = []
        var sks: [SecretKeyShare] = []
        let first = try ctx.keyGenFirst()
        pks.append(first.publicKey); sks.append(first.secretKey)
        for _ in 1..<3 {
            let nxt = try ctx.keyGenNext(prev: pks.last!)
            pks.append(nxt.publicKey); sks.append(nxt.secretKey)
        }
        XCTAssertEqual(pks.count, 3)
        XCTAssertEqual(sks.count, 3)
        XCTAssertNotNil(pks.last)
    }
}
