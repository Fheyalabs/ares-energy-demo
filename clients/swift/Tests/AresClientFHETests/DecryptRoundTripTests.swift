// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class DecryptRoundTripTests: FHETestCase {
    func testThreePartyEncryptDecryptRecoversInput() throws {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        var pks: [PublicKey] = []
        var sks: [SecretKeyShare] = []
        let first = try ctx.keyGenFirst()
        pks.append(first.publicKey); sks.append(first.secretKey)
        for _ in 1..<3 {
            let nxt = try ctx.keyGenNext(prev: pks.last!)
            pks.append(nxt.publicKey); sks.append(nxt.secretKey)
        }
        let jointPK = pks.last!   // chained joint key

        let input: [Double] = [1.25, -2.5, 3.0, 0.5]
        let ct = try ctx.encrypt(values: input, under: jointPK)

        var partials: [Ciphertext] = []
        for sk in sks {
            partials.append(try ctx.partialDecrypt(ct, with: sk))
        }
        let out = try ctx.fuse(partials, slotCapacity: 8)

        XCTAssertGreaterThanOrEqual(out.count, 4)
        for (i, want) in input.enumerated() {
            XCTAssertEqual(out[i], want, accuracy: 0.05, "slot \(i)")
        }
    }
}
