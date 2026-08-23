// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class EvalRoundTripTests: FHETestCase {
    func testFullThresholdSmokePortYields17_0625() throws {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        var pks: [PublicKey] = []; var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        for _ in 1..<3 { let n = try ctx.keyGenNext(prev: pks.last!); pks.append(n.publicKey); sks.append(n.secretKey) }

        for sk in sks {
            _ = try ctx.genEvalMultKeyShare(sk)
            _ = try ctx.genRotKeyShare(sk)
        }

        let jointPK = pks.last!
        let input: [Double] = [1.25, -2.5, 3.0, 0.5]
        let ct = try ctx.encrypt(values: input, under: jointPK)

        let doubled = try ctx.evalAdd(ct, ct)
        let restored = try ctx.evalMultConst(doubled, 0.5)
        let squared = try ctx.evalMult(restored, restored)
        let summed = try ctx.evalSum(squared, batchSize: input.count)

        var partials: [Ciphertext] = []
        for sk in sks { partials.append(try ctx.partialDecrypt(summed, with: sk)) }
        let out = try ctx.fuse(partials, slotCapacity: 8)

        XCTAssertEqual(out[0], 17.0625, accuracy: 0.05)
    }
}
