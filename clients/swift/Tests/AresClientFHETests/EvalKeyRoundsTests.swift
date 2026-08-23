// SPDX-License-Identifier: Apache-2.0

import XCTest
import Foundation
@testable import AresClientFHE

final class EvalKeyRoundsTests: FHETestCase {
    func testEvalMultKeyRoundProtocolInstallsAndMultWorks() throws {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        var pks: [PublicKey] = []; var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        for _ in 1..<3 { let n = try ctx.keyGenNext(prev: pks.last!); pks.append(n.publicKey); sks.append(n.secretKey) }
        let finalPK = pks.last!

        let base = try ctx.evalMultKeyGenLead(sks[0])
        var round1: [EvalMultKey] = [base]
        for i in 1..<sks.count { round1.append(try ctx.evalMultKeySwitchShare(sks[i], base: base)) }
        let joined = try ctx.combineEvalMultSwitchShares(pks, round1)
        var finalShares: [EvalMultKey] = []
        for sk in sks { finalShares.append(try ctx.evalMultKeyFinalShare(sk, joined: joined, finalPK: finalPK)) }
        let evalMultKey = try ctx.combineEvalMultFinalShares(finalPK, finalShares)
        try ctx.insertEvalMultKey(evalMultKey)

        let data = try ctx.serialize(evalMultKey)
        XCTAssertFalse(data.isEmpty)
        _ = try ctx.deserializeEvalMultKey(data)

        let ct = try ctx.encrypt(values: [2.0, 3.0, 4.0, 5.0], under: finalPK)
        let squared = try ctx.evalMult(ct, ct)
        var partials: [Ciphertext] = []
        for sk in sks { partials.append(try ctx.partialDecrypt(squared, with: sk)) }
        let out = try ctx.fuse(partials, slotCapacity: 8)
        XCTAssertEqual(out[0], 4.0, accuracy: 0.1)
        XCTAssertEqual(out[1], 9.0, accuracy: 0.1)
    }

    func testEvalSumKeyRoundProtocolInstalls() throws {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        var pks: [PublicKey] = []; var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        for _ in 1..<3 { let n = try ctx.keyGenNext(prev: pks.last!); pks.append(n.publicKey); sks.append(n.secretKey) }

        let base = try ctx.evalSumKeyGenLead(sks[0])
        var shares: [RotKey] = [base]
        for i in 1..<sks.count { shares.append(try ctx.evalSumKeyShare(sks[i], base: base, ownPK: pks[i])) }
        let sumKey = try ctx.combineEvalSumKeys(pks, shares)
        try ctx.insertEvalSumKey(sumKey)

        let data = try ctx.serialize(sumKey)
        XCTAssertFalse(data.isEmpty)
        _ = try ctx.deserializeRotKey(data)

        // Prove the installed eval-sum key actually enables EvalSum end-to-end.
        let jointPK = pks.last!
        let input: [Double] = [1.0, 2.0, 3.0, 4.0]   // sum = 10.0
        let ct = try ctx.encrypt(values: input, under: jointPK)
        let summed = try ctx.evalSum(ct, batchSize: input.count)
        var partials: [Ciphertext] = []
        for sk in sks { partials.append(try ctx.partialDecrypt(summed, with: sk)) }
        let out = try ctx.fuse(partials, slotCapacity: 8)
        XCTAssertEqual(out[0], 10.0, accuracy: 0.05)
    }
}
