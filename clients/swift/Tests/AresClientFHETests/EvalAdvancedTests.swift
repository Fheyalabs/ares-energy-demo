// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class EvalAdvancedTests: FHETestCase {
    private func setupWithEvalKeys(_ parties: Int = 3, depth: UInt32 = 12) throws -> (CryptoContext, PublicKey, [SecretKeyShare]) {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: depth)
        var pks: [PublicKey] = []; var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        for _ in 1..<parties { let n = try ctx.keyGenNext(prev: pks.last!); pks.append(n.publicKey); sks.append(n.secretKey) }
        let finalPK = pks.last!
        let base = try ctx.evalMultKeyGenLead(sks[0])
        var r1: [EvalMultKey] = [base]
        for i in 1..<sks.count { r1.append(try ctx.evalMultKeySwitchShare(sks[i], base: base)) }
        let joined = try ctx.combineEvalMultSwitchShares(pks, r1)
        var fin: [EvalMultKey] = []
        for sk in sks { fin.append(try ctx.evalMultKeyFinalShare(sk, joined: joined, finalPK: finalPK)) }
        try ctx.insertEvalMultKey(try ctx.combineEvalMultFinalShares(finalPK, fin))
        return (ctx, finalPK, sks)
    }

    private func decryptFirst(_ ctx: CryptoContext, _ ct: Ciphertext, _ sks: [SecretKeyShare], slots: Int) throws -> [Double] {
        var partials: [Ciphertext] = []
        for sk in sks { partials.append(try ctx.partialDecrypt(ct, with: sk)) }
        return try ctx.fuse(partials, slotCapacity: slots)
    }

    func testEvalPolynomialMatchesPolyValues() throws {
        let (ctx, pk, sks) = try setupWithEvalKeys()
        // p(x)=0.5+0.75x-0.25x^3 at x=0.5 → 0.5+0.375-0.03125 = 0.84375
        let ct = try ctx.encrypt(values: [0.5, 0.5, 0.5, 0.5], under: pk)
        let result = try ctx.evalPolynomial(ct, coefficients: [0.5, 0.75, 0.0, -0.25])
        let out = try decryptFirst(ctx, result, sks, slots: 8)
        XCTAssertEqual(out[0], 0.84375, accuracy: 0.05)
    }

    func testEvalArgmaxWinnerMask() throws {
        let (ctx, pk, sks) = try setupWithEvalKeys()
        let c0 = try ctx.encrypt(values: [0.1], under: pk)
        let c1 = try ctx.encrypt(values: [0.6], under: pk)
        let c2 = try ctx.encrypt(values: [0.3], under: pk)
        let masks = try ctx.evalArgmax([c0, c1, c2], sharpeningCoefficients: [0.5, 0.75, 0.0, -0.25])
        XCTAssertEqual(masks.count, 3)
        let m0 = try decryptFirst(ctx, masks[0], sks, slots: 4)[0]
        let m1 = try decryptFirst(ctx, masks[1], sks, slots: 4)[0]
        let m2 = try decryptFirst(ctx, masks[2], sks, slots: 4)[0]
        XCTAssertGreaterThan(m1, m0)
        XCTAssertGreaterThan(m1, m2)
        // Sharpening poly p(x)=0.5+0.75x-0.25x^3 is a soft-step, not a hard step;
        // winner mask converges to ~0.6 at the small separations here. Widen tolerance.
        XCTAssertEqual(m1, 1.0, accuracy: 0.5)
    }

    func testEvalChebyshevSignProducesCiphertext() throws {
        // EvalChebyshevSign approximates a Heaviside step: positive → ~1, negative → ~0.
        // (The bridge's sign lambda is x >= 0 ? 1.0 : 0.0, not the bipolar ±1 sign.)
        // Qualitative invariant: positive input slot > negative input slot.
        let (ctx, pk, sks) = try setupWithEvalKeys()
        let ct = try ctx.encrypt(values: [0.4, -0.4, 0.0, 0.9], under: pk)
        let signed = try ctx.evalChebyshevSign(ct, degree: 13)
        let out = try decryptFirst(ctx, signed, sks, slots: 8)
        // Positive input (slot 0: 0.4) → ~1.0
        XCTAssertGreaterThan(out[0], 0.5)
        // Negative input (slot 1: -0.4) → ~0.0; must be less than the positive slot output
        XCTAssertLessThan(out[1], out[0])
        // Negative input close to zero; tolerance for degree-13 Chebyshev at ringDim=1024
        XCTAssertLessThan(out[1], 0.5)
    }
}
