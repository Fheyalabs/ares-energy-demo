// SPDX-License-Identifier: Apache-2.0

import XCTest
import Foundation
@testable import AresClientFHE

final class SerializationTests: FHETestCase {
    private func threeParties() throws -> (CryptoContext, PublicKey, [SecretKeyShare]) {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        var pks: [PublicKey] = []; var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        for _ in 1..<3 { let n = try ctx.keyGenNext(prev: pks.last!); pks.append(n.publicKey); sks.append(n.secretKey) }
        return (ctx, pks.last!, sks)
    }

    func testPublicKeyAndCiphertextSerializationRoundTrip() throws {
        let (ctx, jointPK, sks) = try threeParties()
        let pkData = try ctx.serialize(jointPK)
        XCTAssertFalse(pkData.isEmpty)
        let pk2 = try ctx.deserializePublicKey(pkData)

        let input: [Double] = [0.5, 1.5, -1.0, 2.0]
        let ct = try ctx.encrypt(values: input, under: pk2)
        let ctData = try ctx.serialize(ct)
        XCTAssertFalse(ctData.isEmpty)
        let ct2 = try ctx.deserializeCiphertext(ctData)

        var partials: [Ciphertext] = []
        for sk in sks { partials.append(try ctx.partialDecrypt(ct2, with: sk)) }
        let out = try ctx.fuse(partials, slotCapacity: 8)
        for (i, want) in input.enumerated() { XCTAssertEqual(out[i], want, accuracy: 0.05) }
    }

    func testDeserializeCiphertextUnderMismatchedContextThrows() throws {
        let (ctx, jointPK, _) = try threeParties()
        let ct = try ctx.encrypt(values: [1.0, 2.0], under: jointPK)
        let ctData = try ctx.serialize(ct)
        let other = try CryptoContext(ringDim: 2048, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        // Invariant under test: mismatch surfaces as a THROWN FHEError, never a crash.
        XCTAssertThrowsError(try other.deserializeCiphertext(ctData)) { err in
            let e = err as? FHEError
            XCTAssertTrue(e == .contextMismatch || e == .deserializeFailed, "got \(String(describing: e))")
        }
    }
}
