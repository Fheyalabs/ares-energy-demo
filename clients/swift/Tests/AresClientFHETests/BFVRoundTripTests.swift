// SPDX-License-Identifier: Apache-2.0

import XCTest
@testable import AresClientFHE

final class BFVRoundTripTests: FHETestCase {
    func testBFVPackedIntRoundTrip() throws {
        let ctx = try BFVCryptoContext(
            ringDim: 8192,
            multiplicativeDepth: 4,
            plaintextModulus: 65537,
            batchSize: 8
        )
        let first = try ctx.keyGenFirst()
        let second = try ctx.keyGenNext(prev: first.publicKey)
        let ct = try ctx.encrypt(intValues: [-3, 0, 42, -1], under: second.publicKey)
        let p0 = try ctx.partialDecrypt(ct, with: first.secretKey)
        let p1 = try ctx.partialDecrypt(ct, with: second.secretKey)
        let out = try ctx.fuseInt([p0, p1], slotCapacity: 4)
        XCTAssertEqual(out, [-3, 0, 42, -1])
    }

    func testBFVEncryptedSquaredDistanceIsExactAcrossPackedSlots() throws {
        let ctx = try BFVCryptoContext(
            ringDim: 1024,
            multiplicativeDepth: 4,
            plaintextModulus: 65537,
            batchSize: 128
        )
        let share = try ctx.singleKeyGen()
        let originFirst = try ctx.encryptRepeatedScalarBFV(10, publicKey: share.publicKey)
        let originSecond = try ctx.encryptRepeatedScalarBFV(20, publicKey: share.publicKey)
        let distance = try ctx.encryptedSquaredDistanceBFV(
            originFirst: originFirst,
            originSecond: originSecond,
            localFirst: 7,
            localSecond: 24
        )

        let ciphertext = try ctx.deserializeCiphertext(distance)
        let partial = try ctx.partialDecrypt(ciphertext, with: share.secretKey)
        let slots = try ctx.fuseInt([partial], slotCapacity: 128)

        XCTAssertEqual(slots.count, 128)
        for (index, slot) in slots.enumerated() {
            XCTAssertEqual(slot, 25, "slot \(index)")
        }
    }

    func testBFVEncryptedSquaredDistanceRejectsMalformedOrigins() throws {
        let ctx = try BFVCryptoContext(
            ringDim: 1024,
            multiplicativeDepth: 4,
            plaintextModulus: 65537,
            batchSize: 128
        )

        XCTAssertThrowsError(try ctx.encryptedSquaredDistanceBFV(
            originFirst: Data([0x01]),
            originSecond: Data([0x02]),
            localFirst: 0,
            localSecond: 0
        ))
    }
}
