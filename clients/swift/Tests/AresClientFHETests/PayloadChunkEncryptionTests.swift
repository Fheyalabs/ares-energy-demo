// SPDX-License-Identifier: Apache-2.0

import Foundation
import XCTest
@testable import AresClientFHE

final class PayloadChunkEncryptionTests: FHETestCase {
    func testEncryptPayloadChunksPreservesMSBFirstBits() throws {
        let ctx = try CryptoContext(
            ringDim: 1024,
            scalingFactor: Double(UInt64(1) << 50),
            depth: 4,
            batchSize: 128
        )
        let share = try ctx.keyGenFirst()
        var payload = Data(repeating: 0, count: 80)
        payload[0] = 0x80
        payload[1] = 0x01
        payload[79] = 0x81

        let chunks = try ctx.encryptPayloadChunks(payload: payload, publicKey: share.publicKey, chunkSize: 128)
        XCTAssertEqual(chunks.count, 5)

        for (chunkIndex, serialized) in chunks.enumerated() {
            let ciphertext = try ctx.deserializeCiphertext(serialized)
            let partial = try ctx.partialDecrypt(ciphertext, with: share.secretKey)
            let slots = try ctx.fuse([partial], slotCapacity: 128)
            for slot in slots.indices {
                let bitIndex = chunkIndex * 128 + slot
                let expected = Double((payload[bitIndex / 8] >> UInt8(7 - (bitIndex % 8))) & 1)
                XCTAssertEqual(slots[slot], expected, accuracy: 0.05, "bit \(bitIndex)")
            }
        }
    }

    func testEncryptPayloadChunksRejectsInvalidChunkSizeAndLength() throws {
        let ctx = try CryptoContext(
            ringDim: 1024,
            scalingFactor: Double(UInt64(1) << 50),
            depth: 4,
            batchSize: 128
        )
        let share = try ctx.keyGenFirst()

        XCTAssertThrowsError(try ctx.encryptPayloadChunks(
            payload: Data(repeating: 0, count: 80), publicKey: share.publicKey, chunkSize: 64
        ))
        XCTAssertThrowsError(try ctx.encryptPayloadChunks(
            payload: Data(repeating: 0, count: 79), publicKey: share.publicKey, chunkSize: 128
        ))
    }
}
