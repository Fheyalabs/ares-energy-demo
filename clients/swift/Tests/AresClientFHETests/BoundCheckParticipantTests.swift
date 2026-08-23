// SPDX-License-Identifier: Apache-2.0

import XCTest
import Crypto
@testable import AresClientFHE

final class BoundCheckParticipantTests: FHETestCase {
    // Build a context + a 2-party key so we have real serialized ciphertexts.
    private func setup() throws -> (CryptoContext, PublicKey, SecretKeyShare, SecretKeyShare) {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 4)
        let a = try ctx.keyGenFirst(); let b = try ctx.keyGenNext(prev: a.publicKey)
        return (ctx, b.publicKey, a.secretKey, b.secretKey)
    }

    func testImplicitCheckPassesOnCorrectCommitment() throws {
        let (ctx, pk, sk0, _) = try setup()
        let encX = try ctx.serialize(try ctx.encrypt(values: [0.5, 0, 0, 0], under: pk))
        let encCheck = try ctx.serialize(try ctx.encrypt(values: [1.0, 0, 0, 0], under: pk)) // stand-in for ||x-c||^2
        let sid = "adm-1"
        let commitment = BoundCheckParticipant.commitment(encCheck: encCheck, encX: encX, sessionID: sid)
        let result = try BoundCheckParticipant.participate(
            ctx: ctx, encCheckBytes: encCheck, encXBytes: encX,
            sessionID: sid, expectedCommitment: commitment, with: sk0)
        XCTAssertTrue(result.passed)
        XCTAssertFalse(result.partial.isEmpty)   // a real partial decryption was produced
    }

    func testImplicitCheckFailsOnTamperedEncCheck() throws {
        let (ctx, pk, sk0, _) = try setup()
        let encX = try ctx.serialize(try ctx.encrypt(values: [0.5, 0, 0, 0], under: pk))
        let encCheck = try ctx.serialize(try ctx.encrypt(values: [1.0, 0, 0, 0], under: pk))
        let sid = "adm-1"
        let commitment = BoundCheckParticipant.commitment(encCheck: encCheck, encX: encX, sessionID: sid)
        // Server tampers: sends a DIFFERENT enc_check than the one the commitment bound.
        let tampered = try ctx.serialize(try ctx.encrypt(values: [9.0, 0, 0, 0], under: pk))
        let result = try BoundCheckParticipant.participate(
            ctx: ctx, encCheckBytes: tampered, encXBytes: encX,
            sessionID: sid, expectedCommitment: commitment, with: sk0)
        XCTAssertFalse(result.passed)             // implicit check catches the swap
    }

    func testCommitmentMatchesGoAlgorithm() {
        // commitment = SHA256( enc_check || SHA256(enc_x) || session_id )
        let encCheck = Data([0x01, 0x02]); let encX = Data([0x03, 0x04]); let sid = "s"
        var inner = SHA256(); inner.update(data: encX)
        var outer = SHA256(); outer.update(data: encCheck); outer.update(data: Data(inner.finalize())); outer.update(data: Data(sid.utf8))
        let expected = Data(outer.finalize())
        XCTAssertEqual(BoundCheckParticipant.commitment(encCheck: encCheck, encX: encX, sessionID: sid), expected)
    }
}
