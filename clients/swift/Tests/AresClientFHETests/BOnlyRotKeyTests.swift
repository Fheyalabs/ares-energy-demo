// SPDX-License-Identifier: Apache-2.0

import XCTest
import Foundation
@testable import AresClientFHE

final class BOnlyRotKeyTests: FHETestCase {
    // The multiparty rotation-key 'a'-vectors are shared across parties, so a
    // participant transmits only its 'b'-vectors and the combiner rebuilds the full
    // share from the shared 'a' + the party 'b'. Checks that 'a' is shared, the
    // b-only payload is smaller than the full share, and the rebuilt share's (a,b)
    // match the originals.
    func testBOnlyRotKeyReconstruction() throws {
        let ctx = try CryptoContext(ringDim: 1024, scalingFactor: Double(UInt64(1) << 50), depth: 2)
        var pks: [PublicKey] = []
        var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        let n = try ctx.keyGenNext(prev: pks.last!); pks.append(n.publicKey); sks.append(n.secretKey)

        let base = try ctx.evalSumKeyGenLead(sks[0])
        let share = try ctx.evalSumKeyShare(sks[1], base: base, ownPK: pks[1])

        let full = try ctx.serialize(share)
        let aBase = try ctx.serializeAVectors(base)
        let aShare = try ctx.serializeAVectors(share)
        let bShare = try ctx.serializeBVectors(share)

        // 'a' is the shared CRS, byte-identical across parties.
        XCTAssertEqual(aBase, aShare, "rotation-key 'a' must be shared across parties")
        XCTAssertLessThan(bShare.count, full.count, "b-only payload must be smaller than the full share")

        let recon = try ctx.reconstructRotKey(a: aBase, b: bShare)
        XCTAssertEqual(try ctx.serializeAVectors(recon), aBase, "reconstructed 'a' must equal the shared 'a'")
        XCTAssertEqual(try ctx.serializeBVectors(recon), bShare, "reconstructed 'b' must equal the transmitted 'b'")
    }
}
