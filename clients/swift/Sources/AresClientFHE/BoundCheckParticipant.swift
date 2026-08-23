// SPDX-License-Identifier: Apache-2.0

import Foundation
import Crypto

/// Outcome of participating in an ARES-BC bound check. `passed` is the IMPLICIT integrity
/// verdict (the lib verified the server's check_commitment automatically); the app decides
/// what to do with a `false` (abort / penalize / proceed) — that policy is the app's.
public struct BoundCheckResult: Sendable {
    public let passed: Bool
    public let partial: Data   // this party's partial decryption of enc_check (to send as bound_check.partial)
}

public enum BoundCheckParticipant {
    /// commitment = SHA256( enc_check || SHA256(enc_x) || session_id ) — matches
    /// pkg/ares/phase/boundcheck/phase.go (the server binds enc_check to the submitted input).
    public static func commitment(encCheck: Data, encX: Data, sessionID: String) -> Data {
        var inner = SHA256(); inner.update(data: encX)
        var outer = SHA256()
        outer.update(data: encCheck)
        outer.update(data: Data(inner.finalize()))
        outer.update(data: Data(sessionID.utf8))
        return Data(outer.finalize())
    }

    /// Implicitly verify the server's commitment, then partial-decrypt enc_check. The app
    /// receives only `BoundCheckResult` — never the hash mechanics.
    public static func participate(
        ctx: CryptoContext, encCheckBytes: Data, encXBytes: Data,
        sessionID: String, expectedCommitment: Data, with sk: SecretKeyShare
    ) throws -> BoundCheckResult {
        let recomputed = commitment(encCheck: encCheckBytes, encX: encXBytes, sessionID: sessionID)
        let passed = constantTimeEquals(recomputed, expectedCommitment)
        let ct = try ctx.deserializeCiphertext(encCheckBytes)
        let partial = try ctx.serialize(try ctx.partialDecrypt(ct, with: sk))
        return BoundCheckResult(passed: passed, partial: partial)
    }

    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
