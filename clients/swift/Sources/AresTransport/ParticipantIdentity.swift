// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Per-participant secrets for one session: the 32-byte-hex pseudonym (the
/// server's `match_pseudonym`, also the WS `pseudonym` and the HMAC auth
/// subject), the Ed25519 device identity that signs protocol messages, a 32-byte
/// link-key public value, and a single-use registration nullifier. All generated
/// fresh for a test session; the device key is what the server verifies signatures
/// against after `/v2/register`. (`lkPub` is registered but unused on the
/// openfhe_full happy path — the deprecated LK commitments aren't in that flow.)
public struct ParticipantIdentity {
    public let pseudonym: String       // 32-byte hex
    public let device: DeviceIdentity  // Ed25519 signer
    public let lkPubHex: String        // 32-byte hex
    public let nullifier: String       // 32-byte hex, single-use

    public init(device: DeviceIdentity = DeviceIdentity()) {
        self.pseudonym = Self.randomHex(32)
        self.device = device
        self.lkPubHex = Self.randomHex(32)
        self.nullifier = Self.randomHex(32)
    }

    static func randomHex(_ n: Int) -> String {
        let key = SymmetricKey(size: SymmetricKeySize(bitCount: n * 8))
        return key.withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
    }
}
