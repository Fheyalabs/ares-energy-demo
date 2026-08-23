// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// An Ed25519 device identity. The 32-byte public key is registered with the
/// server (POST /v2/register); thereafter every signed protocol message carries
/// an Ed25519 signature this identity produces over `label|sessionID|canonical`
/// (see ``SignedPayload``). Matches the server's
/// `arescrypto.VerifyDeviceSignature` — ed25519, 32-byte public key, 64-byte
/// signature (internal/crypto/signatures.go).
public struct DeviceIdentity: @unchecked Sendable {
    // @unchecked: the only stored property is an immutable Ed25519 private key and
    // signing is a pure read, so the value is safe to share across actors even
    // though Curve25519.Signing.PrivateKey is not itself Sendable.
    public let privateKey: Curve25519.Signing.PrivateKey

    /// Generate a fresh device identity.
    public init() {
        self.privateKey = Curve25519.Signing.PrivateKey()
    }

    /// Restore an identity from a stored 32-byte Ed25519 seed.
    public init(rawPrivateKey: Data) throws {
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
    }

    /// The 32-byte Ed25519 public key.
    public var publicKeyRaw: Data { privateKey.publicKey.rawRepresentation }

    /// The public key as lowercase hex — the `share` field of `keygen.share` and
    /// the value registered with the server.
    public var publicKeyHex: String { Self.hex(publicKeyRaw) }

    /// Ed25519 signature (64 bytes) over `message`.
    public func sign(_ message: Data) throws -> Data {
        try privateKey.signature(for: message)
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
