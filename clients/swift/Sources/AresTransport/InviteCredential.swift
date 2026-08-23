// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Mints ARES invite credentials — the `credential_blob` for `POST /v2/register`
/// — matching the server's `auth.CredentialIssuerService`
/// (internal/auth/credentials.go). The credential is an HMAC-SHA256-signed JSON
/// envelope; the signature covers the sorted `key=value` claim parts, each
/// followed by a `0x00` byte (`signClaims` / `canonicalClaimParts`). The server's
/// `VerifyCredentialBlob` checks only the signature, expiry, and version/issuer —
/// not the subject — so one minted invite credential registers any participant.
///
/// The signing key is the deployment's `ARES_CREDENTIAL_SIGNING_KEY` (hex-decoded
/// when ≥32 bytes, else raw UTF-8). Keep it out of source — pass it from the
/// environment at runtime.
public struct InviteCredential {
    private let signingKey: SymmetricKey

    public init(signingKey raw: String) {
        if let decoded = Self.hexDecode(raw), decoded.count >= 32 {
            self.signingKey = SymmetricKey(data: decoded)
        } else {
            self.signingKey = SymmetricKey(data: Data(raw.utf8))
        }
    }

    /// Mint an invite credential blob (raw JSON; the server also accepts
    /// base64(JSON)) for `accountID`.
    public func mint(accountID: String, now: Date = Date(),
                     ttl: TimeInterval = 30 * 24 * 3600) -> Data {
        let issuer = "fheya-auth-v1"
        let provider = "invite"
        let nonce = Self.randomHex(16)
        let tokenHash = Self.sha256Hex("\(accountID)|invite")
        let subjectHash = Self.sha256Hex("\(issuer)|\(provider)|\(accountID)|\(nonce)")
        let issuedAt = Int64(now.timeIntervalSince1970)
        let expiresAt = Int64((now + ttl).timeIntervalSince1970)

        let signature = signClaims(issuer: issuer, provider: provider, nonce: nonce,
                                   subjectHash: subjectHash, tokenHash: tokenHash,
                                   issuedAt: issuedAt, expiresAt: expiresAt)

        // account_id omitted (empty → omitempty server-side). The server re-signs
        // from the unmarshalled claims, so envelope key order is irrelevant.
        let claims: [String: Any] = [
            "version": 1, "issuer": issuer, "subject_hash": subjectHash,
            "provider": provider, "token_hash": tokenHash, "nonce": nonce,
            "issued_at": issuedAt, "expires_at": expiresAt,
        ]
        let envelope: [String: Any] = ["claims": claims, "signature": signature]
        return (try? JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])) ?? Data()
    }

    /// HMAC-SHA256 over the sorted `key=value` parts (each + `0x00`), hex-encoded —
    /// mirrors the server `signClaims` / `canonicalClaimParts`. `account_id` is
    /// always empty on the issue() path.
    func signClaims(issuer: String, provider: String, nonce: String,
                    subjectHash: String, tokenHash: String,
                    issuedAt: Int64, expiresAt: Int64) -> String {
        let parts = [
            "account_id=",
            "expires_at=\(expiresAt)",
            "issued_at=\(issuedAt)",
            "issuer=\(issuer)",
            "nonce=\(nonce)",
            "provider=\(provider)",
            "subject_hash=\(subjectHash)",
            "token_hash=\(tokenHash)",
            "version=1",
        ].sorted()
        var mac = HMAC<SHA256>(key: signingKey)
        for part in parts {
            mac.update(data: Data(part.utf8))
            mac.update(data: Data([0]))
        }
        return Self.hexEncode(Data(mac.finalize()))
    }

    static func sha256Hex(_ s: String) -> String {
        hexEncode(Data(SHA256.hash(data: Data(s.utf8))))
    }

    static func randomHex(_ n: Int) -> String {
        let key = SymmetricKey(size: SymmetricKeySize(bitCount: n * 8))
        return key.withUnsafeBytes { hexEncode(Data($0)) }
    }

    static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func hexDecode(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var d = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            d.append(b); i = j
        }
        return d
    }
}
