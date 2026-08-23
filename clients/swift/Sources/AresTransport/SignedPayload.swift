// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Builds device-signed protocol payloads byte-compatible with the server's
/// `verifySignedPayload` / `canonicalPayloadFromRawMap`
/// (internal/engine/payload_validation.go).
///
/// The server canonicalizes a payload by removing the `sig` field, sorting the
/// remaining **top-level** keys, and concatenating `{"k1":v1,"k2":v2}` using each
/// value's *received* JSON bytes — nested objects are used verbatim, not
/// re-sorted. The signed message is `label|sessionID|<canonical>`, verified as
/// Ed25519 against the registered device key.
///
/// Callers pass each top-level field as a (key, exact-JSON-value) pair. The same
/// value bytes are used for both the canonical (what we sign) and the wire
/// payload (what we send), so the server's re-canonicalization is identical.
public enum SignedPayload {

    /// A top-level field: the key and its already-encoded, compact JSON value
    /// (e.g. `("share", "\"ab12\"")`, `("openfhe", "{\"protocol\":\"…\"}")`,
    /// `("lat_q", "1234")`).
    public typealias Field = (key: String, valueJSON: String)

    /// The server-canonical form: sorted top-level keys, compact, no whitespace.
    public static func canonical(_ fields: [Field]) -> String {
        let body = fields
            .sorted { $0.key < $1.key }
            .map { "\(jsonKey($0.key)):\($0.valueJSON)" }
            .joined(separator: ",")
        return "{\(body)}"
    }

    /// The wire payload: the canonical fields plus a `sig` hex field carrying the
    /// Ed25519 signature over `label|sessionID|canonical`. The server strips
    /// `sig`, re-canonicalizes the rest, and checks the signature — so send order
    /// is irrelevant, but value bytes must match what we signed (they do).
    public static func signed(label: String, sessionID: String,
                              fields: [Field], identity: DeviceIdentity) throws -> Data {
        let canon = canonical(fields)
        let message = Data("\(label)|\(sessionID)|".utf8) + Data(canon.utf8)
        let sigHex = DeviceIdentity.hex(try identity.sign(message))
        let sigField = "\(jsonKey("sig")):\"\(sigHex)\""
        let wire = fields.isEmpty
            ? "{\(sigField)}"
            : "\(String(canon.dropLast())),\(sigField)}"
        return Data(wire.utf8)
    }

    static func jsonKey(_ key: String) -> String {
        "\"\(key.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\""
    }
}
