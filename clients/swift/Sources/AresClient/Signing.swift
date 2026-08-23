import Foundation
import Crypto

public enum Signing {
    /// Compact, sorted-keys JSON — matches the server's canonicalPayloadFromRawMap.
    ///
    /// WARNING (L3 gotcha): `.sortedKeys` sorts ALL nesting levels recursively in
    /// Swift's `JSONSerialization`, whereas the Go server's `canonicalPayloadFromRawMap`
    /// sorts only top-level keys. Payloads containing nested maps MUST be audited for
    /// sort-order parity before L3 server round-trip testing.
    public static func canonicalJSON(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object,
                                   options: [.sortedKeys, .withoutEscapingSlashes])
    }

    /// Ed25519 device signature over `label|sessionID|canonical`, the format the
    /// server's verifySignedPayload reconstructs. Returns the raw 64-byte signature.
    public static func deviceSign(deviceKey: Curve25519.Signing.PrivateKey,
                                  label: String, sessionID: String, canonical: Data) throws -> Data {
        var message = Data("\(label)|\(sessionID)|".utf8)
        message.append(canonical)
        return try Data(deviceKey.signature(for: message))
    }
}
