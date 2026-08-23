import Foundation
import AresClient   // DAGNode

/// A client-owned, durably persisted position in a recipient's server outbox.
/// The transport never advances this value automatically.
public struct WSReplayCursor: Codable, Equatable, Hashable, Sendable {
    public let sequence: Int64

    public init(sequence: Int64) throws {
        guard sequence >= 0 else {
            throw TransportError.dialFailed("negative resume cursor")
        }
        self.sequence = sequence
    }
}

public struct InboundFrame: Sendable {
    public let type: String
    public let sessionID: String
    public let seq: Int
    public let payload: Data?       // raw JSON bytes of the payload value, if present
    public let version: String
    public let raw: Data
}

public enum WSFrame {
    /// Encode an outbound frame. `payloadJSON` is the raw JSON bytes of the payload value,
    /// inlined verbatim (no re-encoding). A non-nil `lineage` sets version="2".
    public static func encodeOutbound(type: String, sessionID: String, seq: Int,
                                      payloadJSON: Data?, lineage: DAGNode?) throws -> Data {
        func esc(_ s: String) -> String {
            "\"" + s.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        var top: [String] = ["\"type\":\(esc(type))", "\"session_id\":\(esc(sessionID))", "\"seq\":\(seq)"]
        if let payloadJSON { top.append("\"payload\":\(String(decoding: payloadJSON, as: UTF8.self))") }
        if let lineage {
            top.append("\"version\":\"2\"")
            let lineageData = try JSONEncoder().encode(lineage)
            top.append("\"lineage\":\(String(decoding: lineageData, as: UTF8.self))")
        }
        return Data(("{" + top.joined(separator: ",") + "}").utf8)
    }

    public static func decodeInbound(_ raw: Data) throws -> InboundFrame {
        let obj = (try JSONSerialization.jsonObject(with: raw)) as? [String: Any] ?? [:]
        let payloadData = RawTopLevelJSONValue.extract(key: "payload", from: raw)
        let seq = (obj["seq"] as? NSNumber)?.intValue ?? (obj["seq"] as? Int) ?? 0
        return InboundFrame(
            type: obj["type"] as? String ?? "",
            sessionID: obj["session_id"] as? String ?? "",
            seq: seq, payload: payloadData,
            version: obj["version"] as? String ?? "", raw: raw)
    }
}

/// Extracts one validated top-level JSON value without reserializing it.
///
/// `JSONSerialization` remains the authority for whole-frame validity above.
/// This scanner exists solely because serializing a parsed payload changes legal
/// JSON spellings such as raw standard-base64 `/` into `\/`, breaking byte-bound
/// inner protocols.
private enum RawTopLevelJSONValue {
    static func extract(key: String, from raw: Data) -> Data? {
        let bytes = Array(raw)
        var cursor = 0
        skipWhitespace(bytes, &cursor)
        guard consume(0x7b, bytes, &cursor) else { // {
            return nil
        }
        skipWhitespace(bytes, &cursor)

        var result: Data?
        while cursor < bytes.count, bytes[cursor] != 0x7d { // }
            guard let name = parseString(bytes, &cursor) else {
                return nil
            }
            skipWhitespace(bytes, &cursor)
            guard consume(0x3a, bytes, &cursor) else { // :
                return nil
            }
            skipWhitespace(bytes, &cursor)
            let valueStart = cursor
            guard skipValue(bytes, &cursor) else {
                return nil
            }
            if name == key {
                let value = Data(bytes[valueStart..<cursor])
                result = value == Data("null".utf8) ? nil : value
            }
            skipWhitespace(bytes, &cursor)
            if consume(0x2c, bytes, &cursor) { // ,
                skipWhitespace(bytes, &cursor)
                continue
            }
            break
        }
        return result
    }

    private static func skipValue(_ bytes: [UInt8], _ cursor: inout Int) -> Bool {
        guard cursor < bytes.count else {
            return false
        }
        switch bytes[cursor] {
        case 0x22: // "
            return skipString(bytes, &cursor)
        case 0x7b: // {
            return skipObject(bytes, &cursor)
        case 0x5b: // [
            return skipArray(bytes, &cursor)
        default:
            let start = cursor
            while cursor < bytes.count,
                  !isWhitespace(bytes[cursor]),
                  bytes[cursor] != 0x2c,
                  bytes[cursor] != 0x5d,
                  bytes[cursor] != 0x7d {
                cursor += 1
            }
            return cursor > start
        }
    }

    private static func skipObject(_ bytes: [UInt8], _ cursor: inout Int) -> Bool {
        guard consume(0x7b, bytes, &cursor) else {
            return false
        }
        skipWhitespace(bytes, &cursor)
        if consume(0x7d, bytes, &cursor) {
            return true
        }
        while true {
            guard skipString(bytes, &cursor) else {
                return false
            }
            skipWhitespace(bytes, &cursor)
            guard consume(0x3a, bytes, &cursor) else {
                return false
            }
            skipWhitespace(bytes, &cursor)
            guard skipValue(bytes, &cursor) else {
                return false
            }
            skipWhitespace(bytes, &cursor)
            if consume(0x2c, bytes, &cursor) {
                skipWhitespace(bytes, &cursor)
                continue
            }
            return consume(0x7d, bytes, &cursor)
        }
    }

    private static func skipArray(_ bytes: [UInt8], _ cursor: inout Int) -> Bool {
        guard consume(0x5b, bytes, &cursor) else {
            return false
        }
        skipWhitespace(bytes, &cursor)
        if consume(0x5d, bytes, &cursor) {
            return true
        }
        while true {
            guard skipValue(bytes, &cursor) else {
                return false
            }
            skipWhitespace(bytes, &cursor)
            if consume(0x2c, bytes, &cursor) {
                skipWhitespace(bytes, &cursor)
                continue
            }
            return consume(0x5d, bytes, &cursor)
        }
    }

    private static func parseString(_ bytes: [UInt8], _ cursor: inout Int) -> String? {
        let start = cursor
        guard skipString(bytes, &cursor) else {
            return nil
        }
        return try? JSONDecoder().decode(String.self, from: Data(bytes[start..<cursor]))
    }

    private static func skipString(_ bytes: [UInt8], _ cursor: inout Int) -> Bool {
        guard consume(0x22, bytes, &cursor) else { // "
            return false
        }
        while cursor < bytes.count {
            switch bytes[cursor] {
            case 0x22: // "
                cursor += 1
                return true
            case 0x5c: // \
                cursor += 1
                guard cursor < bytes.count else {
                    return false
                }
                if bytes[cursor] == 0x75 { // u
                    cursor += 5
                } else {
                    cursor += 1
                }
            default:
                cursor += 1
            }
        }
        return false
    }

    private static func consume(_ byte: UInt8, _ bytes: [UInt8], _ cursor: inout Int) -> Bool {
        guard cursor < bytes.count, bytes[cursor] == byte else {
            return false
        }
        cursor += 1
        return true
    }

    private static func skipWhitespace(_ bytes: [UInt8], _ cursor: inout Int) {
        while cursor < bytes.count, isWhitespace(bytes[cursor]) {
            cursor += 1
        }
    }

    private static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d
    }
}
