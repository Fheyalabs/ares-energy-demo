import Foundation

/// Raw JSON value carried so the parsed payload round-trips. (Byte-exact on-wire
/// payload assembly is an L3 transport concern — the send path there reuses the exact
/// Data used for the lineage payload_hash. L1 preserves the JSON value semantically.)
///
/// WARNING (L3 gotcha): decoded data is re-serialised through ``JSONValue`` and is NOT
/// guaranteed to be byte-identical to the original input bytes. This is a semantic
/// round-trip only; byte-exact wire reproduction is deferred to the L3 transport layer.
public struct RawJSON: Codable, Equatable {
    public let data: Data
    public init(_ data: Data) { self.data = data }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(JSONValue.self)
        self.data = try JSONEncoder().encode(value)
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        let value = try JSONDecoder().decode(JSONValue.self, from: data)
        try container.encode(value)
    }
}

/// Minimal JSON value to round-trip arbitrary payload objects.
public enum JSONValue: Codable, Equatable {
    case null, bool(Bool), number(Double), string(String)
    case array([JSONValue]), object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

/// v2 WebSocket frame. lineage present ⇒ this is a v2 frame.
public struct WSMessage: Codable {
    public var version: String
    public var type: String
    public var sessionID: String
    public var payload: RawJSON?
    public var timestamp: String
    public var lineage: DAGNode?

    enum CodingKeys: String, CodingKey {
        case version, type
        case sessionID = "session_id"
        case payload, timestamp, lineage
    }

    public init(version: String, type: String, sessionID: String,
                payload: RawJSON?, timestamp: String, lineage: DAGNode?) {
        self.version = version; self.type = type; self.sessionID = sessionID
        self.payload = payload; self.timestamp = timestamp; self.lineage = lineage
    }
}
