import Foundation

/// Byte helpers matching the ARES wire encoding (big-endian length prefixes, hex).
public enum ByteUtil {
    /// 4-byte big-endian encoding of n.
    public static func u32be(_ n: UInt32) -> Data {
        Data([UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
              UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
    }

    /// Length-prefix: u32be(len) || b.
    public static func lp(_ b: Data) -> Data {
        var out = u32be(UInt32(b.count))
        out.append(b)
        return out
    }

    /// Lowercase hex string of d.
    public static func hex(_ d: Data) -> String {
        d.map { String(format: "%02x", $0) }.joined()
    }

    /// Decode a hex string to Data; nil on malformed input.
    public static func fromHex(_ s: String) -> Data? {
        guard s.count % 2 == 0 else { return nil }
        var out = Data(capacity: s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let byte = UInt8(s[idx..<next], radix: 16) else { return nil }
            out.append(byte)
            idx = next
        }
        return out
    }
}
