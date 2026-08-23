import Foundation
import XCTest

struct LineageVector: Decodable {
    struct Input: Decodable {
        let ed25519_seed_hex: String
        let session_id: String
        let phase_id: String
        let role: String
        let payload_hex: String
        let parents_hex: [String]
    }
    struct Expected: Decodable {
        let producer_hex: String
        let payload_hash_hex: String
        let node_hash_hex: String
        let signing_msg_hex: String
        let signature_hex: String
        let algorithm: String
    }
    let name: String
    let input: Input
    let expected: Expected
}

enum GoldenVectorLoader {
    /// Locate node_vectors.json from this test file via #filePath (no copy).
    /// File: clients/swift/Tests/AresClientTests/GoldenVectorLoader.swift → repo root is 5 dirs up.
    static func loadNodeVectors(file: StaticString = #filePath) throws -> [LineageVector] {
        var root = URL(fileURLWithPath: "\(file)")
        for _ in 0..<5 { root.deleteLastPathComponent() } // AresClientTests→Tests→swift→clients→<root>
        let url = root.appendingPathComponent("pkg/ares/lineage/testdata/node_vectors.json")
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode([LineageVector].self, from: data)
    }
}
