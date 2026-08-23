import XCTest
@testable import AresClient

final class WireFrameTests: XCTestCase {
    func testV2FrameWithLineageRoundTrips() throws {
        let payload = Data(#"{"slot_index":2,"slot_dk_pub":"aa"}"#.utf8)
        let node = try Lineage.buildSlotNode(
            sessionID: "s1", payloadBytes: payload,
            ed25519Seed: ByteUtil.fromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        ).node
        let msg = WSMessage(version: "2", type: "slot.submit", sessionID: "s1",
                            payload: RawJSON(payload), timestamp: "2026-01-01T00:00:00Z", lineage: node)
        let encoded = try JSONEncoder().encode(msg)
        let decoded = try JSONDecoder().decode(WSMessage.self, from: encoded)
        XCTAssertEqual(decoded.version, "2")
        XCTAssertEqual(decoded.type, "slot.submit")
        XCTAssertEqual(decoded.lineage?.hash, node.hash)
        // payload round-trips SEMANTICALLY (Codable re-encodes JSON values; byte-exact
        // on-wire payload assembly is an L3 transport concern).
        let origVal = try JSONDecoder().decode(JSONValue.self, from: payload)
        let roundVal = try JSONDecoder().decode(JSONValue.self, from: decoded.payload!.data)
        XCTAssertEqual(origVal, roundVal)
    }

    func testV1FrameOmitsLineage() throws {
        let msg = WSMessage(version: "", type: "ping", sessionID: "s1", payload: nil, timestamp: "", lineage: nil)
        let encoded = try JSONEncoder().encode(msg)
        let obj = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertNil(obj["lineage"], "lineage must be omitted when nil")
    }
}
