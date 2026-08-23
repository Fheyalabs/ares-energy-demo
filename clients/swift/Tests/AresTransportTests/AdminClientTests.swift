import XCTest
@testable import AresTransport

final class AdminClientTests: XCTestCase {
    func testStartSessionBodyEncodesAttrs() throws {
        let body = try AdminClient.encodeStartBody(
            sessionID: "auction-1", participants: ["b0", "b1"],
            attrs: ["auction.collective_pk": "aa", "auction.eval_keys": "bb"])
        let obj = try JSONSerialization.jsonObject(with: body) as! [String: Any]
        XCTAssertEqual(obj["session_id"] as? String, "auction-1")
        XCTAssertEqual((obj["participants"] as? [String])?.count, 2)
        XCTAssertEqual((obj["attrs"] as? [String: Any])?["auction.collective_pk"] as? String, "aa")
    }
    func testStartSessionBodyOmitsEmptyAttrs() throws {
        let body = try AdminClient.encodeStartBody(sessionID: "s", participants: ["b0"], attrs: [:])
        let obj = try JSONSerialization.jsonObject(with: body) as! [String: Any]
        XCTAssertNil(obj["attrs"])
    }
}
