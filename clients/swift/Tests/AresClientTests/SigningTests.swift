import XCTest
import Crypto
@testable import AresClient

final class SigningTests: XCTestCase {
    func testCanonicalJSONSortsKeysCompact() throws {
        let obj: [String: Any] = ["b": 2, "a": 1]
        let c = try Signing.canonicalJSON(obj)
        XCTAssertEqual(String(data: c, encoding: .utf8), #"{"a":1,"b":2}"#)
    }

    func testDeviceSignVerifies() throws {
        let key = Curve25519.Signing.PrivateKey()
        let canonical = Data(#"{"a":1,"b":2}"#.utf8)
        let sig = try Signing.deviceSign(deviceKey: key, label: "verify.submit_slot",
                                         sessionID: "s1", canonical: canonical)
        let message = Data("verify.submit_slot|s1|".utf8) + canonical
        XCTAssertTrue(key.publicKey.isValidSignature(sig, for: message))
    }
}
