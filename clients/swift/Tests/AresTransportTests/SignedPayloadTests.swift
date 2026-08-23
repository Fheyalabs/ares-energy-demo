// SPDX-License-Identifier: Apache-2.0

import XCTest
import Crypto
@testable import AresTransport

final class SignedPayloadTests: XCTestCase {

    /// Canonical form must sort top-level keys and stay compact, matching the
    /// server's canonicalPayloadFromRawMap (openfhe < share, no whitespace).
    func testCanonicalSortsTopLevelKeysCompact() {
        let canon = SignedPayload.canonical([
            ("share", "\"ab12\""),
            ("openfhe", "{\"protocol\":\"x\",\"slot_index\":0}"),
        ])
        XCTAssertEqual(
            canon,
            "{\"openfhe\":{\"protocol\":\"x\",\"slot_index\":0},\"share\":\"ab12\"}"
        )
    }

    /// The wire payload carries a 64-byte (128-hex) signature, and that signature
    /// validates over `label|sessionID|canonical` — exactly the bytes the server
    /// reconstructs and checks in verifySignedPayload.
    func testSignedPayloadSignatureVerifiesOverCanonical() throws {
        let id = DeviceIdentity()
        let sessionID = "sess-1"
        let label = "keygen.share"
        let fields: [SignedPayload.Field] = [
            ("share", "\"\(id.publicKeyHex)\""),
            ("openfhe", "{\"protocol\":\"slot_ordered_chained_multiparty\",\"slot_index\":2}"),
        ]

        let wire = try SignedPayload.signed(label: label, sessionID: sessionID,
                                            fields: fields, identity: id)

        let obj = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
        let sigHex = try XCTUnwrap(obj["sig"] as? String)
        XCTAssertEqual(sigHex.count, 128, "ed25519 signature is 64 bytes")
        XCTAssertNotNil(obj["share"])
        XCTAssertNotNil(obj["openfhe"])

        let canon = SignedPayload.canonical(fields)
        let message = Data("\(label)|\(sessionID)|".utf8) + Data(canon.utf8)
        let sig = try XCTUnwrap(Data(hexString: sigHex))
        XCTAssertTrue(id.privateKey.publicKey.isValidSignature(sig, for: message))
    }

    /// A zero-field signed payload is still valid JSON with just `sig`.
    func testEmptyFieldsProducesSigOnlyObject() throws {
        let id = DeviceIdentity()
        let wire = try SignedPayload.signed(label: "decrypt.partial", sessionID: "s",
                                            fields: [], identity: id)
        let obj = try JSONSerialization.jsonObject(with: wire) as! [String: Any]
        XCTAssertEqual(obj.count, 1)
        XCTAssertNotNil(obj["sig"])
    }
}

private extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var d = Data(capacity: hexString.count / 2)
        var i = hexString.startIndex
        while i < hexString.endIndex {
            let j = hexString.index(i, offsetBy: 2)
            guard let b = UInt8(hexString[i..<j], radix: 16) else { return nil }
            d.append(b)
            i = j
        }
        self = d
    }
}
