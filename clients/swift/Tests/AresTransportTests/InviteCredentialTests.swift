// SPDX-License-Identifier: Apache-2.0

import XCTest
import Crypto
@testable import AresTransport

final class InviteCredentialTests: XCTestCase {

    private let testKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    /// Cross-language golden: Swift `signClaims` must byte-match the Go
    /// `auth.signClaims` (server test `TestSignClaimsGoldenForSwift`) for the same
    /// fixed claims, since the server verifies a credential by re-signing the
    /// unmarshalled claims.
    func testSignClaimsMatchesGoGolden() {
        let cred = InviteCredential(signingKey: testKey)
        let sig = cred.signClaims(issuer: "fheya-auth-v1", provider: "invite",
                                  nonce: "fixednonce", subjectHash: "aaa", tokenHash: "bbb",
                                  issuedAt: 1000, expiresAt: 2000)
        XCTAssertEqual(sig, "7062e58e0de3f957bee6202f204b52f08a323f756352f530d196c62017730b65")
    }

    /// A minted blob is a well-formed envelope whose signature re-verifies and
    /// whose claims match the issue() path (version/issuer/provider, no account_id).
    func testMintProducesSelfConsistentEnvelope() throws {
        let cred = InviteCredential(signingKey: testKey)
        let blob = cred.mint(accountID: "test-account", now: Date(timeIntervalSince1970: 1000))
        let env = try JSONSerialization.jsonObject(with: blob) as! [String: Any]
        let claims = env["claims"] as! [String: Any]
        let sig = env["signature"] as! String

        XCTAssertEqual(claims["version"] as? Int, 1)
        XCTAssertEqual(claims["issuer"] as? String, "fheya-auth-v1")
        XCTAssertEqual(claims["provider"] as? String, "invite")
        XCTAssertNil(claims["account_id"])
        XCTAssertEqual(sig.count, 64)

        let expected = cred.signClaims(
            issuer: "fheya-auth-v1", provider: "invite",
            nonce: claims["nonce"] as! String,
            subjectHash: claims["subject_hash"] as! String,
            tokenHash: claims["token_hash"] as! String,
            issuedAt: Int64(claims["issued_at"] as! Int),
            expiresAt: Int64(claims["expires_at"] as! Int))
        XCTAssertEqual(sig, expected)
    }
}
