// SPDX-License-Identifier: Apache-2.0

import XCTest
import Crypto
@testable import AresTransport

final class CandidateSealTests: XCTestCase {

    /// The package is exactly 80 bytes (server `DefaultWinnerPackageBytes`) and the
    /// candidate recovers σ with its own key.
    func testSealIs80BytesAndRoundTrips() throws {
        let recipient = Curve25519.KeyAgreement.PrivateKey()
        let sigma = Data((0..<32).map { UInt8($0) })

        let pkg = try CandidateSeal.seal(sigma: sigma, to: recipient.publicKey)
        XCTAssertEqual(pkg.count, 80)

        let recovered = try CandidateSeal.open(pkg, with: recipient)
        XCTAssertEqual(recovered, sigma)
    }

    /// A different key cannot open the package (Poly1305 auth fails).
    func testWrongKeyCannotOpen() throws {
        let mine = Curve25519.KeyAgreement.PrivateKey()
        let other = Curve25519.KeyAgreement.PrivateKey()
        let pkg = try CandidateSeal.seal(sigma: Data(repeating: 7, count: 32), to: mine.publicKey)
        XCTAssertThrowsError(try CandidateSeal.open(pkg, with: other))
    }

    /// Non-80-byte input is rejected before any crypto.
    func testBadLengthRejected() {
        let mine = Curve25519.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(try CandidateSeal.open(Data(repeating: 0, count: 79), with: mine)) {
            XCTAssertEqual($0 as? CandidateSeal.SealError, .badLength(79))
        }
    }
}
