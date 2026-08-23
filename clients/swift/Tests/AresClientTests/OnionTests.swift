import XCTest
import Crypto
@testable import AresClient

final class OnionTests: XCTestCase {
    private func keypair() -> (sk: Data, pk: Data) {
        let k = Curve25519.KeyAgreement.PrivateKey()
        return (k.rawRepresentation, k.publicKey.rawRepresentation)
    }

    func testNPartyRoundTrip() throws {
        let n = 4
        let keys = (0..<n).map { _ in keypair() }
        let pubs = keys.map { $0.pk }
        let payloads = (0..<n).map { Data("payload-\($0)".utf8) }

        var batch: [Data] = []
        var memos: [Data] = []
        for i in 0..<n {
            let (onion, memo) = try Onion.build(payload: payloads[i], peerPubs: pubs, selfIndex: i)
            batch.append(onion); memos.append(memo)
        }
        for k in 0..<n {
            let (peeled, own) = try Onion.peelBatch(mySk: keys[k].sk, selfMemo: memos[k], onions: batch)
            XCTAssertGreaterThanOrEqual(own, 0, "peeler \(k) did not find its own item")
            batch = peeled
        }
        for i in 0..<n {
            XCTAssertEqual(batch[i], payloads[i], "party \(i) payload not recovered")
        }
    }

    func testPeelBatchThrowsWhenSelfMemoUnmatched() throws {
        let keys = (0..<2).map { _ in keypair() }
        let (onion, _) = try Onion.build(payload: Data("x".utf8), peerPubs: keys.map { $0.pk }, selfIndex: 0)
        XCTAssertThrowsError(try Onion.peelBatch(mySk: keys[0].sk, selfMemo: Data([0xde, 0xad]), onions: [onion]))
    }

    func testBuildRejectsBadSelfIndex() {
        let keys = (0..<2).map { _ in keypair() }
        XCTAssertThrowsError(try Onion.build(payload: Data("x".utf8), peerPubs: keys.map { $0.pk }, selfIndex: 5))
    }

    func testPeelBatchRejectsMalformedShortLayer() throws {
        let mySk = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
        XCTAssertThrowsError(
            try Onion.peelBatch(mySk: mySk, selfMemo: nil, onions: [Data([0, 1, 2])])
        ) { error in
            XCTAssertEqual(error as? OnionError, OnionError.malformedLayer)
        }
    }
}
