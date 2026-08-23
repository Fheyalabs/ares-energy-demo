import XCTest
import Crypto
@testable import AresTransport
@testable import AresClient

final class GossipParticipantTests: XCTestCase {
    func testThreePartyBuildThenPeelRecoversOwnSlotEntry() throws {
        var sks: [Data] = [], pubs: [Data] = []
        for _ in 0..<3 {
            let sk = Curve25519.KeyAgreement.PrivateKey()
            sks.append(sk.rawRepresentation); pubs.append(sk.publicKey.rawRepresentation)
        }
        var parts: [GossipParticipant] = []
        var memos: [Data] = [], onions: [Data] = []
        for i in 0..<3 {
            let gp = GossipParticipant(sessionID: "vote-1", selfIndex: i, slotDKSk: sks[i], slotDKPub: pubs[i])
            let (payloadJSON, memo) = try gp.buildBatch(peerPubs: pubs)
            let obj = try JSONSerialization.jsonObject(with: payloadJSON) as! [String: Any]
            let b64 = (obj["onions"] as! [String])[0]
            onions.append(Data(base64Encoded: b64)!)
            memos.append(memo); parts.append(gp)
        }
        // Full peel: each of the 3 participants peels one layer from ALL onions per round.
        var current = onions
        for round in 0..<3 {
            let (out, ownIdx) = try parts[round].peelRound(selfMemo: memos[round], onions: current)
            XCTAssertGreaterThanOrEqual(ownIdx, 0)
            current = out
        }
        let (bytes, node) = try parts[0].slotSubmission()
        XCTAssertFalse(bytes.isEmpty)
        XCTAssertEqual(node.phaseID, "anon-g-verify")
        XCTAssertEqual(node.role, "slot-submission")
    }
}
