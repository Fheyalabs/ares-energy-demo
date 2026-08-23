// SPDX-License-Identifier: Apache-2.0
// Translation of clients/python/examples/auction_openfhe_smoke.py

import Foundation
import AresClient
import AresClientFHE
import AresTransport

enum AuctionFlow {
    static func run(serverURL: String, participants: Int, authSecret: String, sessionID: String) async throws -> Int {
        let bidders = (0..<participants).map { String(format: "bidder-%02d", $0) }
        let scores = (0..<participants).map { _ in Double.random(in: -0.8...0.8) }

        let depth = UInt32(ProcessInfo.processInfo.environment["AUCTION_CRYPTO_DEPTH"] ?? "10") ?? 10
        let ringDim = UInt32(ProcessInfo.processInfo.environment["AUCTION_RING_DIM"] ?? "2048") ?? 2048
        let ctx = try CryptoContext(ringDim: ringDim, scalingFactor: Double(UInt64(1) << 50), depth: depth)

        // Local N-party threshold keygen; hold all shares client-side.
        var pks: [PublicKey] = []
        var sks: [SecretKeyShare] = []
        let first = try ctx.keyGenFirst()
        pks.append(first.publicKey)
        sks.append(first.secretKey)
        for _ in 1..<participants {
            let next = try ctx.keyGenNext(prev: pks.last!)
            pks.append(next.publicKey)
            sks.append(next.secretKey)
        }
        let collectivePK = pks.last!

        // 2-round eval-mult-key protocol.
        let base = try ctx.evalMultKeyGenLead(sks[0])
        var r1: [EvalMultKey] = [base]
        for i in 1..<sks.count {
            r1.append(try ctx.evalMultKeySwitchShare(sks[i], base: base))
        }
        let joined = try ctx.combineEvalMultSwitchShares(pks, r1)
        var fin: [EvalMultKey] = []
        for sk in sks {
            fin.append(try ctx.evalMultKeyFinalShare(sk, joined: joined, finalPK: collectivePK))
        }
        let evalMultFinal = try ctx.combineEvalMultFinalShares(collectivePK, fin)

        // Encrypt each bidder's score under the collective PK.
        var bidCTHex: [String: String] = [:]
        for (b, s) in zip(bidders, scores) {
            let ct = try ctx.encrypt(values: [s, 0, 0, 0], under: collectivePK)
            bidCTHex[b] = ByteUtil.hex(try ctx.serialize(ct))
        }
        let decryptTargetHex = bidCTHex[bidders[0]]!

        // Pre-compute partial decrypts for every bidder before the concurrent task
        // group so we never capture the non-Sendable CryptoContext/Ciphertext handles
        // across concurrency domains.
        let targetCT = try ctx.deserializeCiphertext(ByteUtil.fromHex(decryptTargetHex)!)
        var partialHexByBidder: [String: String] = [:]
        for (idx, bidder) in bidders.enumerated() {
            let partial = try ctx.partialDecrypt(targetCT, with: sks[idx])
            partialHexByBidder[bidder] = ByteUtil.hex(try ctx.serialize(partial))
        }

        // Seed pre-shared keys via admin attrs so the server uses our local bundle.
        let attrs: [String: String] = [
            "auction.collective_pk": ByteUtil.hex(try ctx.serialize(collectivePK)),
            "auction.eval_keys": ByteUtil.hex(try ctx.serialize(evalMultFinal)),
        ]

        let admin = AdminClient(serverURL: serverURL)
        try await admin.waitForHealth()
        let sessions = try await Orchestrator.connectAll(
            serverURL: serverURL, pseudonyms: bidders,
            sessionID: sessionID, authSecret: authSecret)
        defer { Task { await Orchestrator.closeAll(sessions) } }   // close even if the flow throws
        try await admin.startSession(sessionID: sessionID, participants: bidders, attrs: attrs)

        // Concurrent WS flow — only pre-computed strings are captured.
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (idx, session) in sessions.enumerated() {
                let bidder = bidders[idx]
                let myBidHex = bidCTHex[bidder]!
                let myPartialHex = partialHexByBidder[bidder]!
                group.addTask {
                    _ = try await session.expect("auction.invitation")
                    try await session.send("auction.keygen.share",
                        payloadJSON: Data("{\"share\":\"ks-\(bidder)\"}".utf8))
                    try await session.awaitPhase("AUCTION_BIDDING")
                    try await session.send("auction.bid",
                        payloadJSON: Data("{\"bid_ct\":\"\(myBidHex)\"}".utf8))
                    try await session.awaitPhase("AUCTION_DECRYPTING")
                    try await session.send("auction.decrypt.partial",
                        payloadJSON: Data("{\"partial_ct\":\"\(myPartialHex)\"}".utf8))
                }
            }
            try await group.waitForAll()
        }

        let terminal = try await admin.pollUntilTerminal(sessionID: sessionID, terminal: "AUCTION_SETTLED")
        if terminal == "AUCTION_SETTLED" || terminal.isEmpty {
            FileHandle.standardError.write(Data("auction: reached \(terminal.isEmpty ? "terminal" : terminal)\n".utf8))
            return 0
        }
        FileHandle.standardError.write(Data("auction: stuck at \(terminal)\n".utf8))
        return 1
    }
}
