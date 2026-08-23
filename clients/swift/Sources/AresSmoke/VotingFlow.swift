// SPDX-License-Identifier: Apache-2.0

import Foundation
import Crypto
import AresClient
import AresTransport

// ---------------------------------------------------------------------------
// MARK: - VotingFlow
// ---------------------------------------------------------------------------

/// End-to-end voting flow: onion-shuffle + SC-10 lineage slot submission +
/// ballot collection.
///
/// Protocol arc:
///   1. All voters connect via WS, admin starts session.
///   2. Each voter receives `vote.invitation`.
///   3. All voters concurrently send `onion.batch` (one onion per voter,
///      N-layer ECIES, built over the full participant peel order).
///   4. The server assembles the full batch and sends `onion.peel_forward`
///      to voter-0 only.  Voter-0 peels their layer and sends
///      `onion.peel_forward` back; the server relays to voter-1.  This
///      sequential chain repeats until all N voters have peeled.
///   5. State advances to VERIFYING.  Every voter sends `slot.submit` with
///      the canonical slot-entry payload and its SC-10 lineage node (v2
///      frame).
///   6. State advances to SUBMITTING.  Every voter sends `vote.ballot`.
///   7. Session tallies and reaches a terminal / BROADCASTING state.
///
/// Returns 0 on success (terminal reached), 1 on any error.
enum VotingFlow {
    static func run(serverURL: String, participants: Int, authSecret: String, sessionID: String) async throws -> Int {
        let n = participants
        guard n >= 2 else {
            fputs("voting: need at least 2 participants\n", stderr)
            return 1
        }

        // --- Generate per-voter slot keypairs (X25519 raw bytes) ---
        var slotSKs: [Data] = []
        var slotPKs: [Data] = []
        for _ in 0..<n {
            let privKey = Curve25519.KeyAgreement.PrivateKey()
            slotSKs.append(privKey.rawRepresentation)
            slotPKs.append(privKey.publicKey.rawRepresentation)
        }

        let voterNames = (0..<n).map { String(format: "voter-%02d", $0) }

        // --- Pre-build gossip participants (value types, Sendable) ---
        let gossips: [GossipParticipant] = (0..<n).map { i in
            GossipParticipant(
                sessionID: sessionID,
                selfIndex: i,
                slotDKSk: slotSKs[i],
                slotDKPub: slotPKs[i]
            )
        }

        // --- Pre-build onion batches + memos (all crypto before concurrency) ---
        var batchPayloads: [Data] = []
        var selfMemos: [Data] = []
        for i in 0..<n {
            let (batchJSON, memo) = try gossips[i].buildBatch(peerPubs: slotPKs)
            batchPayloads.append(batchJSON)
            selfMemos.append(memo)
        }

        // --- Pre-build slot submissions (payload bytes + lineage node) ---
        var slotPayloads: [Data] = []
        var slotNodes: [DAGNode] = []
        for i in 0..<n {
            let (payload, node) = try gossips[i].slotSubmission()
            slotPayloads.append(payload)
            slotNodes.append(node)
        }

        // --- Connect all voters ---
        let admin = AdminClient(serverURL: serverURL)
        try await admin.waitForHealth()
        let sessions = try await Orchestrator.connectAll(
            serverURL: serverURL, pseudonyms: voterNames,
            sessionID: sessionID, authSecret: authSecret, timeout: 60)
        defer { Task { await Orchestrator.closeAll(sessions) } }   // close even if the flow throws

        // Brief pause to let all WS upgrade handshakes complete in the hub
        // before the admin POST triggers the invitation broadcast.
        try await Task.sleep(nanoseconds: 300_000_000)

        // --- Start session ---
        try await admin.startSession(sessionID: sessionID, participants: voterNames)

        // --- Run all voters concurrently ---
        // Each voter drives its own WS connection through the full arc.
        // The peel chain is sequential from the server's perspective
        // (server relays onion.peel_forward to each voter in turn), so
        // each voter just waits for the peel_forward message destined for
        // it — there is no client-side coordination needed.
        var flowError: String? = nil
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for i in 0..<n {
                    let session = sessions[i]
                    let voterIdx = i
                    let batchPayload = batchPayloads[i]
                    let selfMemo = selfMemos[i]
                    let gossip = gossips[i]
                    let slotPayload = slotPayloads[i]
                    let slotNode = slotNodes[i]
                    let voterName = voterNames[i]

                    group.addTask {
                        // 1. Wait for invitation.
                        _ = try await session.expect("vote.invitation", timeout: 30)
                        fputs("voting: \(voterName): got invitation\n", stderr)

                        // 2. Send onion.batch.
                        try await session.send("onion.batch", payloadJSON: batchPayload)
                        fputs("voting: \(voterName): sent onion.batch\n", stderr)

                        // 3. Peel chain: wait for onion.peel_forward, peel,
                        //    send onion.peel_forward back.  The server only
                        //    sends peel_forward to the voter whose turn it is;
                        //    voters whose turn has not come yet won't receive
                        //    this message and skip this step.
                        //
                        //    We poll receiveAny with a generous timeout,
                        //    filtering for peel_forward.  If we timeout we
                        //    assume our peel turn is already done (the server
                        //    didn't relay to us), and move on.
                        let peelDeadline = Date().addingTimeInterval(60)
                        var didPeel = false
                        while Date() < peelDeadline {
                            let remaining = peelDeadline.timeIntervalSinceNow
                            guard remaining > 0 else { break }
                            do {
                                let frame = try await session.receiveAny(timeout: min(remaining, 5))
                                if frame.type == "onion.peel_forward" {
                                    fputs("voting: \(voterName): received peel_forward, peeling\n", stderr)
                                    guard let rawPayload = frame.payload,
                                          let onionsObj = try? JSONSerialization.jsonObject(with: rawPayload) as? [String: Any],
                                          let onionsB64 = onionsObj["onions"] as? [String] else {
                                        throw TransportError.closed("\(voterName): malformed peel_forward payload")
                                    }
                                    let onionBytes = try onionsB64.map { b64 -> Data in
                                        guard let d = Data(base64Encoded: b64) else {
                                            throw TransportError.closed("\(voterName): bad base64 in peel_forward")
                                        }
                                        return d
                                    }
                                    let (peeled, _) = try gossip.peelRound(selfMemo: selfMemo, onions: onionBytes)
                                    let peeledB64 = peeled.map { $0.base64EncodedString() }
                                    let peelPayload = try JSONSerialization.data(
                                        withJSONObject: ["onions": peeledB64],
                                        options: [.sortedKeys])
                                    try await session.send("onion.peel_forward", payloadJSON: peelPayload)
                                    fputs("voting: \(voterName): sent onion.peel_forward\n", stderr)
                                    didPeel = true
                                    break
                                }
                                // Other message types (e.g. phase-transition
                                // notifications) — log and continue.
                                fputs("voting: \(voterName): dropped \(frame.type) while waiting for peel\n", stderr)
                            } catch TransportError.timeout {
                                // No peel_forward for this voter — not our turn.
                                break
                            }
                        }
                        if !didPeel {
                            fputs("voting: \(voterName): no peel turn (not in peel chain)\n", stderr)
                        }

                        // 4. Wait for VERIFYING.
                        try await session.awaitPhase("VERIFYING", timeout: 60)
                        fputs("voting: \(voterName): state is VERIFYING\n", stderr)

                        // 5. Send slot.submit (v2 frame with lineage).
                        try await session.send("slot.submit", payloadJSON: slotPayload, lineage: slotNode)
                        fputs("voting: \(voterName): sent slot.submit\n", stderr)

                        // 6. Wait for SUBMITTING.
                        try await session.awaitPhase("SUBMITTING", timeout: 30)
                        fputs("voting: \(voterName): state is SUBMITTING\n", stderr)

                        // 7. Send vote.ballot.
                        let choice = voterIdx % 2
                        let ballotJSON = Data("{\"choice\":\(choice),\"weight\":1.0}".utf8)
                        try await session.send("vote.ballot", payloadJSON: ballotJSON)
                        fputs("voting: \(voterName): sent vote.ballot choice=\(choice)\n", stderr)
                    }
                }
                try await group.waitForAll()
            }
        } catch {
            flowError = "\(error)"
            fputs("voting: flow error: \(error)\n", stderr)
        }

        // --- Poll for terminal state ---
        let terminal = try await admin.pollUntilTerminal(
            sessionID: sessionID, terminal: "BROADCASTING", tries: 40, interval: 0.5)

        if let err = flowError {
            fputs("voting: FAILED (flow error): \(err)\n", stderr)
            return 1
        }

        // BROADCASTING or empty (terminal) is success.
        if terminal == "BROADCASTING" || terminal.isEmpty {
            fputs("voting: reached terminal state: \(terminal.isEmpty ? "(closed)" : terminal)\n", stderr)
            return 0
        }
        fputs("voting: stuck at state: \(terminal)\n", stderr)
        return 1
    }
}

private func fputs(_ msg: String, _ stream: UnsafeMutablePointer<FILE>) {
    Foundation.fputs(msg, stream)
}
