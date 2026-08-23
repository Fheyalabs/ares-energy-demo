// SPDX-License-Identifier: Apache-2.0

import Foundation
import AresClient
import AresClientFHE
import AresTransport

enum BoundCheckFlow {
    /// Three modes:
    ///   inbound  — all inputs in [1-eps, 1+eps] → SETTLED, no violations
    ///   violation — one party inflates ‖x‖² ≈ 4 → server flags violation
    ///   tamper   — client corrupts its enc_check → participant.passed == false
    static func run(serverURL: String, participants n: Int, authSecret: String,
                    sessionID: String, mode: String) async throws -> Int {
        let dim = Int(ProcessInfo.processInfo.environment["ADMISSION_DIM"] ?? "8") ?? 8
        let depth = UInt32(ProcessInfo.processInfo.environment["ADMISSION_CRYPTO_DEPTH"] ?? "8") ?? 8
        let ringDim = UInt32(ProcessInfo.processInfo.environment["ADMISSION_RING_DIM"] ?? "16384") ?? 16384

        let parties = (0..<n).map { "party-\($0)" }
        let ctx = try CryptoContext(ringDim: ringDim, scalingFactor: Double(UInt64(1) << 50), depth: depth)

        // --- 1. Local N-party threshold keygen + eval-mult + eval-sum keys ---
        var pks: [PublicKey] = []; var sks: [SecretKeyShare] = []
        let f = try ctx.keyGenFirst(); pks.append(f.publicKey); sks.append(f.secretKey)
        for _ in 1..<n { let nx = try ctx.keyGenNext(prev: pks.last!); pks.append(nx.publicKey); sks.append(nx.secretKey) }
        let collectivePK = pks.last!

        // eval-mult-key 2-round
        let emkBase = try ctx.evalMultKeyGenLead(sks[0])
        var emkR1: [EvalMultKey] = [emkBase]
        for i in 1..<sks.count { emkR1.append(try ctx.evalMultKeySwitchShare(sks[i], base: emkBase)) }
        let emkJoined = try ctx.combineEvalMultSwitchShares(pks, emkR1)
        var emkFin: [EvalMultKey] = []
        for sk in sks { emkFin.append(try ctx.evalMultKeyFinalShare(sk, joined: emkJoined, finalPK: collectivePK)) }
        let evalMultFinal = try ctx.combineEvalMultFinalShares(collectivePK, emkFin)

        // eval-sum (rotation) key — NormCircuit EvalProductSum needs it
        let eskBase = try ctx.evalSumKeyGenLead(sks[0])
        var eskShares: [RotKey] = []
        for i in 0..<sks.count { eskShares.append(try ctx.evalSumKeyShare(sks[i], base: eskBase, ownPK: pks[i])) }
        let evalSumFinal = try ctx.combineEvalSumKeys(pks, eskShares)

        // --- 2. Encrypt inputs ---
        let unitVal = 1.0 / sqrt(Double(dim))
        var allEncX: [String: Data] = [:]   // party → serialized enc_x
        var encXHex: [String: String] = [:]
        for (i, party) in parties.enumerated() {
            let inflate = (mode == "violation" && i == 0)  // party-0 is the violator
            let vals = (0..<dim).map { _ in unitVal * (inflate ? 2.0 : 1.0) }
            let ct = try ctx.encrypt(values: vals, under: collectivePK)
            let ser = try ctx.serialize(ct); allEncX[party] = ser
            encXHex[party] = ByteUtil.hex(ser)
        }

        // --- 3. Seed pre-shared keys + connect + start session ---
        let attrs: [String: String] = [
            "collective_pk":   ByteUtil.hex(try ctx.serialize(collectivePK)),
            "eval_mult_final": ByteUtil.hex(try ctx.serialize(evalMultFinal)),
            "eval_sum_final":  ByteUtil.hex(try ctx.serialize(evalSumFinal)),
            "dim":             String(dim),
            "ring_dim":        String(ringDim),
            "depth":           String(depth),
        ]

        let admin = AdminClient(serverURL: serverURL)
        try await admin.waitForHealth()
        let sessions = try await Orchestrator.connectAll(serverURL: serverURL, pseudonyms: parties,
                                                sessionID: sessionID, authSecret: authSecret)
        defer { Task { await Orchestrator.closeAll(sessions) } }
        // Brief settle: URLSessionWebSocketTask.resume() returns before the server-side
        // WS upgrade handshake completes. Without this pause, startSession broadcasts
        // the invitation to clients not yet registered in the hub → silently dropped.
        try await Task.sleep(nanoseconds: 2_000_000_000)
        try await admin.startSession(sessionID: sessionID, participants: parties, attrs: attrs)

        // --- 4. Phase A (concurrent): each party submits its input and awaits the
        //        bound_check.challenge. No FHE here — pure WS I/O — so running the
        //        parties concurrently is safe AND necessary: the server only computes
        //        the challenge once ALL inputs are in (a sequential loop would deadlock,
        //        each party blocking on a challenge that needs the next party's input).
        //        The challenge is broadcast in full (all parties' enc_check + commitment),
        //        so every task receives the identical map. ---
        var challengeChecks: [String: String] = [:]      // party -> enc_check hex
        var challengeCommitments: [String: String] = [:]  // party -> commitment hex
        try await withThrowingTaskGroup(of: ([String: String], [String: String]).self) { group in
            for (idx, session) in sessions.enumerated() {
                let me = parties[idx]
                let myInputHex = encXHex[me]!
                group.addTask {
                    _ = try await session.expect("admission.invitation")
                    try await session.send("admission.input",
                        payloadJSON: Data("{\"enc_x\":\"\(myInputHex)\"}".utf8))
                    let frame = try await session.expect("bound_check.challenge")
                    guard let rawPayload = frame.payload,
                          let obj = try JSONSerialization.jsonObject(with: rawPayload) as? [String: Any],
                          let checks = obj["checks"] as? [String: String],
                          let commits = obj["commitments"] as? [String: String]
                    else { throw TransportError.http(0, "bad bound_check.challenge shape") }
                    return (checks, commits)
                }
            }
            for try await (checks, commits) in group {
                // All parties receive the identical full challenge (last write wins).
                challengeChecks = checks
                challengeCommitments = commits
            }
        }
        guard !challengeChecks.isEmpty else {
            FileHandle.standardError.write(Data("boundcheck: no bound_check.challenge received\n".utf8)); return 1
        }

        // --- 5. Phase B (serial FHE): for each party, implicitly verify its own
        //        commitment, then partial-decrypt the REAL enc_check of EVERY checked
        //        party (boundcheck.Exit fuses an N-of-N quorum PER ciphertext). FHE calls
        //        are serialized over the shared context → no thread-safety hazard. ---
        var partyPassed: [String: Bool] = [:]
        for (idx, session) in sessions.enumerated() {
            let me = parties[idx]
            // Tamper mode: party-0 verifies against a DIFFERENT (valid) enc_check than
            // the one its commitment was bound to → recomputed commitment ≠ expected →
            // implicit check fails. Mirrors "server swapped enc_check" without corrupting
            // ciphertext bytes (which would break deserialization, not the binding).
            let verifyParty = (mode == "tamper" && idx == 0) ? parties[(idx + 1) % n] : me
            guard let verifyEncCheckHex = challengeChecks[verifyParty],
                  let verifyEncCheck = ByteUtil.fromHex(verifyEncCheckHex),
                  let ownCommitmentHex = challengeCommitments[me],
                  let ownCommitment = ByteUtil.fromHex(ownCommitmentHex)
            else {
                FileHandle.standardError.write(Data("boundcheck: missing enc_check/commitment for \(me)\n".utf8)); return 1
            }

            let result = try BoundCheckParticipant.participate(
                ctx: ctx, encCheckBytes: verifyEncCheck, encXBytes: allEncX[me]!,
                sessionID: sessionID, expectedCommitment: ownCommitment, with: sks[idx])
            partyPassed[me] = result.passed

            // Partial map: this party's partial decryption of every party's REAL enc_check.
            var partialMap: [String: String] = [:]
            for checkedParty in parties {
                guard let ecHex = challengeChecks[checkedParty],
                      let ec = ByteUtil.fromHex(ecHex) else {
                    FileHandle.standardError.write(Data("boundcheck: bad enc_check hex for \(checkedParty)\n".utf8)); return 1
                }
                let ct = try ctx.deserializeCiphertext(ec)
                let partial = try ctx.serialize(ctx.partialDecrypt(ct, with: sks[idx]))
                partialMap[checkedParty] = partial.base64EncodedString()
            }
            try await session.send("bound_check.partial",
                payloadJSON: try JSONSerialization.data(withJSONObject: partialMap))
        }

        // --- 6. Assertions ---
        let terminal = try await admin.pollUntilTerminal(sessionID: sessionID, terminal: "ADMISSION_SETTLED")
        FileHandle.standardError.write(Data("boundcheck: terminal=\(terminal)\n".utf8))

        switch mode {
        case "inbound":
            guard terminal == "ADMISSION_SETTLED" || terminal.isEmpty else {
                FileHandle.standardError.write(Data("boundcheck INBOUND FAIL: expected SETTLED, got \(terminal)\n".utf8)); return 1
            }
            guard partyPassed.values.allSatisfy({ $0 }) else {
                FileHandle.standardError.write(Data("boundcheck INBOUND FAIL: not all passed: \(partyPassed)\n".utf8)); return 1
            }
            FileHandle.standardError.write(Data("boundcheck INBOUND: OK\n".utf8))
        case "violation":
            guard partyPassed[parties[0]] == true else {
                FileHandle.standardError.write(Data("boundcheck VIOLATION FAIL: party-0 participate.passed=false but its enc_x was intact\n".utf8)); return 1
            }
            // Session should abort (terminal empty or not SETTLED).
            if terminal == "ADMISSION_SETTLED" {
                FileHandle.standardError.write(Data("boundcheck VIOLATION FAIL: expected abort, got SETTLED\n".utf8)); return 1
            }
            FileHandle.standardError.write(Data("boundcheck VIOLATION: OK (session aborted as expected)\n".utf8))
        case "tamper":
            guard partyPassed[parties[0]] == false else {
                FileHandle.standardError.write(Data("boundcheck TAMPER FAIL: expected party-0 passed=false\n".utf8)); return 1
            }
            FileHandle.standardError.write(Data("boundcheck TAMPER: OK (passed=false)\n".utf8))
        default:
            FileHandle.standardError.write(Data("boundcheck: unknown mode \(mode)\n".utf8)); return 2
        }
        return 0
    }
}
