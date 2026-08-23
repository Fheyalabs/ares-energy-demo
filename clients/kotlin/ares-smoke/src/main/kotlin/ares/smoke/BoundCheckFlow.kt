// SPDX-License-Identifier: Apache-2.0

package ares.smoke

import ares.client.ByteUtil
import ares.client.fhe.BoundCheckParticipant
import ares.client.fhe.CryptoContext
import ares.client.fhe.EvalMultKey
import ares.client.fhe.PublicKey
import ares.client.fhe.RotKey
import ares.client.fhe.SecretKeyShare
import ares.client.transport.AdminClient
import ares.client.transport.Orchestrator
import kotlin.math.sqrt

object BoundCheckFlow {
    /** Extract a JSON string-to-string map from the transport's raw frame. */
    internal fun extractStringMap(rawBytes: ByteArray, key: String): Map<String, String> {
        val raw = strictUTF8(rawBytes)
        val start = raw.indexOf("\"$key\":{")
        if (start == -1) return emptyMap()
        var i = start + key.length + 4
        val result = LinkedHashMap<String, String>()
        while (i < raw.length && raw[i] != '}') {
            if (raw[i] == ',') i++
            if (raw[i] != '"') break
            val keyStart = i + 1
            val keyEnd = raw.indexOf('"', keyStart)
            val partyKey = raw.substring(keyStart, keyEnd)
            i = raw.indexOf('"', keyEnd + 2) + 1
            val valStart = i
            val valEnd = raw.indexOf('"', valStart)
            result[partyKey] = raw.substring(valStart, valEnd)
            i = valEnd + 1
        }
        return result
    }

    fun run(serverURL: String, participants: Int, authSecret: String, sessionID: String, mode: String): Int {
        val dim = (System.getenv("ADMISSION_DIM") ?: "8").toInt()
        val depth = (System.getenv("ADMISSION_CRYPTO_DEPTH") ?: "8").toInt()
        val ringDim = (System.getenv("ADMISSION_RING_DIM") ?: "16384").toInt()
        val n = participants

        val parties = (0 until n).map { "party-$it" }
        val ctx = CryptoContext(ringDim, Math.scalb(1.0, 50), depth)
        ctx.use {
            // --- 1. Local N-party threshold keygen + eval-mult + eval-sum keys ---
            val pks = ArrayList<PublicKey>(); val sks = ArrayList<SecretKeyShare>()
            val f = ctx.keyGenFirst(); pks.add(f.publicKey); sks.add(f.secretKey)
            repeat(n - 1) { val nx = ctx.keyGenNext(pks.last()); pks.add(nx.publicKey); sks.add(nx.secretKey) }
            val collectivePK = pks.last()

            // eval-mult-key 2-round
            val emkBase = ctx.evalMultKeyGenLead(sks[0])
            val emkR1 = ArrayList<EvalMultKey>(); emkR1.add(emkBase)
            for (i in 1 until sks.size) emkR1.add(ctx.evalMultKeySwitchShare(sks[i], emkBase))
            val emkJoined = ctx.combineEvalMultSwitchShares(pks, emkR1)
            val emkFin = ArrayList<EvalMultKey>()
            for (sk in sks) emkFin.add(ctx.evalMultKeyFinalShare(sk, emkJoined, collectivePK))
            val evalMultFinal = ctx.combineEvalMultFinalShares(collectivePK, emkFin)
            emkBase.close(); emkR1.forEach { it.close() }; emkJoined.close(); emkFin.forEach { it.close() }

            // eval-sum (rotation) key
            val eskBase = ctx.evalSumKeyGenLead(sks[0])
            val eskShares = ArrayList<RotKey>()
            for (i in 0 until sks.size) eskShares.add(ctx.evalSumKeyShare(sks[i], eskBase, pks[i]))
            val evalSumFinal = ctx.combineEvalSumKeys(pks, eskShares)
            eskBase.close(); eskShares.forEach { it.close() }

            // --- 2. Encrypt inputs ---
            val unitVal = sqrt(1.0 / dim)
            val allEncX = HashMap<String, ByteArray>()
            val encXHex = HashMap<String, String>()
            for ((i, party) in parties.withIndex()) {
                val inflate = mode == "violation" && i == 0
                val vals = DoubleArray(dim) { unitVal * if (inflate) 2.0 else 1.0 }
                val ct = ctx.encrypt(vals, collectivePK)
                val ser = ctx.serialize(ct); allEncX[party] = ser
                encXHex[party] = ByteUtil.hex(ser)
                ct.close()
            }

            // --- 3. Seed pre-shared keys + connect + start session ---
            val attrs = mapOf(
                "collective_pk" to ByteUtil.hex(ctx.serialize(collectivePK)),
                "eval_mult_final" to ByteUtil.hex(ctx.serialize(evalMultFinal)),
                "eval_sum_final" to ByteUtil.hex(ctx.serialize(evalSumFinal)),
                "dim" to dim.toString(),
                "ring_dim" to ringDim.toString(),
                "depth" to depth.toString(),
            )
            evalMultFinal.close(); evalSumFinal.close()

            val admin = AdminClient(serverURL)
            admin.waitForHealth()
            val sessions = Orchestrator.connectAll(serverURL, parties, sessionID, authSecret)
            try {
                Thread.sleep(2_000)
                admin.startSession(sessionID, parties, attrs)

                // --- 4. Phase A (concurrent threads): each party submits input and awaits
                //        bound_check.challenge. No FHE here — pure WS I/O. Concurrent is
                //        required: the server only broadcasts the challenge once ALL inputs
                //        are in, so each party must NOT block waiting for the challenge
                //        before the next party submits. ---
                val challengeChecks = HashMap<String, String>()
                val challengeCommitments = HashMap<String, String>()
                val threads = sessions.mapIndexed { idx, session ->
                    val me = parties[idx]; val myInputHex = encXHex[me]!!
                    kotlin.concurrent.thread {
                        runCatching {
                            session.expect("admission.invitation")
                            session.send("admission.input", "{\"enc_x\":\"$myInputHex\"}".toByteArray())
                            val frame = session.expect("bound_check.challenge")
                            val checks = extractStringMap(frame.raw, "checks")
                            val commits = extractStringMap(frame.raw, "commitments")
                            synchronized(challengeChecks) { challengeChecks.putAll(checks) }
                            synchronized(challengeCommitments) { challengeCommitments.putAll(commits) }
                        }
                    }
                }
                threads.forEach { it.join() }
                check(challengeChecks.isNotEmpty()) { "boundcheck: no bound_check.challenge received" }

                // --- 5. Phase B (serial FHE): for each party, implicitly verify its own
                //        commitment, then partial-decrypt the REAL enc_check of EVERY
                //        checked party (boundcheck.Exit fuses N-of-N quorum PER ciphertext). ---
                val partyPassed = HashMap<String, Boolean>()
                for ((idx, session) in sessions.withIndex()) {
                    val me = parties[idx]
                    // Tamper mode: party-0 verifies against a different valid enc_check
                    // (the commitment was bound to party-0's own, so mismatch → passed=false).
                    val verifyParty = if (mode == "tamper" && idx == 0) parties[(idx + 1) % n] else me
                    val verifyEncCheck = ByteUtil.fromHex(challengeChecks[verifyParty]!!)!!
                    val ownCommitment = ByteUtil.fromHex(challengeCommitments[me]!!)!!

                    val result = BoundCheckParticipant.participate(
                        ctx, verifyEncCheck, allEncX[me]!!, sessionID, ownCommitment, sks[idx])
                    partyPassed[me] = result.passed

                    // Partial map: this party's partial of EVERY real enc_check.
                    val partialMap = LinkedHashMap<String, String>()
                    for (checkedParty in parties) {
                        val ct = ctx.deserializeCiphertext(ByteUtil.fromHex(challengeChecks[checkedParty]!!)!!)
                        val partial = ctx.partialDecrypt(ct, sks[idx])
                        partialMap[checkedParty] = java.util.Base64.getEncoder().encodeToString(ctx.serialize(partial))
                        ct.close(); partial.close()
                    }
                    val entries = partialMap.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }
                    session.send("bound_check.partial", "{$entries}".toByteArray())
                }

                // --- 6. Assertions ---
                val terminal = admin.pollUntilTerminal(sessionID, "ADMISSION_SETTLED")
                System.err.println("boundcheck: terminal=$terminal")

                return when (mode) {
                    "inbound" -> {
                        if (terminal != "ADMISSION_SETTLED" && !terminal.isEmpty()) { System.err.println("boundcheck INBOUND FAIL: expected SETTLED, got $terminal"); 1 }
                        else if (partyPassed.values.any { !it }) { System.err.println("boundcheck INBOUND FAIL: not all passed: $partyPassed"); 1 }
                        else { System.err.println("boundcheck INBOUND: OK"); 0 }
                    }
                    "violation" -> {
                        if (partyPassed[parties[0]] != true) { System.err.println("boundcheck VIOLATION FAIL: party-0 passed=${partyPassed[parties[0]]}"); 1 }
                        else if (terminal == "ADMISSION_SETTLED") { System.err.println("boundcheck VIOLATION FAIL: expected abort"); 1 }
                        else { System.err.println("boundcheck VIOLATION: OK"); 0 }
                    }
                    "tamper" -> {
                        if (partyPassed[parties[0]] != false) { System.err.println("boundcheck TAMPER FAIL: expected party-0 passed=false"); 1 }
                        else { System.err.println("boundcheck TAMPER: OK"); 0 }
                    }
                    else -> { System.err.println("boundcheck: unknown mode $mode"); 2 }
                }
            } finally {
                Orchestrator.closeAll(sessions)
            }
        }
    }
}
