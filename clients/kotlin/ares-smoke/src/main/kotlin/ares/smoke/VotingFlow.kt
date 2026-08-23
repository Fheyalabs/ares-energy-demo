// SPDX-License-Identifier: Apache-2.0
package ares.smoke

import ares.client.DAGNode
import ares.client.transport.AdminClient
import ares.client.transport.GossipParticipant
import ares.client.transport.Orchestrator
import ares.client.transport.TransportException
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.SecureRandom
import java.util.Base64

/**
 * End-to-end voting flow: onion-shuffle + SC-10 lineage slot submission +
 * ballot collection.
 *
 * Mirrors Swift [VotingFlow] exactly:
 *  1. All voters connect via WS, admin starts session.
 *  2. Each voter receives `vote.invitation`.
 *  3. All voters concurrently send `onion.batch`.
 *  4. The server assembles the full batch and sends `onion.peel_forward` to
 *     voter-0 only; each peeler strips its ECIES layer and forwards.
 *  5. State advances to VERIFYING; every voter sends `slot.submit` (v2 frame).
 *  6. State advances to SUBMITTING; every voter sends `vote.ballot`.
 *  7. Session tallies and reaches BROADCASTING / terminal state.
 *
 * Returns 0 on success, 1 on any error.
 */
object VotingFlow {

    fun run(serverURL: String, participants: Int, authSecret: String, sessionID: String): Int {
        val n = participants
        if (n < 2) {
            System.err.println("voting: need at least 2 participants")
            return 1
        }

        // --- Generate per-voter slot keypairs (X25519 raw bytes) ---
        // Use BouncyCastle lightweight API directly so .encoded gives the raw
        // 32-byte scalar / u-coordinate — exactly what Onion.build/peelBatch expect.
        val rng = SecureRandom()
        val slotSKs = ArrayList<ByteArray>(n)
        val slotPKs = ArrayList<ByteArray>(n)
        for (i in 0 until n) {
            val priv = X25519PrivateKeyParameters(rng)
            slotSKs.add(priv.encoded)                     // raw 32-byte scalar
            slotPKs.add(priv.generatePublicKey().encoded) // raw 32-byte u-coord
        }

        val voterNames = (0 until n).map { String.format("voter-%02d", it) }

        // --- Pre-build gossip participants ---
        val gossips = (0 until n).map { i ->
            GossipParticipant(
                sessionID  = sessionID,
                selfIndex  = i,
                slotDKSk   = slotSKs[i],
                slotDKPub  = slotPKs[i],
            )
        }

        // --- Pre-build onion batches + memos (all crypto before concurrency) ---
        val batchPayloads = ArrayList<ByteArray>(n)
        val selfMemos     = ArrayList<ByteArray>(n)
        for (i in 0 until n) {
            val (batchJSON, memo) = gossips[i].buildBatch(slotPKs)
            batchPayloads.add(batchJSON)
            selfMemos.add(memo)
        }

        // --- Pre-build slot submissions (payload bytes + lineage node) ---
        val slotPayloads = ArrayList<ByteArray>(n)
        val slotNodes    = ArrayList<DAGNode>(n)
        for (i in 0 until n) {
            val (payload, node) = gossips[i].slotSubmission()
            slotPayloads.add(payload)
            slotNodes.add(node)
        }

        // --- Connect all voters ---
        val admin = AdminClient(serverURL)
        admin.waitForHealth()

        val sessions = Orchestrator.connectAll(
            serverURL  = serverURL,
            pseudonyms = voterNames,
            sessionID  = sessionID,
            authSecret = authSecret,
        )

        // Brief pause to let all WS upgrade handshakes complete in the hub
        // before the admin POST triggers the invitation broadcast.
        Thread.sleep(300)

        // --- Start session ---
        admin.startSession(sessionID, voterNames)

        // --- Run all voters concurrently ---
        val errors = java.util.Collections.synchronizedList(ArrayList<String>())
        val threads = (0 until n).map { i ->
            val session    = sessions[i]
            val voterName  = voterNames[i]
            val batchPayload = batchPayloads[i]
            val selfMemo   = selfMemos[i]
            val gossip     = gossips[i]
            val slotPayload = slotPayloads[i]
            val slotNode   = slotNodes[i]

            Thread {
                try {
                    // 1. Wait for invitation.
                    session.expect("vote.invitation", 30_000)
                    System.err.println("voting: $voterName: got invitation")

                    // 2. Send onion.batch.
                    session.send("onion.batch", batchPayload)
                    System.err.println("voting: $voterName: sent onion.batch")

                    // 3. Peel chain: wait for onion.peel_forward, peel, send back.
                    //    The server only sends peel_forward to the voter whose turn
                    //    it is; others timeout and move on.
                    val peelDeadline = System.currentTimeMillis() + 60_000
                    var didPeel = false
                    outer@ while (System.currentTimeMillis() < peelDeadline) {
                        val remaining = peelDeadline - System.currentTimeMillis()
                        if (remaining <= 0) break
                        try {
                            val frame = session.receiveAny(minOf(remaining, 5_000))
                            when (frame.type) {
                                "onion.peel_forward" -> {
                                    System.err.println("voting: $voterName: received peel_forward, peeling")
                                    val onionBytes = decodeOnions(frame.raw)
                                    val (peeled, _) = gossip.peelRound(selfMemo, onionBytes)
                                    val peeledB64 = peeled.map { Base64.getEncoder().encodeToString(it) }
                                    val peelPayload = encodeOnions(peeledB64)
                                    session.send("onion.peel_forward", peelPayload)
                                    System.err.println("voting: $voterName: sent onion.peel_forward")
                                    didPeel = true
                                    break@outer
                                }
                                else -> {
                                    // Other message types (e.g. phase-transition notifications) — log and continue.
                                    System.err.println("voting: $voterName: dropped ${frame.type} while waiting for peel")
                                }
                            }
                        } catch (e: TransportException) {
                            // Timeout — no peel_forward for this voter (not our turn).
                            break
                        }
                    }
                    if (!didPeel) {
                        System.err.println("voting: $voterName: no peel turn (not in peel chain)")
                    }

                    // 4. Wait for VERIFYING.
                    session.awaitPhase("VERIFYING", 60_000)
                    System.err.println("voting: $voterName: state is VERIFYING")

                    // 5. Send slot.submit (v2 frame with lineage).
                    session.send("slot.submit", slotPayload, slotNode)
                    System.err.println("voting: $voterName: sent slot.submit")

                    // 6. Wait for SUBMITTING.
                    session.awaitPhase("SUBMITTING", 30_000)
                    System.err.println("voting: $voterName: state is SUBMITTING")

                    // 7. Send vote.ballot.
                    val choice = i % 2
                    val ballotJSON = "{\"choice\":$choice,\"weight\":1.0}".toByteArray(Charsets.UTF_8)
                    session.send("vote.ballot", ballotJSON)
                    System.err.println("voting: $voterName: sent vote.ballot choice=$choice")

                } catch (e: Exception) {
                    val msg = "$voterName: ${e.message ?: e.toString()}"
                    System.err.println("voting: flow error: $msg")
                    errors.add(msg)
                }
            }.also { it.name = "voter-$i" }
        }

        threads.forEach { it.start() }
        threads.forEach { it.join() }

        // Close sessions.
        Orchestrator.closeAll(sessions)

        // --- Poll for terminal state ---
        val terminal = admin.pollUntilTerminal(sessionID, "BROADCASTING", tries = 40, intervalMs = 500)

        if (errors.isNotEmpty()) {
            System.err.println("voting: FAILED (flow errors): ${errors.joinToString("; ")}")
            return 1
        }

        // BROADCASTING or empty (terminal / closed) is success.
        return if (terminal == "BROADCASTING" || terminal.isEmpty()) {
            System.err.println("voting: reached terminal state: ${if (terminal.isEmpty()) "(closed)" else terminal}")
            0
        } else {
            System.err.println("voting: stuck at state: $terminal")
            1
        }
    }

    // -----------------------------------------------------------------------
    // Payload helpers — mirror Swift decodeOnions / encodeOnions
    // -----------------------------------------------------------------------

    /**
     * Extract the `{"onions":[...]}` list from a raw inbound frame text.
     *
     * The server sends `onion.peel_forward` frames whose payload field is:
     *   `{"onions":["<base64>","<base64>",...]}`
     *
     * We extract the `onions` JSON array from the raw frame text using a
     * regex (mirrors Swift extractPayload / decodeOnions helpers).
     */
    internal fun decodeOnions(rawBytes: ByteArray): List<ByteArray> {
        val rawFrame = strictUTF8(rawBytes)
        // Extract the value of "payload": {...} from the outer WireFrame JSON.
        // The payload is inlined verbatim, so it is a JSON object nested inside
        // the outer frame object.  We search for the "onions" array directly.
        val arrayMatch = Regex("\"onions\"\\s*:\\s*\\[([^\\]]*)]")
            .find(rawFrame)
            ?: throw TransportException("peel_forward: missing 'onions' array in frame: $rawFrame")
        val arrayContent = arrayMatch.groupValues[1]
        // Parse base64 strings: find all quoted values.
        val entries = Regex("\"([A-Za-z0-9+/=]+)\"").findAll(arrayContent)
            .map { it.groupValues[1] }.toList()
        if (entries.isEmpty()) throw TransportException("peel_forward: empty onions array")
        return entries.map { b64 ->
            Base64.getDecoder().decode(b64)
                ?: throw TransportException("peel_forward: bad base64 in onions: $b64")
        }
    }

    /**
     * Encode `{"onions":[...]}` from a list of base64 strings.
     *
     * Keys are sorted (only one key, so this is trivially sorted) and output
     * is compact — matching the Swift JSONSerialization.data(options: [.sortedKeys]).
     */
    private fun encodeOnions(b64List: List<String>): ByteArray {
        val sb = StringBuilder("{\"onions\":[")
        b64List.forEachIndexed { idx, b64 ->
            if (idx > 0) sb.append(',')
            sb.append('"').append(b64).append('"')
        }
        sb.append("]}")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}
