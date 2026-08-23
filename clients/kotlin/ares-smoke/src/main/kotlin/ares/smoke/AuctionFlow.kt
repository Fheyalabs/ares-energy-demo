// SPDX-License-Identifier: Apache-2.0

package ares.smoke

import ares.client.ByteUtil
import ares.client.fhe.CryptoContext
import ares.client.fhe.EvalMultKey
import ares.client.fhe.PublicKey
import ares.client.fhe.SecretKeyShare
import ares.client.transport.AdminClient
import ares.client.transport.Orchestrator

object AuctionFlow {
    fun run(serverURL: String, participants: Int, authSecret: String, sessionID: String): Int {
        val bidders = (0 until participants).map { "bidder-%02d".format(it) }
        val scores = (0 until participants).map { -0.8 + Math.random() * 1.6 }  // [-0.8, 0.8]

        // Crypto params MUST match the server (auction.sh exports these to both sides).
        val depth = (System.getenv("AUCTION_CRYPTO_DEPTH") ?: "12").toInt()
        val ringDim = (System.getenv("AUCTION_RING_DIM") ?: "2048").toInt()

        val ctx = CryptoContext(ringDim, Math.scalb(1.0, 50), depth)
        ctx.use {
            // 1. Local N-party threshold keygen; hold all shares client-side.
            val pks = ArrayList<PublicKey>(); val sks = ArrayList<SecretKeyShare>()
            val first = ctx.keyGenFirst(); pks.add(first.publicKey); sks.add(first.secretKey)
            repeat(participants - 1) { val nx = ctx.keyGenNext(pks.last()); pks.add(nx.publicKey); sks.add(nx.secretKey) }
            val collectivePK = pks.last()

            // eval-mult-key 2-round protocol → evalMultFinal (close intermediates to bound native mem)
            val base = ctx.evalMultKeyGenLead(sks[0])
            val r1 = ArrayList<EvalMultKey>(); r1.add(base)
            for (i in 1 until sks.size) r1.add(ctx.evalMultKeySwitchShare(sks[i], base))
            val joined = ctx.combineEvalMultSwitchShares(pks, r1)
            val fin = ArrayList<EvalMultKey>()
            for (sk in sks) fin.add(ctx.evalMultKeyFinalShare(sk, joined, collectivePK))
            val evalMultFinal = ctx.combineEvalMultFinalShares(collectivePK, fin)
            // Close intermediate eval-key handles to bound native memory.
            base.close(); r1.forEach { it.close() }; joined.close(); fin.forEach { it.close() }

            // 2. Encrypt each bid as a normalized scalar [score,0,0,0]; serialize → hex.
            val bidCTHex = HashMap<String, String>()
            for (i in bidders.indices) {
                val ct = ctx.encrypt(doubleArrayOf(scores[i], 0.0, 0.0, 0.0), collectivePK)
                bidCTHex[bidders[i]] = ByteUtil.hex(ctx.serialize(ct))
                ct.close()
            }
            val decryptTargetHex = bidCTHex[bidders[0]]!!

            // 3. Pre-compute each bidder's partial of bidder-0's ciphertext (FHE handles not
            //    thread-safe → do all FHE before the concurrent WS phase, mirroring Swift).
            val partialHexByBidder = HashMap<String, String>()
            for (i in bidders.indices) {
                val targetCT = ctx.deserializeCiphertext(ByteUtil.fromHex(decryptTargetHex)!!)
                val partial = ctx.partialDecrypt(targetCT, sks[i])
                partialHexByBidder[bidders[i]] = ByteUtil.hex(ctx.serialize(partial))
                targetCT.close(); partial.close()
            }

            // 4. Seed pre-shared keys via admin attrs so the server uses our local bundle.
            val attrs = mapOf(
                "auction.collective_pk" to ByteUtil.hex(ctx.serialize(collectivePK)),
                "auction.eval_keys" to ByteUtil.hex(ctx.serialize(evalMultFinal)),
            )
            evalMultFinal.close()
            val admin = AdminClient(serverURL)
            admin.waitForHealth()
            val sessions = Orchestrator.connectAll(serverURL, bidders, sessionID, authSecret)
            try {
                admin.startSession(sessionID, bidders, attrs)
                // 5. Per-bidder WS flow (concurrent — only pre-computed Strings captured).
                val errors = java.util.Collections.synchronizedList(ArrayList<String>())
                val threads = sessions.mapIndexed { idx, s ->
                    val bidder = bidders[idx]
                    val bidHex = bidCTHex[bidder]!!; val partialHex = partialHexByBidder[bidder]!!
                    kotlin.concurrent.thread {
                        runCatching {
                            s.expect("auction.invitation")
                            s.send("auction.keygen.share", "{\"share\":\"ks-$bidder\"}".toByteArray())
                            s.awaitPhase("AUCTION_BIDDING")
                            s.send("auction.bid", "{\"bid_ct\":\"$bidHex\"}".toByteArray())
                            s.awaitPhase("AUCTION_DECRYPTING")
                            s.send("auction.decrypt.partial", "{\"partial_ct\":\"$partialHex\"}".toByteArray())
                        }.onFailure { errors.add("$bidder: $it") }
                    }
                }
                threads.forEach { it.join() }
                if (errors.isNotEmpty()) { errors.forEach { System.err.println("auction: $it") }; return 1 }
                val terminal = admin.pollUntilTerminal(sessionID, "AUCTION_SETTLED")
                System.err.println("auction: reached ${if (terminal.isEmpty()) "terminal" else terminal}")
                return if (terminal == "AUCTION_SETTLED" || terminal.isEmpty()) 0 else 1
            } finally {
                Orchestrator.closeAll(sessions)
            }
        }
    }
}
