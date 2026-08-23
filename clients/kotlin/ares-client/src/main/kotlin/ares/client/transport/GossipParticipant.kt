// SPDX-License-Identifier: Apache-2.0

package ares.client.transport

import ares.client.ByteUtil
import ares.client.DAGNode
import ares.client.Lineage
import ares.client.Onion
import java.util.Base64

/**
 * SC-2 / SC-10 anon gossip arc: wraps the L1 onion-routing and lineage
 * primitives for a single participant in a slot-submission round.
 *
 * Mirrors Swift [GossipParticipant] and Python [GossipParticipant] exactly.
 *
 * @param sessionID  ARES session identifier (used in lineage node)
 * @param selfIndex  participant's position in the peel order (0-based); also
 *                   used as slot_index in the slot-entry JSON
 * @param slotDKSk   raw 32-byte X25519 private key (slot delivery key)
 * @param slotDKPub  raw 32-byte X25519 public key
 */
class GossipParticipant(
    private val sessionID: String,
    private val selfIndex: Int,
    private val slotDKSk: ByteArray,
    private val slotDKPub: ByteArray,
) {
    /**
     * Canonical slot-entry JSON: `{"slot_dk_pub":<hex>,"slot_index":<i>}`.
     *
     * Keys are sorted alphabetically ("slot_dk_pub" < "slot_index") and the
     * output is compact (no whitespace). These are the exact bytes used as the
     * onion payload in [buildBatch] AND the slot.submit payload in
     * [slotSubmission], so the Go `anon.SlotEntry` decoder accepts them.
     */
    fun slotEntryBytes(): ByteArray =
        ("{\"slot_dk_pub\":\"${ByteUtil.hex(slotDKPub)}\",\"slot_index\":$selfIndex}")
            .toByteArray(Charsets.UTF_8)

    /**
     * Build the initial onion batch payload `{"onions":[<base64 onion>]}` and
     * return the self-memo blob for later peel-round identification.
     *
     * @param peerPubs  raw X25519 pubkeys of ALL participants in peel order
     * @return (payloadJSON bytes, selfMemo bytes)
     */
    fun buildBatch(peerPubs: List<ByteArray>): Pair<ByteArray, ByteArray> {
        val entry = slotEntryBytes()
        val (onion, memo) = Onion.build(entry, peerPubs, selfIndex)
        val payload = "{\"onions\":[\"${Base64.getEncoder().encodeToString(onion)}\"]}"
            .toByteArray(Charsets.UTF_8)
        return Pair(payload, memo)
    }

    /**
     * Peel one ECIES layer from every onion in [onions]; identify own item via
     * [selfMemo]. Mirrors [Onion.peelBatch] directly.
     *
     * @return (peeled onions list, ownIndex — index of own item in the list)
     */
    fun peelRound(selfMemo: ByteArray, onions: List<ByteArray>): Pair<List<ByteArray>, Int> =
        Onion.peelBatch(slotDKSk, selfMemo, onions)

    /**
     * Build the slot.submit payload bytes and a signed SC-10 lineage [DAGNode]
     * that commits to those bytes via its payload_hash.
     *
     * @return (payloadBytes, node)
     */
    fun slotSubmission(): Pair<ByteArray, DAGNode> {
        val payload = slotEntryBytes()
        return Pair(payload, Lineage.buildSlotNode(sessionID, payload).node)
    }
}
