import Foundation
import AresClient   // Onion, Lineage, DAGNode, ByteUtil

/// SC-2 / SC-10 anon gossip arc: wraps the L1 onion-routing and lineage
/// primitives for a single participant in a slot-submission round.
public struct GossipParticipant: Sendable {
    let sessionID: String
    let selfIndex: Int
    let slotDKSk: Data
    let slotDKPub: Data

    public init(sessionID: String, selfIndex: Int, slotDKSk: Data, slotDKPub: Data) {
        self.sessionID = sessionID
        self.selfIndex = selfIndex
        self.slotDKSk = slotDKSk
        self.slotDKPub = slotDKPub
    }

    /// Canonical slot-entry JSON: {"slot_dk_pub":<hex>,"slot_index":<i>} sorted-keys compact.
    /// Identical bytes serve as the onion payload AND the slot.submit payload.
    func slotEntryBytes() throws -> Data {
        let obj: [String: Any] = [
            "slot_index": selfIndex,
            "slot_dk_pub": ByteUtil.hex(slotDKPub)
        ]
        return try JSONSerialization.data(
            withJSONObject: obj,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }

    /// Build the onion-batch payload `{"onions":[<base64 onion>]}` and return the
    /// self-memo byte blob needed later for peel-round identification.
    public func buildBatch(peerPubs: [Data]) throws -> (payloadJSON: Data, selfMemo: Data) {
        let entry = try slotEntryBytes()
        let (onion, selfMemo) = try Onion.build(
            payload: entry,
            peerPubs: peerPubs,
            selfIndex: selfIndex
        )
        let payload: [String: Any] = ["onions": [onion.base64EncodedString()]]
        let data = try JSONSerialization.data(
            withJSONObject: payload,
            options: [.sortedKeys]
        )
        return (data, selfMemo)
    }

    /// Peel one ECIES layer from every onion in the batch; locate own item via selfMemo.
    public func peelRound(selfMemo: Data, onions: [Data]) throws -> (peeled: [Data], ownIndex: Int) {
        try Onion.peelBatch(mySk: slotDKSk, selfMemo: selfMemo, onions: onions)
    }

    /// Produce the slot.submit payload bytes and a signed SC-10 lineage node over them.
    public func slotSubmission() throws -> (payloadBytes: Data, node: DAGNode) {
        let payloadBytes = try slotEntryBytes()
        let (node, _, _) = try Lineage.buildSlotNode(
            sessionID: sessionID,
            payloadBytes: payloadBytes
        )
        return (payloadBytes, node)
    }
}
