# SPDX-License-Identifier: Apache-2.0
"""Generic gossip-arc participant, mirroring Go's anon.Participant."""
from __future__ import annotations

import base64
import json

from .lineage import build_slot_node
from .onion import build_onion, peel_batch


class GossipParticipant:
    """One participant's client-side gossip arc state.

    Args:
        session_id: ARES session identifier (used in lineage node).
        self_index: participant's position in the peel order (0-based).
                    Also used as slot_index in the slot submission payload.
        slot_dk_sk: raw 32-byte X25519 private key (slot delivery key).
        slot_dk_pub: raw 32-byte X25519 public key.
    """

    def __init__(
        self,
        session_id: str,
        self_index: int,
        slot_dk_sk: bytes,
        slot_dk_pub: bytes,
    ) -> None:
        self._session_id = session_id
        self._self_index = self_index
        self._slot_dk_sk = slot_dk_sk
        self._slot_dk_pub = slot_dk_pub

    def _slot_entry_bytes(self) -> bytes:
        """Canonical JSON bytes for this participant's slot entry.

        Used both as the onion payload (build_batch) and the slot.submit
        payload (slot_submission), so the bytes are identical in both paths.
        """
        return json.dumps(
            {"slot_index": self._self_index, "slot_dk_pub": self._slot_dk_pub.hex()},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def build_batch(self, peer_pubs: list[bytes]) -> tuple[dict, bytes]:
        """Build the initial onion batch payload for onion.batch submission.

        Wraps the slot entry in len(peer_pubs) ECIES layers (SC-2: self-layer
        included). All participants use the same full peel order.

        Args:
            peer_pubs: raw X25519 pubkeys of ALL participants in peel order.

        Returns:
            (batch_payload_dict, self_memo) — dict has "onions" key with
            a list containing one base64-encoded onion.
        """
        slot_entry = self._slot_entry_bytes()
        onion, self_memo = build_onion(slot_entry, peer_pubs, self._self_index)
        return {"onions": [base64.b64encode(onion).decode()]}, self_memo

    def peel_round(
        self,
        self_memo: bytes,
        onions: list[bytes],
    ) -> tuple[list[bytes], bytes]:
        """Peel one ECIES layer from each onion; identify own item by self_memo.

        Args:
            self_memo: returned by build_batch for this participant.
            onions: raw onion bytes from the server broadcast.

        Returns:
            (peeled_onions, own_payload) — own_payload is the decrypted inner
            bytes for the own item (still has remaining inner layers unless this
            is the last peel round).

        Raises:
            ValueError: if self_memo does not match any item in onions
                (propagated from peel_batch).
        """
        peeled, own_idx = peel_batch(self._slot_dk_sk, self_memo, onions)
        assert own_idx >= 0, "peel_batch must locate own item or raise"
        return peeled, peeled[own_idx]

    def slot_submission(self) -> tuple[bytes, dict]:
        """Build the slot.submit payload bytes and signed lineage node.

        Returns:
            (payload_bytes, node_dict) — payload_bytes are the exact bytes
            to send as WSMessage.payload; node_dict is the SC-10 lineage
            DAGNode to attach as WSMessage.lineage.
        """
        payload_bytes = self._slot_entry_bytes()
        node_dict, _sk, _pk = build_slot_node(
            session_id=self._session_id,
            payload_bytes=payload_bytes,
        )
        return payload_bytes, node_dict
