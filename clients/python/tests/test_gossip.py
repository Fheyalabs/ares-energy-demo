# SPDX-License-Identifier: Apache-2.0
"""Tests for GossipParticipant — full onion build/peel/submit cycle."""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)


def _x25519_keygen() -> tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk_b, pk_b


def test_gossip_participant_full_cycle():
    """N=3 participants: build onions, peel N rounds, each recovers its payload."""
    from ares_client.gossip import GossipParticipant

    n = 3
    session_id = "gossip-test-session"
    keys = [_x25519_keygen() for _ in range(n)]
    pubs = [pk for _, pk in keys]

    participants = [
        GossipParticipant(
            session_id=session_id,
            self_index=i,
            slot_dk_sk=keys[i][0],
            slot_dk_pub=keys[i][1],
        )
        for i in range(n)
    ]

    # Each builds their onion batch (N-layer, wrapping their slot entry).
    batches_and_memos = [p.build_batch(pubs) for p in participants]
    memos = [m for _, m in batches_and_memos]

    # shared_batch: one onion per participant (batch[i] = participant i's onion).
    shared_batch = [
        base64.b64decode(batch_dict["onions"][0])
        for batch_dict, _ in batches_and_memos
    ]

    # N sequential peel rounds. After all N rounds, all layers are peeled.
    # own_payload at round k has n-k-1 remaining inner layers (not plaintext yet,
    # except at the last round k=n-1).
    for k in range(n):
        peeled, own_payload = participants[k].peel_round(memos[k], shared_batch)
        assert own_payload is not None, f"participant {k} did not find its own item"
        if k == n - 1:
            last_slot = json.loads(own_payload)
            assert last_slot["slot_index"] == n - 1
        shared_batch = peeled

    # After all N rounds, shared_batch[i] is the plaintext for participant i
    # (batch order is preserved; all onions used the same peel order).
    for i in range(n):
        slot_data = json.loads(shared_batch[i])
        assert slot_data["slot_index"] == i, f"participant {i}: wrong slot_index"
        assert slot_data["slot_dk_pub"] == keys[i][1].hex(), f"participant {i}: wrong slot_dk_pub"


def test_slot_submission_produces_valid_lineage_node():
    """slot_submission returns valid payload bytes and lineage node."""
    from ares_client.gossip import GossipParticipant
    keys = [_x25519_keygen() for _ in range(2)]
    p = GossipParticipant(
        session_id="test-session",
        self_index=0,
        slot_dk_sk=keys[0][0],
        slot_dk_pub=keys[0][1],
    )
    payload_bytes, node_dict = p.slot_submission()
    assert isinstance(payload_bytes, bytes)
    slot = json.loads(payload_bytes)
    assert slot["slot_index"] == 0
    assert slot["slot_dk_pub"] == keys[0][1].hex()
    assert node_dict["phase_id"] == "anon-g-verify"
    assert node_dict["role"] == "slot-submission"
    assert node_dict["algorithm"] == "ed25519"
    assert len(node_dict["hash"]) == 64
    assert len(node_dict["signature"]) == 128
    assert node_dict["parents"] == [], "slot submissions must have no lineage parents"
    assert node_dict["payload_hash"] == hashlib.sha256(payload_bytes).hexdigest(), \
        "lineage payload_hash must be SHA-256 of the exact payload bytes returned"
