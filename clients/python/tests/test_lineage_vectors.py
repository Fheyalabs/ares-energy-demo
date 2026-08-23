# SPDX-License-Identifier: Apache-2.0
"""Golden-vector parity: Python must reproduce Go's lineage node byte-for-byte."""
import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).parent.parent.parent.parent / \
    "pkg/ares/lineage/testdata/node_vectors.json"


def load_vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)


@pytest.mark.parametrize("vec", load_vectors(), ids=lambda v: v["name"])
def test_golden_vector(vec):
    from ares_client.lineage import build_slot_node

    seed = bytes.fromhex(vec["input"]["ed25519_seed_hex"])
    session_id = vec["input"]["session_id"]
    payload_bytes = bytes.fromhex(vec["input"]["payload_hex"])
    parents_hex = vec["input"]["parents_hex"]

    node, _sk, _pk = build_slot_node(
        session_id=session_id,
        payload_bytes=payload_bytes,
        ed25519_seed=seed,
        parents_hex=parents_hex,
        phase_id=vec["input"]["phase_id"],
        role=vec["input"].get("role", "slot-submission"),
    )

    exp = vec["expected"]
    assert node["producer"] == exp["producer_hex"], "producer mismatch"
    assert node["payload_hash"] == exp["payload_hash_hex"], "payload_hash mismatch"
    assert node["hash"] == exp["node_hash_hex"], "node_hash mismatch"
    assert node["signature"] == exp["signature_hex"], "signature mismatch"
    assert node["algorithm"] == exp["algorithm"], "algorithm mismatch"
