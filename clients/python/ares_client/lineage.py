# SPDX-License-Identifier: Apache-2.0
"""SC-10 lineage DAGNode builder — Python implementation of the SP-B2-C contract."""
from __future__ import annotations

import datetime
import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)


def _lp(b: bytes) -> bytes:
    """4-byte big-endian length prefix followed by b."""
    return struct.pack(">I", len(b)) + b


def build_slot_node(
    session_id: str,
    payload_bytes: bytes,
    ed25519_seed: bytes | None = None,
    parents_hex: list[str] | None = None,
    phase_id: str = "anon-g-verify",
    role: str = "slot-submission",
) -> tuple[dict, bytes, bytes]:
    """Build a SC-10 DAGNode for a slot submission per the SP-B2-C contract.

    Returns (node_dict, raw_sk_32, raw_pk_32). node_dict is ready for
    JSON serialisation as the "lineage" field of a v2 WSMessage.
    created_at is informational and excluded from node_hash / signing_msg.
    """
    if parents_hex is None:
        parents_hex = []

    sid_b = session_id.encode()
    phase_b = phase_id.encode()
    role_b = role.encode()

    # 1. payload_hash = SHA-256(payload_bytes)
    payload_hash = hashlib.sha256(payload_bytes).digest()

    # 2. Validate and decode parents
    decoded_parents = []
    for ph in parents_hex:
        try:
            pb = bytes.fromhex(ph)
        except ValueError:
            raise ValueError(f"parent hash is not valid hex: {ph!r}") from None
        if len(pb) != 32:
            raise ValueError(
                f"parent hash must be 32 bytes, got {len(pb)}: {ph!r}"
            )
        decoded_parents.append(pb)

    # 3. node_hash — parents sorted lexicographically (raw bytes), then written
    # without a per-parent length prefix (matches Go's DeriveNodeHash).
    sorted_parents = sorted(decoded_parents)
    node_hash_input = _lp(sid_b) + _lp(phase_b) + _lp(role_b) + _lp(payload_hash)
    node_hash_input += struct.pack(">I", len(sorted_parents))
    for pb in sorted_parents:
        node_hash_input += pb  # raw 32 bytes, no length prefix
    node_hash = hashlib.sha256(node_hash_input).digest()

    # 4. signing_msg = node_hash || lp(session_id) || lp(phase_id) || lp(role)
    signing_msg = node_hash + _lp(sid_b) + _lp(phase_b) + _lp(role_b)

    # 5. Ephemeral Ed25519 keypair
    if ed25519_seed is not None:
        sk = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    else:
        sk = Ed25519PrivateKey.generate()

    pk_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sk_raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    sig_bytes = sk.sign(signing_msg)

    node_dict: dict = {
        "hash": node_hash.hex(),
        "session_id": session_id,
        "phase_id": phase_id,
        "role": role,
        "parents": [pb.hex() for pb in sorted_parents],
        "parent_roles": [],
        "payload_hash": payload_hash.hex(),
        "created_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "producer": pk_raw.hex(),
        "signature": sig_bytes.hex(),
        "algorithm": "ed25519",
    }
    return node_dict, sk_raw, pk_raw
