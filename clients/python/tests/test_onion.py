# SPDX-License-Identifier: Apache-2.0
"""Tests for SC-2-correct onion primitives."""
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _keygen() -> tuple[bytes, bytes]:
    """Return (raw_sk_32, raw_pk_32)."""
    sk = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pk_b = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk_b, pk_b


def test_build_onion_includes_self_layer():
    """SC-2: build_onion produces N layers including the builder's own."""
    from ares_client.onion import build_onion, peel_batch
    n = 4
    keys = [_keygen() for _ in range(n)]
    pubs = [pk for _, pk in keys]
    payload = b"test-payload"

    onion, self_memo = build_onion(payload, pubs, self_index=0)

    assert isinstance(self_memo, bytes) and len(self_memo) > 0
    assert len(onion) > len(payload)


def test_peel_batch_round_trip():
    """N participants peel all N rounds; each recovers its payload via self_memo.

    Each onion has N layers.  Round k has party k peel one layer from the whole
    batch.  Party k identifies its own item at round k via self_memo (ciphertext
    match), but the payload is fully exposed only after all N rounds complete
    (each round strips one layer).  own_idx is stable across rounds since items
    maintain their positions in the batch.
    """
    from ares_client.onion import build_onion, peel_batch
    n = 4
    keys = [_keygen() for _ in range(n)]
    pubs = [pk for _, pk in keys]
    payloads = [f"payload-{i}".encode() for i in range(n)]

    batches_and_memos = [
        build_onion(payloads[i], pubs, self_index=i) for i in range(n)
    ]
    batch = [o for o, _ in batches_and_memos]
    memos = [m for _, m in batches_and_memos]

    # Track the batch index of each party's own item (stable across rounds).
    own_indices = [-1] * n
    for k in range(n):
        sk_k, _ = keys[k]
        peeled, own_idx = peel_batch(sk_k, memos[k], batch)
        assert own_idx >= 0, f"peeler {k} did not find its own item"
        own_indices[k] = own_idx
        batch = peeled

    # After all N rounds every item has been fully peeled — batch[j] is now the
    # original plaintext for whichever party owned batch position j.
    for i in range(n):
        assert batch[own_indices[i]] == payloads[i], f"party {i} recovered wrong payload"


def test_no_skip_self_regression():
    """SC-2 fix: builder (self_index=0) can immediately identify its own item via self_memo."""
    from ares_client.onion import build_onion, peel_batch
    keys = [_keygen() for _ in range(3)]
    pubs = [pk for _, pk in keys]

    # With self_index=0, layer 0 is applied LAST (outermost), so self_memo == assembled onion.
    onion, self_memo = build_onion(b"secret", pubs, self_index=0)
    assert self_memo == onion, "self_index=0 must produce self_memo == assembled onion"
    peeled, own_idx = peel_batch(keys[0][0], self_memo, [onion])
    assert own_idx == 0, "builder could not identify its own item"
    # Old SC-2-stale code would NOT include a self-layer; this test verifies we can
    # actually decrypt our own item (not just identify it by failure).
    assert len(peeled[0]) < len(onion)
