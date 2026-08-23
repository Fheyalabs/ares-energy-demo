# SPDX-License-Identifier: Apache-2.0
"""SC-2-correct ECIES onion build / peel — N layers, one per participant.

SC-2 fix: build_onion applies N ECIES layers in reverse peel order (innermost
layer = last peeler, outermost layer = first peeler).  The builder records
self_memo as the ciphertext blob immediately after its own layer is applied;
peel_batch identifies the caller's own item by exact ciphertext match against
self_memo BEFORE decryption — never by "can't decrypt", which is the SC-2 fix.

Previous (incorrect) code encrypted under only the builder's own key (1 layer).
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PUB_LEN = 32
_NONCE_LEN = 12
_HKDF_INFO = b"ares_onion_v1"


def _ecies_encrypt(recipient_pub_bytes: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* for *recipient_pub_bytes* using ephemeral ECDH + AES-GCM."""
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    shared = eph_sk.exchange(X25519PublicKey.from_public_bytes(recipient_pub_bytes))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(shared)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    pub_raw = eph_pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return pub_raw + nonce + ct


def _ecies_decrypt(recipient_sk_bytes: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext produced by :func:`_ecies_encrypt`.

    Raises :class:`cryptography.exceptions.InvalidTag` if the key is wrong or
    the ciphertext is not a valid ECIES blob.
    """
    sk = X25519PrivateKey.from_private_bytes(recipient_sk_bytes)
    if len(ciphertext) < _PUB_LEN + _NONCE_LEN + 16:  # 16 = AES-GCM tag
        raise InvalidTag
    eph_pk = X25519PublicKey.from_public_bytes(ciphertext[:_PUB_LEN])
    nonce = ciphertext[_PUB_LEN:_PUB_LEN + _NONCE_LEN]
    ct = ciphertext[_PUB_LEN + _NONCE_LEN:]
    shared = sk.exchange(eph_pk)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, None)


def build_onion(
    payload: bytes,
    peel_order_pubs: list[bytes],
    self_index: int,
) -> tuple[bytes, bytes]:
    """Wrap *payload* in N ECIES layers — one per participant — in REVERSE peel order (SC-2 correct).

    Layers are applied innermost-first: the last peeler's key is applied first
    (innermost), and the first peeler's key is applied last (outermost).
    ``self_memo`` is the ciphertext blob immediately after the builder's own
    layer was applied, before any outer layers are added.  It is used by
    :func:`peel_batch` to identify the builder's own item by exact byte match
    — never by decryption failure, which is the SC-2 fix.

    Args:
        payload: The plaintext to protect.
        peel_order_pubs: Ordered list of raw 32-byte X25519 public keys for
            all N parties in peeling order.
        self_index: The caller's position in *peel_order_pubs*.

    Returns:
        ``(onion, self_memo)`` where *onion* is the fully-wrapped N-layer
        ciphertext and *self_memo* is the intermediate ciphertext after the
        builder's own layer (used for self-identification in
        :func:`peel_batch`).
    """
    if not (0 <= self_index < len(peel_order_pubs)):
        raise ValueError(f"self_index {self_index} out of range [0, {len(peel_order_pubs)})")
    data = payload
    self_memo: bytes | None = None
    for i in range(len(peel_order_pubs) - 1, -1, -1):
        data = _ecies_encrypt(peel_order_pubs[i], data)
        if i == self_index:
            self_memo = data
    assert self_memo is not None
    return data, self_memo


def peel_batch(
    my_sk_bytes: bytes,
    self_memo: bytes | None,
    onions: list[bytes],
) -> tuple[list[bytes], int]:
    """Peel one ECIES layer from every item in *onions* (SC-2 correct).

    All items in a well-formed batch at round k are addressed to the same
    peeler; every item must decrypt successfully.  The caller's own item is
    identified by exact byte match against *self_memo* BEFORE decryption (the
    ciphertext memory match), so self-identification never relies on decryption
    failure.

    Args:
        my_sk_bytes: Raw 32-byte X25519 private key.
        self_memo: The ``self_memo`` value returned by :func:`build_onion` for
            the caller's own item — the ciphertext blob the caller expects to
            see as the outermost layer of its own onion at this round.  Pass
            ``None`` to skip self-identification.
        onions: Current batch of onion blobs for this peel round.

    Returns:
        ``(peeled, own_index)`` where *peeled[i]* is the decrypted inner blob
        and *own_index* is the batch index of the caller's own item (-1 if
        *self_memo* is ``None`` or no match found).

    Raises:
        ValueError: If *self_memo* is given but no item in the batch matches.
    """
    peeled: list[bytes] = []
    own_index = -1
    for i, onion in enumerate(onions):
        if self_memo is not None and onion == self_memo:
            own_index = i
        peeled.append(_ecies_decrypt(my_sk_bytes, onion))
    if self_memo is not None and own_index < 0:
        raise ValueError("self_memo did not match any item in batch")
    return peeled, own_index
