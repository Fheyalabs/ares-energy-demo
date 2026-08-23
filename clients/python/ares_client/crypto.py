# SPDX-License-Identifier: Apache-2.0
"""OpenFHE crypto helpers (stub interface).

In Phase 4 these stubs are wired to the existing
ARES-impl ``openfhe-contract-helper`` so the scoring circuit runs for
real end-to-end on the homelab. For now they return placeholder bytes
so smoke flows can exercise the wire/state-machine without crypto.

Public API:

    crypto = StubCrypto()
    pk = await crypto.keygen_share(pseudonym, round=1)
    bid_ct = await crypto.encrypt_scalar(value=42, pk=pk)
    partial = await crypto.partial_decrypt(ct, share)
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any, Protocol


class CryptoProvider(Protocol):
    """Interface every concrete provider implements."""

    async def keygen_share(self, pseudonym: str, round: int) -> bytes: ...
    async def encrypt_scalar(self, value: float, pk: bytes) -> bytes: ...
    async def encrypt_vector(self, values: list[float], pk: bytes) -> bytes: ...
    async def partial_decrypt(self, ciphertext: bytes, share: bytes) -> bytes: ...


class StubCrypto:
    """Deterministic placeholder crypto.

    Returns short hash-derived bytes so the wire protocol moves but no
    real CKKS work happens. Replace with OpenFHECrypto (Phase 4) for
    real end-to-end runs.
    """

    async def keygen_share(self, pseudonym: str, round: int) -> bytes:
        await asyncio.sleep(0)
        digest = hashlib.sha256(f"keygen|{pseudonym}|{round}".encode()).digest()
        return b"stub.kg." + digest[:24]

    async def encrypt_scalar(self, value: float, pk: bytes) -> bytes:
        await asyncio.sleep(0)
        digest = hashlib.sha256(f"enc|scalar|{value}".encode() + pk).digest()
        return b"stub.ct." + digest[:24]

    async def encrypt_vector(self, values: list[float], pk: bytes) -> bytes:
        await asyncio.sleep(0)
        digest = hashlib.sha256(
            f"enc|vector|{','.join(map(str, values))}".encode() + pk
        ).digest()
        return b"stub.ct." + digest[:24]

    async def partial_decrypt(self, ciphertext: bytes, share: bytes) -> bytes:
        await asyncio.sleep(0)
        digest = hashlib.sha256(ciphertext + share).digest()
        return b"stub.pd." + digest[:24]


# Default provider for tests and stub smokes.
DEFAULT = StubCrypto()
