# SPDX-License-Identifier: Apache-2.0
"""Tests for the stub crypto provider."""

from __future__ import annotations

import pytest

from ares_client.crypto import StubCrypto


@pytest.mark.asyncio
async def test_keygen_share_is_deterministic():
    c = StubCrypto()
    a = await c.keygen_share("p-1", round=1)
    b = await c.keygen_share("p-1", round=1)
    assert a == b


@pytest.mark.asyncio
async def test_keygen_share_differs_per_pseudonym():
    c = StubCrypto()
    a = await c.keygen_share("p-1", round=1)
    b = await c.keygen_share("p-2", round=1)
    assert a != b


@pytest.mark.asyncio
async def test_encrypt_scalar_returns_bytes():
    c = StubCrypto()
    ct = await c.encrypt_scalar(42, pk=b"pk")
    assert isinstance(ct, bytes)
    assert ct.startswith(b"stub.ct.")


@pytest.mark.asyncio
async def test_partial_decrypt_derives_from_inputs():
    c = StubCrypto()
    p1 = await c.partial_decrypt(b"ct-A", b"share-1")
    p2 = await c.partial_decrypt(b"ct-A", b"share-2")
    assert p1 != p2
