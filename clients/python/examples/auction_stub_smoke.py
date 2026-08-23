# SPDX-License-Identifier: Apache-2.0
"""Sealed-bid auction smoke config.

Smoke flow (stub-crypto path):

    1. wait for auction.invitation
    2. send auction.keygen.share with a stub keygen contribution
    3. send auction.bid with a stub-encrypted bid amount
    4. wait for any decrypt prompt from the server (or session.end)
    5. send auction.decrypt.partial with a stub partial
    6. return the bid amount this participant submitted

Replace ares_client.crypto.DEFAULT with a real OpenFHE provider for the
Phase 4 end-to-end run.
"""

from __future__ import annotations

import os
import random
from typing import Any

from ares_client import AppConfig, ARESSession
from ares_client.crypto import DEFAULT as crypto


async def auction_flow(session: ARESSession, role: str, total: int) -> dict[str, Any]:
    # Step 1: keygen share (the auction's PhaseKeygen consumes this).
    share = await crypto.keygen_share(session.pseudonym, round=1)
    await session.send("auction.keygen.share", {
        "round": 1,
        "share": share.hex(),
    })

    # Step 2: submit one encrypted scalar bid.
    bid = random.randint(10, 1000)
    bid_ct = await crypto.encrypt_scalar(bid, pk=b"stub-collective-pk")
    await session.send("auction.bid", {
        "bid_ct": bid_ct.hex(),
        "bid_cleartext_for_debug": bid,
    })

    # Step 3: respond to threshold decryption.
    partial = await crypto.partial_decrypt(
        ciphertext=b"stub-winning-bid-ct",
        share=share,
    )
    await session.send("auction.decrypt.partial", {
        "partial": partial.hex(),
    })

    return {
        "pseudonym": session.pseudonym,
        "role": role,
        "submitted_bid": bid,
    }


CONFIG = AppConfig(
    name="auction",
    server_url=os.environ.get("ARES_SERVER", "http://localhost:8000"),
    auth_secret=os.environ.get("ARES_WS_SECRET", ""),
    invite_type="auction.invitation",
    participant_flow=auction_flow,
)
