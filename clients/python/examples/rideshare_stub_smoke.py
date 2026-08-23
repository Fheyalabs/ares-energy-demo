# SPDX-License-Identifier: Apache-2.0
"""Ride-share smoke config.

The first participant is the rider; the rest are drivers (matches
rideShareTrigger in the session-service binary).

Smoke flow per participant (stub-crypto path):

    rider:
        1. send ride.request with (max_price, pickup_lat, pickup_lon)
        2. wait for any settlement frame
    drivers:
        1. send ride.keygen.share
        2. send ride.bid with (ask_price, current_lat, current_lon)
        3. wait for any settlement frame, respond with decrypt.partial
"""

from __future__ import annotations

import os
import random
from typing import Any

from ares_client import AppConfig, ARESSession
from ares_client.crypto import DEFAULT as crypto


async def rideshare_role_for(participants: list[str]) -> dict[str, str]:
    """First is the rider, the rest are drivers."""
    return {
        p: ("rider" if i == 0 else "driver")
        for i, p in enumerate(participants)
    }


async def rideshare_flow(session: ARESSession, role: str, total: int) -> dict[str, Any]:
    if role == "rider":
        max_price = random.randint(10, 50)
        await session.send("ride.request", {
            "max_price": max_price,
            "pickup_lat": 37.7749,
            "pickup_lon": -122.4194,
        })
        return {
            "pseudonym": session.pseudonym,
            "role": "rider",
            "max_price": max_price,
        }

    # Driver path.
    share = await crypto.keygen_share(session.pseudonym, round=1)
    await session.send("ride.keygen.share", {
        "round": 1,
        "share": share.hex(),
    })

    ask = random.randint(8, 60)
    bid_ct = await crypto.encrypt_vector(
        values=[ask, random.uniform(37.0, 38.0), random.uniform(-123.0, -121.0)],
        pk=b"stub-collective-pk",
    )
    await session.send("ride.bid", {
        "bid_ct": bid_ct.hex(),
        "ask_cleartext_for_debug": ask,
    })

    partial = await crypto.partial_decrypt(b"stub-winner-package", share)
    await session.send("ride.decrypt.partial", {"partial": partial.hex()})

    return {
        "pseudonym": session.pseudonym,
        "role": "driver",
        "submitted_ask": ask,
    }


CONFIG = AppConfig(
    name="rideshare",
    server_url=os.environ.get("ARES_SERVER", "http://localhost:8000"),
    auth_secret=os.environ.get("ARES_WS_SECRET", ""),
    invite_type="ride.invitation",
    participant_flow=rideshare_flow,
    role_for=rideshare_role_for,
)
