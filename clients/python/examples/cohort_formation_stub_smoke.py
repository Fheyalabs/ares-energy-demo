# SPDX-License-Identifier: Apache-2.0
"""Cohort-formation smoke config (run with COHORT_MODE=formation).

This drives the one-time cohort-key-bundle generation. The smoke just
exchanges keygen shares; the actual key bundle is produced in the
server-side phase Exit hook. After this smoke completes, capture the
bundle (printed by the smoke driver) and feed it into
cohort_weekly_stub_smoke.py for the weekly path.
"""

from __future__ import annotations

import os
from typing import Any

from ares_client import AppConfig, ARESSession
from ares_client.crypto import DEFAULT as crypto


async def cohort_formation_flow(session: ARESSession, role: str, total: int) -> dict[str, Any]:
    share = await crypto.keygen_share(session.pseudonym, round=1)
    await session.send("cohort.keygen.share", {
        "round": 1,
        "share": share.hex(),
    })
    return {
        "pseudonym": session.pseudonym,
        "role": role,
        "share_prefix": share[:8].hex(),
    }


CONFIG = AppConfig(
    name="cohort-formation",
    server_url=os.environ.get("ARES_SERVER", "http://localhost:8000"),
    auth_secret=os.environ.get("ARES_WS_SECRET", ""),
    invite_type="cohort.formation.invitation",
    participant_flow=cohort_formation_flow,
)
