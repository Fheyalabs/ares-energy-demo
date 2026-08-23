# SPDX-License-Identifier: Apache-2.0
"""Weekly cohort-ranking smoke config (run with COHORT_MODE=weekly).

Required environment variables:

    COHORT_COLLECTIVE_PK   hex/base64 from the formation phase output
    COHORT_SECRET_SHARES   JSON {"m-1":"...","m-2":"..."} mapping
    COHORT_EVAL_KEYS       hex/base64 from the formation phase output

The smoke driver POSTs these into admin_attrs on session start; the
weekly trigger seeds them into the SessionContext before
PhasePreSharedKeyLookup runs.
"""

from __future__ import annotations

import json
import os
import random
from typing import Any

from ares_client import AppConfig, ARESSession
from ares_client.crypto import DEFAULT as crypto


def _load_attrs() -> dict[str, Any]:
    pk = os.environ.get("COHORT_COLLECTIVE_PK", "stub-collective-pk")
    shares_raw = os.environ.get("COHORT_SECRET_SHARES", "")
    eval_keys = os.environ.get("COHORT_EVAL_KEYS", "stub-eval-keys")
    try:
        shares = json.loads(shares_raw) if shares_raw else {}
    except json.JSONDecodeError:
        shares = {}
    return {
        "ranking.collective_pk": pk,
        "ranking.secret_shares": shares,
        "ranking.eval_keys": eval_keys,
    }


async def weekly_flow(session: ARESSession, role: str, total: int) -> dict[str, Any]:
    rating = random.randint(0, 100)
    ct = await crypto.encrypt_scalar(rating, pk=b"stub-collective-pk")
    await session.send("ranking.rating", {
        "rating_ct": ct.hex(),
        "rating_cleartext_for_debug": rating,
    })
    share = await crypto.keygen_share(session.pseudonym, round=1)
    partial = await crypto.partial_decrypt(b"stub-winner-rating", share)
    await session.send("ranking.decrypt.partial", {"partial": partial.hex()})
    return {
        "pseudonym": session.pseudonym,
        "role": role,
        "submitted_rating": rating,
    }


CONFIG = AppConfig(
    name="cohort-weekly",
    server_url=os.environ.get("ARES_SERVER", "http://localhost:8000"),
    auth_secret=os.environ.get("ARES_WS_SECRET", ""),
    invite_type="ranking.invitation",
    participant_flow=weekly_flow,
    admin_attrs=_load_attrs(),
)
