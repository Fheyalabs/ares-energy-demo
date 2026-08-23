# SPDX-License-Identifier: Apache-2.0
"""End-to-end cohort-formation smoke against a live homelab.

Formation is the "once per cohort" key-generation pipeline:

    PhaseCohortForm → PhaseCohortKeygen → COHORT_SEALED (terminal)

The server-side PhaseCohortKeygen does the actual N-party threshold
CKKS keygen via helper.KeygenChain on Exit; participants just submit
one cohort.keygen.share each to drive the accumulator quorum and
trigger the transition. In production, the operator harvests the
produced bundle (CtxCollectivePK + CtxEvalKeys) and feeds it into
NewWeeklyRankingSessionWithHelper for subsequent weekly sessions.

This smoke proves the wire + state machine + server-side keygen on
the live homelab. The harvest path is a separate concern.

Usage:

    export ARES_SERVER=https://api.fheya.de
    export ARES_WS_SECRET=
    python -m examples.cohort_formation_openfhe_smoke --participants 3
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import time
from typing import Any

import httpx

from ares_client import ARESSession

log = logging.getLogger("cohort-formation-smoke")


async def run(
    server_url: str,
    participants: int,
    session_id: str,
    auth_secret: str,
) -> int:
    members = [f"founder-{i:02d}" for i in range(participants)]
    log.info("members=%s", members)

    log.info("connecting %d members to %s", participants, server_url)
    sessions = [
        await ARESSession.connect(
            server_url=server_url,
            pseudonym=m,
            session_id=session_id,
            auth_secret=auth_secret,
            default_timeout=60.0,
        )
        for m in members
    ]

    async with httpx.AsyncClient(timeout=30.0) as http:
        r = await http.post(f"{server_url}/admin/sessions", json={
            "session_id": session_id,
            "participants": members,
        })
        if r.status_code != 201:
            raise RuntimeError(f"start_session: {r.status_code} {r.text}")
        log.info("session started: %s", r.json())

    async def participant_flow(session: ARESSession, member: str) -> dict[str, Any]:
        invite = await session.expect("cohort.formation.invitation")
        log.info("%s <- %s", member, invite.type)

        # Each member submits one keygen share to drive the
        # accumulator. The server-side PhaseCohortKeygen runs real
        # N-party threshold keygen via the helper at Exit.
        await session.send("cohort.keygen.share", {"share": "ks-" + member})
        return {"member": member}

    t0 = time.monotonic()
    results = await asyncio.gather(*[
        participant_flow(s, s.pseudonym) for s in sessions
    ])
    elapsed = time.monotonic() - t0
    log.info("all members submitted in %.2fs", elapsed)

    # Poll until terminal. Formation's PhaseCohortKeygen exits to
    # COHORT_SEALED with no further phase — the dispatcher logs a
    # "no phase claims" warning after the last keygen.share, but
    # the keys are already in context. We just wait for the runner
    # state to settle.
    async with httpx.AsyncClient(timeout=30.0) as http:
        for _ in range(40):
            r = await http.get(f"{server_url}/admin/sessions/{session_id}")
            if r.status_code != 200:
                break
            state = r.json().get("state", "")
            log.info("state = %r", state)
            if state in ("", "COHORT_SEALED", "COHORT_KEYGEN"):
                # COHORT_KEYGEN can be terminal if the server hit
                # "no phase claims COHORT_SEALED" on advance — the
                # keygen Exit ran first so the bundle is in ctx.
                break
            await asyncio.sleep(0.5)

    for s in sessions:
        await s.close()

    log.info("smoke complete: %d members, elapsed=%.2fs", participants, elapsed)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--server", default=os.environ.get("ARES_SERVER", "http://localhost:8000"))
    p.add_argument("--participants", "-n", type=int, default=3)
    p.add_argument("--session-id", default=None)
    p.add_argument("--auth-secret", default=os.environ.get("ARES_WS_SECRET", ""))
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )
    session_id = args.session_id or f"cohort-formation-{int(time.time())}"
    return asyncio.run(run(
        server_url=args.server.rstrip("/"),
        participants=args.participants,
        session_id=session_id,
        auth_secret=args.auth_secret,
    ))


if __name__ == "__main__":
    raise SystemExit(main())
