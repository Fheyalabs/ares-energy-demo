# SPDX-License-Identifier: Apache-2.0
"""End-to-end recurring-cohort weekly smoke against a live homelab.

Targets the cohort session-service running in weekly mode
(COHORT_MODE=weekly). The smoke driver acts as the cohort
administrator: it pre-generates the cohort's key bundle once,
then drives the weekly ranking session.

In a real deployment the cohort key bundle would come from a
prior cohort-formation run (or KMS); this smoke just generates
it locally to keep the test self-contained.

Flow:

    1. spawn a local OpenFHE helper subprocess
    2. run the N-party threshold keygen (the "cohort formation"
       step, normally amortized across many weekly sessions)
    3. each participant encrypts a normalized rating in [-1, 1]
    4. connect N WebSocket sessions to the weekly service
    5. POST /admin/sessions with attrs={ranking.collective_pk,
       ranking.eval_keys, ranking.secret_shares} so the weekly
       trigger's required-attr check passes and the keys flow
       into PhasePreSharedKeyLookup
    6. weekly trigger walks the session to RANKING_BIDDING; each
       participant sends ranking.rating → await RANKING_DECRYPT →
       send ranking.decrypt.partial

Usage:

    export ARES_SERVER=http://localhost:8000
    export ARES_WS_SECRET=
    export ARES_HELPER_BINARY=/path/to/openfhe-helper
    export COHORT_CRYPTO_DEPTH=10   # matches server default
    export COHORT_RING_DIM=2048
    python -m examples.cohort_openfhe_smoke --participants 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import time
from typing import Any

import httpx

from ares_client import ARESSession
from ares_client.openfhe import ContractParams, OpenFHEHelper

log = logging.getLogger("cohort-smoke")


async def run(
    server_url: str,
    helper_path: str | None,
    participants: int,
    session_id: str,
    auth_secret: str,
) -> int:
    members = [f"member-{i:02d}" for i in range(participants)]
    ratings = [random.uniform(-0.8, 0.8) for _ in range(participants)]
    log.info("members=%s ratings=%s", members, [f"{r:.3f}" for r in ratings])

    depth = int(os.environ.get("COHORT_CRYPTO_DEPTH", "10"))
    ring_dim = int(os.environ.get("COHORT_RING_DIM", "2048"))
    params = ContractParams(ring_dim=ring_dim, depth=depth, scaling_mod_size=50)
    log.info("crypto params: ring_dim=%d depth=%d", ring_dim, depth)

    helper: OpenFHEHelper | None = None
    rating_cts: dict[str, str] = {}
    shares_by_member: dict[str, Any] = {}
    decrypt_target: bytes | None = None
    joint = b""
    eval_keys_bytes = b""

    if helper_path:
        helper = OpenFHEHelper(helper_path)
        await helper.start()
        t0 = time.monotonic()
        shares, eval_keys = await helper.run_full_keygen(params, participants)
        log.info("cohort keygen complete in %.2fs", time.monotonic() - t0)
        joint = shares[-1].public_key
        eval_keys_bytes = eval_keys.eval_mult_final
        for m, r, share in zip(members, ratings, shares):
            ct = await helper.encrypt(params, joint, [r, 0.0, 0.0, 0.0])
            rating_cts[m] = ct.hex()
            shares_by_member[m] = share
            log.info("encrypted %s rating=%.3f → %d bytes", m, r, len(ct))
        # Shared partial-decrypt target so the server's PhaseDecrypt
        # has N partials against one ciphertext to fuse.
        decrypt_target = bytes.fromhex(rating_cts[members[0]])
    else:
        log.info("stub mode — no helper, sending placeholder bytes")
        for m in members:
            rating_cts[m] = "deadbeef" * 8

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

    # The weekly trigger requires CtxSecretShares to be present even
    # though it's mostly vestigial — pass a placeholder map keyed by
    # member name. The real per-participant secret shares stay
    # client-side and are used to produce ranking.decrypt.partial.
    pre_shared_attrs: dict[str, Any] = {
        "ranking.secret_shares": {m: "client-side" for m in members},
    }
    if helper:
        pre_shared_attrs["ranking.collective_pk"] = joint.hex()
        pre_shared_attrs["ranking.eval_keys"] = eval_keys_bytes.hex()
        log.info("seeding pre-shared keys (pk=%d bytes, ek=%d bytes)",
                 len(joint), len(eval_keys_bytes))
    else:
        # Stub mode still needs the keys present so the trigger's
        # required-attr check passes; supply hex zeros.
        pre_shared_attrs["ranking.collective_pk"] = "00"
        pre_shared_attrs["ranking.eval_keys"] = "00"

    async with httpx.AsyncClient(timeout=30.0) as http:
        body = {
            "session_id": session_id,
            "participants": members,
            "attrs": pre_shared_attrs,
        }
        r = await http.post(f"{server_url}/admin/sessions", json=body)
        if r.status_code != 201:
            raise RuntimeError(f"start_session: {r.status_code} {r.text}")
        log.info("session started: %s", r.json())

    async def participant_flow(session: ARESSession, member: str) -> dict[str, Any]:
        invite = await session.expect("ranking.invitation")
        log.info("%s <- %s", member, invite.type)

        # The weekly trigger already walked the session to
        # RANKING_BIDDING, so we can submit ratings immediately.
        await session.send("ranking.rating", {"rating_ct": rating_cts[member]})
        await session.await_phase("RANKING_DECRYPT", timeout=30.0)

        if helper is not None and decrypt_target is not None:
            share = shares_by_member[member]
            partial = await helper.partial_decrypt(
                params, decrypt_target, share.secret_key_share, share.lead,
            )
            await session.send("ranking.decrypt.partial", {"partial_ct": partial.hex()})
        else:
            await session.send("ranking.decrypt.partial", {"partial": "pd-" + member})
        return {"member": member, "submitted_rating": float(ratings[members.index(member)])}

    t0 = time.monotonic()
    results = await asyncio.gather(*[
        participant_flow(s, s.pseudonym) for s in sessions
    ])
    elapsed = time.monotonic() - t0
    log.info("all members submitted in %.2fs", elapsed)

    async with httpx.AsyncClient(timeout=10.0) as http:
        for _ in range(20):
            r = await http.get(f"{server_url}/admin/sessions/{session_id}")
            if r.status_code != 200:
                break
            state = r.json().get("state", "")
            log.info("state = %r", state)
            if state == "" or state == "RANKING_SETTLED":
                break
            await asyncio.sleep(0.5)

    for s in sessions:
        await s.close()
    if helper:
        await helper.close()

    log.info("smoke complete: %d members, elapsed=%.2fs", participants, elapsed)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--server", default=os.environ.get("ARES_SERVER", "http://localhost:8000"))
    p.add_argument("--helper", default=os.environ.get("ARES_HELPER_BINARY"))
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
    session_id = args.session_id or f"cohort-{int(time.time())}"
    return asyncio.run(run(
        server_url=args.server.rstrip("/"),
        helper_path=args.helper,
        participants=args.participants,
        session_id=session_id,
        auth_secret=args.auth_secret,
    ))


if __name__ == "__main__":
    raise SystemExit(main())
