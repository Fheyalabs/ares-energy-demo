# SPDX-License-Identifier: Apache-2.0
"""End-to-end ride-share smoke against a live homelab session-service.

Mirrors auction_openfhe_smoke (commit ce42ce8) for the ride-share app:

    1. spawn a local OpenFHE helper subprocess
    2. run the N-party threshold keygen via the helper
    3. each driver encrypts a composite score
       (α·price_fitness + β·proximity, computed cleartext) as a single
       scalar
    4. connect N WebSocket sessions to the session-service
    5. POST /admin/sessions with attrs={ride.collective_pk:hex,
       ride.eval_keys:hex} — the PreSharedKeygen path
    6. each participant: send ride.keygen.share → await RIDE_SUBMIT →
       send ride.bid → await RIDE_DECRYPT → send ride.decrypt.partial

v1 simplification: every participant submits ride.bid (rider role
folded into the same ciphertext stream). A role-aware variant where
participants[0] sends ride.request and others send ride.bid is a
follow-up; this smoke proves the wire/state-machine + real CKKS
argmax. Composite-score-from-real-FHE is also future work.

Usage:

    export ARES_SERVER=http://localhost:8000
    export ARES_WS_SECRET=
    export ARES_HELPER_BINARY=/path/to/openfhe-helper
    export RIDESHARE_CRYPTO_DEPTH=12   # matches server default
    export RIDESHARE_RING_DIM=2048
    python -m examples.rideshare_openfhe_smoke --participants 3
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import time
from typing import Any

import httpx

from ares_client import ARESSession
from ares_client.openfhe import ContractParams, OpenFHEHelper

log = logging.getLogger("rideshare-smoke")


async def run(
    server_url: str,
    helper_path: str | None,
    participants: int,
    session_id: str,
    auth_secret: str,
) -> int:
    bidders = [f"rider-shared-{i:02d}" for i in range(participants)]
    # Composite score per participant, normalized to [-1, 1] so the
    # sharpening polynomial domain is honored.
    scores = [random.uniform(-0.8, 0.8) for _ in range(participants)]
    log.info("bidders=%s scores=%s", bidders, [f"{s:.3f}" for s in scores])

    depth = int(os.environ.get("RIDESHARE_CRYPTO_DEPTH", "12"))
    ring_dim = int(os.environ.get("RIDESHARE_RING_DIM", "2048"))
    params = ContractParams(ring_dim=ring_dim, depth=depth, scaling_mod_size=50)
    log.info("crypto params: ring_dim=%d depth=%d", ring_dim, depth)

    helper: OpenFHEHelper | None = None
    bid_cts: dict[str, str] = {}
    shares_by_bidder: dict[str, Any] = {}
    decrypt_target: bytes | None = None
    joint = b""
    eval_keys_bytes = b""

    if helper_path:
        helper = OpenFHEHelper(helper_path)
        await helper.start()
        t0 = time.monotonic()
        shares, eval_keys = await helper.run_full_keygen(params, participants)
        log.info("keygen complete in %.2fs", time.monotonic() - t0)
        joint = shares[-1].public_key
        eval_keys_bytes = eval_keys.eval_mult_final
        for b, s, share in zip(bidders, scores, shares):
            ct = await helper.encrypt(params, joint, [s, 0.0, 0.0, 0.0])
            bid_cts[b] = ct.hex()
            shares_by_bidder[b] = share
            log.info("encrypted %s score=%.3f → %d bytes", b, s, len(ct))
        # Shared partial-decrypt target so the server's PhaseDecrypt
        # has N partials against one ciphertext to fuse.
        decrypt_target = bytes.fromhex(bid_cts[bidders[0]])
    else:
        log.info("stub mode — no helper, sending placeholder bytes")
        for b in bidders:
            bid_cts[b] = "deadbeef" * 8

    log.info("connecting %d participants to %s", participants, server_url)
    sessions = [
        await ARESSession.connect(
            server_url=server_url,
            pseudonym=b,
            session_id=session_id,
            auth_secret=auth_secret,
            default_timeout=60.0,
        )
        for b in bidders
    ]

    pre_shared_attrs: dict[str, Any] = {}
    if helper:
        pre_shared_attrs["ride.collective_pk"] = joint.hex()
        pre_shared_attrs["ride.eval_keys"] = eval_keys_bytes.hex()
        log.info("seeding pre-shared keys (pk=%d bytes, ek=%d bytes)",
                 len(joint), len(eval_keys_bytes))

    async with httpx.AsyncClient(timeout=30.0) as http:
        body: dict[str, Any] = {
            "session_id": session_id,
            "participants": bidders,
        }
        if pre_shared_attrs:
            body["attrs"] = pre_shared_attrs
        r = await http.post(f"{server_url}/admin/sessions", json=body)
        if r.status_code != 201:
            raise RuntimeError(f"start_session: {r.status_code} {r.text}")
        log.info("session started: %s", r.json())

    async def participant_flow(session: ARESSession, bidder: str) -> dict[str, Any]:
        invite = await session.expect("ride.invitation")
        log.info("%s <- %s", bidder, invite.type)

        await session.send("ride.keygen.share", {"share": "ks-" + bidder})
        await session.await_phase("RIDE_SUBMIT", timeout=30.0)

        await session.send("ride.bid", {"bid_ct": bid_cts[bidder]})
        await session.await_phase("RIDE_DECRYPT", timeout=30.0)

        if helper is not None and decrypt_target is not None:
            share = shares_by_bidder[bidder]
            partial = await helper.partial_decrypt(
                params, decrypt_target, share.secret_key_share, share.lead,
            )
            await session.send("ride.decrypt.partial", {"partial_ct": partial.hex()})
        else:
            await session.send("ride.decrypt.partial", {"partial": "pd-" + bidder})
        return {"bidder": bidder, "submitted_score": float(scores[bidders.index(bidder)])}

    t0 = time.monotonic()
    results = await asyncio.gather(*[
        participant_flow(s, s.pseudonym) for s in sessions
    ])
    elapsed = time.monotonic() - t0
    log.info("all participants submitted in %.2fs", elapsed)

    async with httpx.AsyncClient(timeout=10.0) as http:
        for _ in range(20):
            r = await http.get(f"{server_url}/admin/sessions/{session_id}")
            if r.status_code != 200:
                break
            state = r.json().get("state", "")
            log.info("state = %r", state)
            if state == "" or state == "RIDE_SETTLE":
                break
            await asyncio.sleep(0.5)

    for s in sessions:
        await s.close()
    if helper:
        await helper.close()

    log.info("smoke complete: %d participants, elapsed=%.2fs", participants, elapsed)
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
    session_id = args.session_id or f"ride-{int(time.time())}"
    return asyncio.run(run(
        server_url=args.server.rstrip("/"),
        helper_path=args.helper,
        participants=args.participants,
        session_id=session_id,
        auth_secret=args.auth_secret,
    ))


if __name__ == "__main__":
    raise SystemExit(main())
