# SPDX-License-Identifier: Apache-2.0
"""End-to-end auction smoke against a live homelab session-service.

Drives N participants through the full auction protocol:

    1. spawn a local OpenFHE helper subprocess
    2. run the N-party threshold keygen via the helper
    3. encrypt each participant's bid as a single normalized scalar
    4. connect N WebSocket sessions to the session-service
    5. POST /admin/sessions to start the auction
    6. each participant sends auction.keygen.share + auction.bid +
       auction.decrypt.partial in sequence
    7. drive until the session reaches AUCTION_SETTLED (or terminal)

The full crypto correctness of the argmax is already proven by
tests/test_openfhe.py::test_argmax_picks_winner — that test drives the
helper IPC end-to-end against real OpenFHE. This driver is the
transport-correctness smoke: it confirms the live session-service
accepts real CKKS ciphertexts, advances the state machine, and emits
the expected per-phase messages.

Usage:

    export ARES_SERVER=http://localhost:8000     # or https://api.fheya.de
    export ARES_WS_SECRET=                       # empty for dev-bypass
    export ARES_HELPER_BINARY=/path/to/openfhe-helper
    python -m examples.auction_openfhe_smoke --participants 6

If you only want a stub (no real CKKS) smoke, drop ARES_HELPER_BINARY
and the driver falls back to placeholder ciphertexts — wire-only test.
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
from ares_client.openfhe import (
    ContractParams,
    OpenFHEHelper,
)

log = logging.getLogger("auction-smoke")


async def run(
    server_url: str,
    helper_path: str | None,
    participants: int,
    session_id: str,
    auth_secret: str,
) -> int:
    bidders = [f"bidder-{i:02d}" for i in range(participants)]
    scores = [random.uniform(-0.8, 0.8) for _ in range(participants)]
    log.info("bidders=%s scores=%s", bidders, [f"{s:.3f}" for s in scores])

    # 1. Helper + crypto setup (or stub if no helper).
    helper: OpenFHEHelper | None = None
    bid_cts: dict[str, str] = {}  # hex-encoded ciphertexts, per bidder
    shares_by_bidder: dict[str, Any] = {}  # KeyShare per bidder (helper mode)
    decrypt_target: bytes | None = None  # ciphertext everyone partial-decrypts

    # CKKS contract MUST match the server's. The server reads these
    # from AUCTION_CRYPTO_DEPTH / AUCTION_RING_DIM env vars; the smoke
    # honors the same names so a single export configures both sides.
    # Defaults match the auction binary defaults (depth=12, ring_dim=2048)
    # — keeps keys at ~500 KiB so Mac OOM during parallel keygen +
    # encrypt + argmax is avoided.
    depth = int(os.environ.get("AUCTION_CRYPTO_DEPTH", "12"))
    ring_dim = int(os.environ.get("AUCTION_RING_DIM", "2048"))
    params = ContractParams(ring_dim=ring_dim, depth=depth, scaling_mod_size=50)
    log.info("crypto params: ring_dim=%d depth=%d", ring_dim, depth)

    if helper_path:
        helper = OpenFHEHelper(helper_path)
        await helper.start()
        t0 = time.monotonic()
        shares, eval_keys = await helper.run_full_keygen(params, participants)
        log.info("keygen complete in %.2fs", time.monotonic() - t0)
        joint = shares[-1].public_key
        for b, s, share in zip(bidders, scores, shares):
            ct = await helper.encrypt(params, joint, [s, 0.0, 0.0, 0.0])
            bid_cts[b] = ct.hex()
            shares_by_bidder[b] = share
            log.info("encrypted %s score=%.3f → %d bytes", b, s, len(ct))
        # All bidders partial-decrypt the same ciphertext so the server's
        # PhaseDecrypt has N partials against one target to fuse. We pick
        # the first bidder's bid_ct — the recovered scalar isn't the
        # auction outcome (mask·bid fusion isn't wired into this phase
        # yet), but it drives the session to AUCTION_SETTLED with real
        # threshold partials instead of placeholder bytes.
        decrypt_target = bytes.fromhex(bid_cts[bidders[0]])
    else:
        log.info("stub mode — no helper, sending placeholder bytes")
        for b in bidders:
            bid_cts[b] = "deadbeef" * 8

    # 2. Connect WS sessions.
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

    # 3. POST /admin/sessions. When in helper mode we pass the
    # pre-generated key bundle as hex-encoded attrs so the server's
    # PhaseKeygen detects pre-shared keys and skips its own keygen.
    # Without this the server would generate a DIFFERENT bundle and
    # the bids encrypted under our local bundle wouldn't decrypt
    # against the server's eval keys.
    pre_shared_attrs: dict[str, Any] = {}
    if helper:
        pre_shared_attrs["auction.collective_pk"] = joint.hex()
        pre_shared_attrs["auction.eval_keys"] = eval_keys.eval_mult_final.hex()
        log.info(
            "seeding pre-shared keys (pk=%d bytes, ek=%d bytes)",
            len(joint), len(eval_keys.eval_mult_final),
        )

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

    # 4. Each participant submits in sequence: keygen.share, bid, decrypt.partial.
    async def participant_flow(session: ARESSession, bidder: str) -> dict[str, Any]:
        invite = await session.expect("auction.invitation")
        log.info("%s <- %s", bidder, invite.type)

        await session.send("auction.keygen.share", {
            "share": "ks-" + bidder,
        })
        await asyncio.sleep(0)

        # Wait for all N participants' keygen shares to accumulate
        # and the session to enter BIDDING before sending bids.
        await session.await_phase("AUCTION_BIDDING", timeout=30.0)
        await session.send("auction.bid", {"bid_ct": bid_cts[bidder]})
        await asyncio.sleep(0)

        # Wait for scoring to complete and the session to enter
        # DECRYPTING before sending partials.
        await session.await_phase("AUCTION_DECRYPTING", timeout=30.0)
        if helper is not None and decrypt_target is not None:
            share = shares_by_bidder[bidder]
            partial = await helper.partial_decrypt(
                params, decrypt_target, share.secret_key_share, share.lead,
            )
            await session.send("auction.decrypt.partial", {"partial_ct": partial.hex()})
        else:
            await session.send("auction.decrypt.partial", {"partial": "pd-" + bidder})
        return {"bidder": bidder, "submitted_score": float(scores[bidders.index(bidder)])}

    t0 = time.monotonic()
    results = await asyncio.gather(*[
        participant_flow(s, s.pseudonym) for s in sessions
    ])
    elapsed = time.monotonic() - t0
    log.info("all participants submitted in %.2fs", elapsed)

    # 5. Poll the session state until terminal.
    async with httpx.AsyncClient(timeout=10.0) as http:
        for _ in range(20):
            r = await http.get(f"{server_url}/admin/sessions/{session_id}")
            if r.status_code != 200:
                log.warning("get session: %s", r.text)
                break
            state = r.json().get("state", "")
            log.info("state = %r", state)
            if state == "" or state == "AUCTION_SETTLED":
                break
            await asyncio.sleep(0.5)

    # 6. Cleanup.
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
    session_id = args.session_id or f"auction-{int(time.time())}"
    return asyncio.run(run(
        server_url=args.server.rstrip("/"),
        helper_path=args.helper,
        participants=args.participants,
        session_id=session_id,
        auth_secret=args.auth_secret,
    ))


if __name__ == "__main__":
    raise SystemExit(main())
