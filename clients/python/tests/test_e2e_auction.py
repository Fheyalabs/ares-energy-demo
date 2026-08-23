# SPDX-License-Identifier: Apache-2.0
"""End-to-end smoke against a live auction session-service.

The test starts the Go auction-service as a subprocess on a random
port, runs the auction smoke flow with N=3 stub-crypto participants,
and verifies each participant's flow completes and returns a result
shape that matches what auction_flow promises.

Skipped if ``go`` is not on PATH or the test would need >10s timeout.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time

import pytest

from ares_client import AppConfig, run_smoke
from examples.auction_stub_smoke import auction_flow


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _repo_root() -> str:
    # tests/ → clients/python/ → ARES-core/
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", ".."))


@pytest.fixture
def auction_service():
    if shutil.which("go") is None:
        pytest.skip("go not on PATH")
    port = _free_port()
    env = os.environ.copy()
    env["SESSION_PORT"] = str(port)
    env["ARES_WS_SECRET"] = ""  # dev bypass
    proc = subprocess.Popen(
        ["go", "run", "./examples/sealed_bid_auction/cmd/session-service"],
        cwd=_repo_root(),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Wait up to 20s for the server to come up.
    import urllib.request
    deadline = time.monotonic() + 20.0
    ready = False
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/admin/health", timeout=0.5)
            ready = True
            break
        except Exception:
            time.sleep(0.2)
    if not ready:
        proc.terminate()
        out, _ = proc.communicate(timeout=2)
        pytest.fail(f"auction-service did not come up:\n{out.decode(errors='replace')}")
    yield port
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.mark.asyncio
async def test_auction_smoke_end_to_end(auction_service):
    port = auction_service
    cfg = AppConfig(
        name="auction",
        server_url=f"http://127.0.0.1:{port}",
        invite_type="auction.invitation",
        participant_flow=auction_flow,
        default_timeout=10.0,
    )
    results = await run_smoke(cfg, n_participants=3, session_id="auc-test-001")
    assert len(results) == 3
    for r in results:
        assert r["pseudonym"].startswith("p-")
        assert r["role"] == "peer"
        assert 10 <= r["submitted_bid"] <= 1000
