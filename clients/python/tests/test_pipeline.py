# SPDX-License-Identifier: Apache-2.0
"""Tests for the pipeline orchestrator's AdminClient."""

from __future__ import annotations

import pytest
from aiohttp import web

from ares_client.pipeline import AdminClient


@pytest.fixture
async def fake_server(unused_tcp_port):
    """Spin up a minimal admin-shaped HTTP server."""
    started_sessions: list[dict] = []

    async def health(_req):
        return web.json_response({"status": "ok", "service": "fake"})

    async def start(req):
        body = await req.json()
        started_sessions.append(body)
        return web.json_response(
            {"session_id": body["session_id"], "state": "INIT"},
            status=201,
        )

    async def get_one(req):
        sid = req.match_info["id"]
        for s in started_sessions:
            if s["session_id"] == sid:
                return web.json_response({"session_id": sid, "state": "INIT"})
        return web.Response(status=404)

    app = web.Application()
    app.router.add_get("/admin/health", health)
    app.router.add_post("/admin/sessions", start)
    app.router.add_get("/admin/sessions/{id}", get_one)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", unused_tcp_port)
    await site.start()
    try:
        yield unused_tcp_port, started_sessions
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_admin_health(fake_server):
    port, _ = fake_server
    admin = AdminClient(f"http://127.0.0.1:{port}")
    h = await admin.health()
    assert h["status"] == "ok"


@pytest.mark.asyncio
async def test_admin_start_session(fake_server):
    port, started = fake_server
    admin = AdminClient(f"http://127.0.0.1:{port}")
    r = await admin.start_session("s-1", ["a", "b", "c"], attrs={"k": "v"})
    assert r["session_id"] == "s-1"
    assert started[0]["participants"] == ["a", "b", "c"]
    assert started[0]["attrs"] == {"k": "v"}


@pytest.mark.asyncio
async def test_admin_get_session(fake_server):
    port, _ = fake_server
    admin = AdminClient(f"http://127.0.0.1:{port}")
    await admin.start_session("s-2", ["x"])
    g = await admin.get_session("s-2")
    assert g["session_id"] == "s-2"
