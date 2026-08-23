# SPDX-License-Identifier: Apache-2.0
"""Multi-participant smoke orchestration.

:func:`run_smoke` is the high-level entry point. It:

1. Connects N participants to the server via :class:`ARESSession`.
2. POSTs ``/admin/sessions`` to start the server-side session.
3. Awaits each participant's ``invite_type`` broadcast.
4. Invokes :attr:`AppConfig.participant_flow` for each participant in
   parallel and gathers their results.
5. Cleans up WebSockets and reports.

The result is a list of whatever the participant flow returns — usually
a dict capturing the per-participant outcome (received winner, decrypted
result, settlement transcript).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from .config import AppConfig, ARESClientError, default_role_for
from .session import ARESSession

log = logging.getLogger(__name__)


class AdminClient:
    """Thin wrapper around the session-service admin HTTP API."""

    def __init__(self, server_url: str, timeout: float = 10.0) -> None:
        self.server_url = server_url.rstrip("/")
        self._timeout = timeout

    async def health(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.get(f"{self.server_url}/admin/health")
            r.raise_for_status()
            return r.json()

    async def start_session(
        self,
        session_id: str,
        participants: list[str],
        attrs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "session_id": session_id,
            "participants": participants,
        }
        if attrs:
            body["attrs"] = attrs
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(f"{self.server_url}/admin/sessions", json=body)
            if r.status_code != 201:
                raise ARESClientError(
                    f"start_session: HTTP {r.status_code}: {r.text}"
                )
            return r.json()

    async def get_session(self, session_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.get(f"{self.server_url}/admin/sessions/{session_id}")
            r.raise_for_status()
            return r.json()


async def _wait_for_health(admin: AdminClient, timeout: float = 10.0) -> None:
    """Poll /admin/health until it responds 200 or timeout."""
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            await admin.health()
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            await asyncio.sleep(0.2)
    raise ARESClientError(f"server health never came up: {last_err}")


def _participant_names(prefix: str, n: int) -> list[str]:
    return [f"{prefix}-{i+1:02d}" for i in range(n)]


async def run_smoke(
    config: AppConfig,
    n_participants: int,
    session_id: str,
    participant_prefix: str = "p",
    wait_for_server: bool = True,
) -> list[Any]:
    """Drive an end-to-end smoke run against the configured server.

    Returns the list of participant flow return values, in participant
    order.
    """
    if n_participants < 1:
        raise ARESClientError("n_participants must be >= 1")

    started = time.monotonic()
    admin = AdminClient(config.server_url)

    if wait_for_server:
        await _wait_for_health(admin)

    participants = _participant_names(participant_prefix, n_participants)
    role_for = config.role_for or default_role_for
    roles = await role_for(participants)

    log.info("[%s] connecting %d participants to %s", config.name, n_participants, config.server_url)
    sessions: list[ARESSession] = []
    try:
        # Connect serially so any failure stops immediately with a
        # clear participant identity in the error.
        for p in participants:
            s = await ARESSession.connect(
                server_url=config.server_url,
                pseudonym=p,
                session_id=session_id,
                auth_secret=config.auth_secret,
                default_timeout=config.default_timeout,
            )
            sessions.append(s)

        # Start the server-side session.
        log.info("[%s] POST /admin/sessions session_id=%s", config.name, session_id)
        await admin.start_session(
            session_id,
            participants,
            attrs=dict(config.admin_attrs),
        )

        # Each participant waits for the invitation, then runs its flow.
        async def participant_main(s: ARESSession) -> Any:
            invite = await s.expect(config.invite_type, timeout=config.default_timeout)
            log.info("[%s/%s] invitation received", config.name, s.pseudonym)
            return await config.participant_flow(s, roles[s.pseudonym], n_participants)

        results = await asyncio.gather(
            *[participant_main(s) for s in sessions],
            return_exceptions=False,
        )
    finally:
        await asyncio.gather(*[s.close() for s in sessions], return_exceptions=True)

    elapsed = time.monotonic() - started
    log.info("[%s] smoke complete in %.2fs", config.name, elapsed)
    return results
