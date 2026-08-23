# SPDX-License-Identifier: Apache-2.0
"""Per-participant ARES session.

:class:`ARESSession` owns one WebSocket connection plus the inbound
message queue. Methods are async and named for the smoke-test idiom:

    msg = await session.expect("auction.invitation")
    await session.send("auction.keygen.share", {"round": 1, "share": "..."})
    await session.close()

The receive pump runs in the background; messages arrive in an
``asyncio.Queue`` and :meth:`expect` / :meth:`receive_any` drain it.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import websockets
from websockets.asyncio.client import ClientConnection

from .config import ARESClientError

log = logging.getLogger(__name__)


@dataclass
class WSMessage:
    """One inbound WebSocket frame."""

    type: str
    session_id: str = ""
    seq: int = 0
    payload: Any = None
    timestamp: str = ""
    version: str = ""
    lineage: dict | None = None
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict) -> "WSMessage":
        return cls(
            type=data.get("type", ""),
            session_id=data.get("session_id", ""),
            seq=data.get("seq", 0),
            payload=data.get("payload"),
            timestamp=data.get("timestamp", ""),
            version=data.get("version", ""),
            lineage=data.get("lineage"),
            raw=data,
        )


def _derive_ws_token(secret: str, pseudonym: str) -> str:
    """HMAC-SHA256(secret, pseudonym) hex — matches transport.AuthMiddleware."""
    mac = hmac.new(secret.encode("utf-8"), pseudonym.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def _ws_url(server_url: str, pseudonym: str, token: str) -> str:
    parsed = urlparse(server_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    query = urlencode({"pseudonym": pseudonym, "auth": token})
    return urlunparse((scheme, parsed.netloc, "/v2/ws", "", query, ""))


class ARESSession:
    """One participant's view of a session.

    Construct via :meth:`connect`; the helper does the WS handshake and
    starts the receive pump.
    """

    def __init__(
        self,
        pseudonym: str,
        ws: ClientConnection,
        session_id: str,
        default_timeout: float = 30.0,
    ) -> None:
        self.pseudonym = pseudonym
        self.session_id = session_id
        self._ws = ws
        self._inbox: asyncio.Queue[WSMessage] = asyncio.Queue()
        self._default_timeout = default_timeout
        self._closed = False
        self._server_url = ""  # set by connect()
        self._recv_task = asyncio.create_task(self._recv_loop(), name=f"recv-{pseudonym}")

    # Construction ---------------------------------------------------

    @classmethod
    async def connect(
        cls,
        server_url: str,
        pseudonym: str,
        session_id: str,
        auth_secret: str = "",
        default_timeout: float = 30.0,
        ssl_context: "ssl.SSLContext | bool | None" = None,
    ) -> "ARESSession":
        """Open a WS connection, authenticated for ``pseudonym``.

        TLS / certificate verification:

        * If ``server_url`` starts with ``https://`` or ``wss://``, the
          underlying ``websockets.connect`` call uses TLS with the
          system's default trust store and verifies the server
          certificate against the URL hostname. No additional
          configuration is needed for public CAs (Let's Encrypt,
          public CA-signed certs).

        * Pass ``ssl_context=ssl.create_default_context(cafile="...")``
          to supply a custom CA bundle (e.g. for a homelab with a
          private CA). The argument is forwarded as ``ssl=`` to
          ``websockets.connect``.

        * Pass ``ssl_context=False`` to **disable** verification.
          Useful for local development against self-signed certs;
          never use in production.

        * Plain ``http://`` / ``ws://`` URLs skip TLS entirely. The
          framework warns when ``auth_secret`` is set against a plain
          URL (token leaks over plaintext); leave ``auth_secret=""``
          for dev-bypass mode in that case.
        """
        token = _derive_ws_token(auth_secret, pseudonym) if auth_secret else ""
        url = _ws_url(server_url, pseudonym, token)
        log.debug("[%s] dialing %s", pseudonym, url)
        kwargs: dict[str, "Any"] = {
            "ping_interval": 20,
            "ping_timeout": 30,
            "close_timeout": 5,
            "max_size": 64 * 1024 * 1024,  # 64 MiB — large CKKS payloads
        }
        if ssl_context is not None:
            kwargs["ssl"] = ssl_context
        try:
            ws = await websockets.connect(url, **kwargs)
        except Exception as e:
            raise ARESClientError(f"dial WS for {pseudonym!r}: {e}") from e
        session = cls(pseudonym, ws, session_id, default_timeout=default_timeout)
        session._server_url = server_url.rstrip("/")
        return session

    # Sending --------------------------------------------------------

    async def send(
        self,
        msg_type: str,
        payload: Any = None,
        seq: int = 0,
        *,
        lineage: dict | None = None,
    ) -> None:
        """Send a WS frame. Pass lineage= to emit a v2 frame."""
        if self._closed:
            raise ARESClientError(f"{self.pseudonym}: session closed")
        frame: dict[str, Any] = {
            "type": msg_type,
            "session_id": self.session_id,
            "seq": seq,
        }
        if payload is not None:
            frame["payload"] = payload
        if lineage is not None:
            frame["version"] = "2"
            frame["lineage"] = lineage
        body = json.dumps(frame)
        log.debug("[%s] → %s (%d bytes)", self.pseudonym, msg_type, len(body))
        await self._ws.send(body)

    # Receiving ------------------------------------------------------

    async def expect(self, msg_type: str, timeout: float | None = None) -> WSMessage:
        """Wait for the next frame of ``msg_type``. Other frames are dropped.

        Raises :class:`ARESClientError` if the timeout elapses.
        """
        deadline = time.monotonic() + (timeout if timeout is not None else self._default_timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ARESClientError(
                    f"{self.pseudonym}: timeout waiting for {msg_type!r}"
                )
            try:
                msg = await asyncio.wait_for(self._inbox.get(), timeout=remaining)
            except asyncio.TimeoutError:
                raise ARESClientError(
                    f"{self.pseudonym}: timeout waiting for {msg_type!r}"
                ) from None
            if msg.type == msg_type:
                return msg
            log.debug("[%s] dropped %s (waiting for %s)", self.pseudonym, msg.type, msg_type)

    async def receive_any(self, timeout: float | None = None) -> WSMessage:
        """Return the next frame regardless of type."""
        t = timeout if timeout is not None else self._default_timeout
        try:
            return await asyncio.wait_for(self._inbox.get(), timeout=t)
        except asyncio.TimeoutError:
            raise ARESClientError(
                f"{self.pseudonym}: timeout waiting for any frame"
            ) from None

    async def await_phase(
        self,
        target_state: str,
        timeout: float = 30.0,
    ) -> None:
        """Poll the admin endpoint until the session reaches *target_state*.

        Raises :class:`ARESClientError` if the deadline elapses.
        """
        import httpx

        deadline = time.monotonic() + timeout
        url = f"{self._server_url}/admin/sessions/{self.session_id}"
        async with httpx.AsyncClient(timeout=5.0) as http:
            while time.monotonic() < deadline:
                try:
                    r = await http.get(url)
                except Exception:
                    await asyncio.sleep(0.1)
                    continue
                if r.status_code != 200:
                    await asyncio.sleep(0.1)
                    continue
                data = r.json()
                state = data.get("state", "")
                if state == target_state:
                    return
                await asyncio.sleep(0.1)
        raise ARESClientError(
            f"{self.pseudonym}: timeout waiting for state {target_state!r}"
        )

    # Lifecycle ------------------------------------------------------

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._recv_task.cancel()
        try:
            await self._ws.close()
        except Exception:  # noqa: BLE001 — close on a flaky socket is best-effort
            pass

    async def __aenter__(self) -> "ARESSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # Internals ------------------------------------------------------

    async def _recv_loop(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    log.warning("[%s] non-JSON frame, dropped", self.pseudonym)
                    continue
                msg = WSMessage.from_json(data)
                await self._inbox.put(msg)
                log.debug("[%s] ← %s", self.pseudonym, msg.type)
        except asyncio.CancelledError:
            pass
        except websockets.exceptions.ConnectionClosed as e:
            log.debug("[%s] WS closed: %s", self.pseudonym, e)
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] recv loop error: %s", self.pseudonym, e)
