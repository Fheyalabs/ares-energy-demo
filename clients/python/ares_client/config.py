# SPDX-License-Identifier: Apache-2.0
"""Typed configuration for ARES client smoke runs.

An :class:`AppConfig` describes everything :func:`run_smoke` needs to
drive an end-to-end test of one application against a live
session-service:

    server_url
        Where the session-service listens (e.g. ``http://localhost:8000``).
    auth_secret
        The HMAC key shared with the session-service. Empty string means
        dev-bypass — the session-service must have ``AllowDevBypass``.
    invite_type
        WS message type the server broadcasts when a session starts.
        The client waits for this before driving each participant.
    participant_flow
        Async function (session, role, total_participants) -> Any. One
        invocation per participant; receives an :class:`ARESSession`
        already connected and authenticated.
    role_for
        Optional async function (participants_list) -> dict[name -> role].
        For apps like ride-share where role assignment matters. Defaults
        to assigning all participants role="peer".
    admin_attrs
        Optional dict merged into the admin POST body's "attrs" field.
        For apps that need to seed extra context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping

# Type aliases for participant_flow / role_for so editors and mypy can
# guide users to the right shape.

ParticipantFlow = Callable[["AnyARESSession", str, int], Awaitable[Any]]
RoleAssigner = Callable[[list[str]], Awaitable[dict[str, str]]]

# AnyARESSession is a forward declaration; AppConfig consumers see the
# concrete ARESSession type when they import from ares_client.
AnyARESSession = Any


class ARESClientError(RuntimeError):
    """Base class for ares_client-raised errors."""


@dataclass
class AppConfig:
    """One application's smoke configuration. See module docstring."""

    name: str
    server_url: str
    invite_type: str
    participant_flow: ParticipantFlow

    auth_secret: str = ""
    role_for: RoleAssigner | None = None
    admin_attrs: Mapping[str, Any] = field(default_factory=dict)

    # Tunables -------------------------------------------------------

    default_timeout: float = 30.0
    """Default per-message wait timeout (seconds)."""

    heartbeat_log_interval: float = 5.0
    """How often the smoke driver logs an alive ping per participant."""

    def __post_init__(self) -> None:
        if not self.name:
            raise ARESClientError("AppConfig.name is required")
        if not self.server_url:
            raise ARESClientError("AppConfig.server_url is required")
        if not self.invite_type:
            raise ARESClientError("AppConfig.invite_type is required")
        if self.participant_flow is None:  # type: ignore[unreachable]
            raise ARESClientError("AppConfig.participant_flow is required")


async def default_role_for(participants: list[str]) -> dict[str, str]:
    """Assign every participant role="peer". Suitable for symmetric apps."""
    return {p: "peer" for p in participants}
