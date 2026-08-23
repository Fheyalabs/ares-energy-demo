# SPDX-License-Identifier: Apache-2.0
"""Generic Python client for ARES-core applications.

Public entry points:

    from ares_client import AppConfig, ARESSession, run_smoke

    config = AppConfig(
        name="auction",
        server_url="http://localhost:8000",
        invite_type="auction.invitation",
        participant_flow=auction_flow,
    )
    asyncio.run(run_smoke(config, n_participants=6, session_id="auc-001"))

The library is intentionally protocol-agnostic: each app supplies its
own ``participant_flow`` coroutine that drives one participant through
the protocol using the :class:`ARESSession` helpers. Three example
configs ship in ``ares_client.examples`` for the auction, ride-share,
and recurring-cohort apps.
"""

from .config import AppConfig, ARESClientError
from .session import ARESSession, WSMessage
from .pipeline import run_smoke, AdminClient

__all__ = [
    "AppConfig",
    "ARESClientError",
    "ARESSession",
    "WSMessage",
    "run_smoke",
    "AdminClient",
]

__version__ = "0.5.0"
