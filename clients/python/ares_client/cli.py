# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for ares-client.

Usage:

    python -m ares_client --config examples.auction_stub_smoke \
        --participants 6 --session-id auc-001

The ``--config`` argument is a dotted Python module path. The module
must expose a ``CONFIG`` global of type :class:`AppConfig`.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import sys
import time
from typing import Any

from .config import AppConfig, ARESClientError
from .pipeline import run_smoke


def _load_config(dotted: str, overrides: dict[str, Any] | None = None) -> AppConfig:
    try:
        mod = importlib.import_module(dotted)
    except ImportError as e:
        raise ARESClientError(f"import {dotted}: {e}") from e
    cfg = getattr(mod, "CONFIG", None)
    if cfg is None or not isinstance(cfg, AppConfig):
        raise ARESClientError(
            f"{dotted} must expose a module-level CONFIG: AppConfig"
        )
    if overrides:
        for k, v in overrides.items():
            setattr(cfg, k, v)
    return cfg


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ares-client",
        description="Run an ARES-core app smoke against a live session-service.",
    )
    p.add_argument(
        "--config", required=True,
        help="Dotted Python module path with a CONFIG: AppConfig global "
             "(e.g. examples.auction_stub_smoke).",
    )
    p.add_argument(
        "--participants", "-n", type=int, default=6,
        help="Number of participants (default 6).",
    )
    p.add_argument(
        "--session-id", default=None,
        help="Session ID (default: auto-generated from app name + epoch).",
    )
    p.add_argument(
        "--server", default=None,
        help="Override AppConfig.server_url.",
    )
    p.add_argument(
        "--participant-prefix", default="p",
        help="Pseudonym prefix for generated participants (default 'p').",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="DEBUG-level logs.",
    )
    p.add_argument(
        "--no-wait", action="store_true",
        help="Skip the /admin/health pre-flight.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _setup_logging(args.verbose)

    overrides: dict[str, Any] = {}
    if args.server:
        overrides["server_url"] = args.server

    try:
        cfg = _load_config(args.config, overrides=overrides)
    except ARESClientError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    session_id = args.session_id or f"{cfg.name}-{int(time.time())}"

    try:
        results = asyncio.run(
            run_smoke(
                cfg,
                n_participants=args.participants,
                session_id=session_id,
                participant_prefix=args.participant_prefix,
                wait_for_server=not args.no_wait,
            )
        )
    except ARESClientError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    print(json.dumps({"results": results}, default=str, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
