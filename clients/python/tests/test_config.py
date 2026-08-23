# SPDX-License-Identifier: Apache-2.0
"""Tests for AppConfig validation."""

from __future__ import annotations

import pytest

from ares_client import AppConfig, ARESClientError


async def _noop_flow(session, role, total):
    return None


def test_minimal_config_constructs():
    cfg = AppConfig(
        name="x",
        server_url="http://localhost:8000",
        invite_type="x.invite",
        participant_flow=_noop_flow,
    )
    assert cfg.name == "x"
    assert cfg.auth_secret == ""
    assert cfg.role_for is None


def test_missing_name_raises():
    with pytest.raises(ARESClientError):
        AppConfig(name="", server_url="http://x", invite_type="t", participant_flow=_noop_flow)


def test_missing_server_url_raises():
    with pytest.raises(ARESClientError):
        AppConfig(name="x", server_url="", invite_type="t", participant_flow=_noop_flow)


def test_missing_invite_type_raises():
    with pytest.raises(ARESClientError):
        AppConfig(name="x", server_url="http://x", invite_type="", participant_flow=_noop_flow)
