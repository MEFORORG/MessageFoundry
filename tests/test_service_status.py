# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Service-status reporting (L6a, ADR 0065 / BACKLOG #75): the read-only NSSM `sc query` badge.

Read-only + unprivileged (no shell, no elevation, validated name, off the loop); default OFF; gated by
monitoring:read. `sc query` is Windows-only, so the actual query is monkeypatched — the tests pin the
config gating, the name validation, and the endpoint/permission wiring, not the live SCM."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry import service_status
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, ServiceStatusSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "svc.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    svc = AuthService(engine.store, AuthSettings())
    await svc.initialize()
    return svc


async def _token(engine: Engine, svc: AuthService, *roles: Role) -> str:
    await svc.create_local_user(
        username="u",
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await svc.store.get_user_by_username("u")
    assert user is not None and user.password_hash is not None
    await svc.store.set_password(
        user.id, password_hash=user.password_hash, must_change_password=False
    )
    out = await svc.login("u", PW)
    assert out.token is not None
    return out.token


def _client(engine: Engine, svc: AuthService, cfg: ServiceStatusSettings) -> httpx.AsyncClient:
    app = create_app(engine, auth=svc, service_settings=cfg)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


# --- the neutral helper (pure) ---------------------------------------------------


def test_is_safe_service_name() -> None:
    assert service_status.is_safe_service_name("MessageFoundry")
    assert service_status.is_safe_service_name("MEFOR_Engine 1.0-x")
    assert not service_status.is_safe_service_name("")  # empty = not a name
    for bad in ("svc & calc", "a|b", 'a"b', "a;b", "a`b", "a$b", "a\\b", "a/b"):
        assert not service_status.is_safe_service_name(bad), bad
    # Must start with an alphanumeric — a leading '-'/space (an sc-token risk) or whitespace-only name
    # is rejected (review hardening).
    for bad in ("-config", "--help", " leadingspace", "   ", " "):
        assert not service_status.is_safe_service_name(bad), bad


def test_parse_service_state() -> None:
    assert service_status.parse_service_state("STATE : 4  RUNNING") == "running"
    assert service_status.parse_service_state("STATE : 1  STOPPED") == "stopped"
    assert service_status.parse_service_state("STATE : 3  STOP_PENDING") == "stopped"
    assert service_status.parse_service_state("garbage") == "unknown"


async def test_query_unsafe_or_empty_name_is_unavailable() -> None:
    assert await service_status.query_service_state("") == "unavailable"
    assert await service_status.query_service_state("bad & name") == "unavailable"


# --- the endpoint ----------------------------------------------------------------


async def test_status_disabled_by_default(engine: Engine) -> None:
    svc = await _service(engine)
    token = await _token(engine, svc, Role.VIEWER)
    # Default settings → report_status off → no query, state 'disabled'.
    async with _client(engine, svc, ServiceStatusSettings()) as c:
        r = await c.get("/service/status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert body == {"enabled": False, "state": "disabled", "service_name": ""}


async def test_status_enabled_calls_query(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    svc = await _service(engine)
    token = await _token(engine, svc, Role.VIEWER)

    async def _fake(name: str) -> str:
        assert name == "MEFOR_Engine"
        return "running"

    monkeypatch.setattr("messagefoundry.api.app.query_service_state", _fake)
    cfg = ServiceStatusSettings(report_status=True, service_name="MEFOR_Engine")
    async with _client(engine, svc, cfg) as c:
        r = await c.get("/service/status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json() == {
            "enabled": True,
            "state": "running",
            "service_name": "MEFOR_Engine",
        }


async def test_status_requires_monitoring_read(engine: Engine) -> None:
    svc = await _service(engine)
    async with _client(engine, svc, ServiceStatusSettings()) as c:
        # No bearer at all → 401 (auth required).
        assert (await c.get("/service/status")).status_code == 401


def test_settings_rejects_unsafe_service_name() -> None:
    ServiceStatusSettings(service_name="MEFOR_Engine")  # ok
    ServiceStatusSettings(service_name="")  # empty ok (disabled)
    with pytest.raises(ValueError):
        ServiceStatusSettings(service_name="svc & calc.exe")
