# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
    svc = AuthService(engine.store, AuthSettings(require_mfa=False))
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
    # No numeric code: fall back to the state word.
    assert service_status.parse_service_state("STATE : RUNNING") == "running"
    # A tab-indented field is still the field.
    assert service_status.parse_service_state("\tSTATE\t: 4\tRUNNING") == "running"
    # A code the SCM defines but this module does not report stays unknown.
    assert service_status.parse_service_state("STATE : 7  PAUSED") == "unknown"
    assert service_status.parse_service_state("STATE : 2  START_PENDING") == "unknown"


# Verbatim `sc query` blocks, which is the shape the parser is actually handed.
#
# Only ONE of these three discriminates against the whole-output substring search BACKLOG #1556
# removed, and it is named for that: the old body tested RUNNING before STOP, so a running service
# came out right despite its STOPPABLE / ACCEPTS_SHUTDOWN flags line, and a stopped service whose
# NAME carries the letters "running" came out wrong. The other two are positive controls -- they
# pin the shapes the parser must keep reading correctly, and they passed before the fix too.
_STOPPED_BUT_OLD_PARSER_SAID_RUNNING = """SERVICE_NAME: AcmeRunningSync
DISPLAY_NAME: Acme Running Sync
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
"""

_RUNNING = """SERVICE_NAME: MessageFoundry
DISPLAY_NAME: MessageFoundry Engine
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
"""

# `sc queryex` adds fields after STATE; the parser must not depend on STATE being last.
_RUNNING_QUERYEX = """SERVICE_NAME: MessageFoundry
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 4812
        FLAGS              :
"""


def test_parse_service_state_reads_the_state_field_not_the_whole_output() -> None:
    """BACKLOG #1556: the verdict comes from the STATE field, not from a word anywhere.

    The one arm the fix changes. The service is STOPPED and its own name contains the letters
    `running`, which is exactly what the removed substring search read."""
    assert service_status.parse_service_state(_STOPPED_BUT_OLD_PARSER_SAID_RUNNING) == "stopped"
    # The block really does carry the wrong word ahead of the STATE field -- otherwise this test
    # would pass against the parser it was written to reject.
    head = _STOPPED_BUT_OLD_PARSER_SAID_RUNNING.upper().split("STATE")[0]
    assert "RUNNING" in head


def test_parse_service_state_on_real_running_output() -> None:
    """Positive controls: the shapes `sc query` and `sc queryex` print for a running service."""
    assert service_status.parse_service_state(_RUNNING) == "running"
    assert service_status.parse_service_state(_RUNNING_QUERYEX) == "running"
    # The flags line sits between STATE and the rest, and `queryex` keeps going past it.
    assert "STOPPABLE" in _RUNNING
    assert "PID" in _RUNNING_QUERYEX


def test_parse_service_state_ignores_a_state_word_outside_the_state_field() -> None:
    """No STATE field means no verdict, however many state words the output carries."""
    assert service_status.parse_service_state("SERVICE_NAME: RunningStoppedSvc") == "unknown"
    assert service_status.parse_service_state("DISPLAY_NAME: Is It Running") == "unknown"


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
