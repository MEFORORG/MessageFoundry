# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""S7b logging surfaces — runtime verbosity control + redacted log-tail viewer (#171, ADR 0130).

Covers the ``set_runtime_level`` helper (validate + apply, ephemeral), the ``GET``/``PATCH
/logging/level`` control (RBAC + audit + 400 on a bad level), and the ``GET /logs/tail`` viewer (the
new ``logs:view`` PHI-read gate, redaction reuse, ``logs_view`` audit counting exposed lines, graceful
degradation when no ``[logging].log_dir`` is set, and pagination).

The bulk-export surface (#124, ADR 0131) is covered in :mod:`tests.test_message_export`.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.logging_setup import (
    LOG_LEVELS,
    current_log_level,
    set_runtime_level,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # ≥15, satisfies the ASVS policy

# A synthetic app-log tail: a plain operational line, an HL7-bearing ERROR line (PHI), and a bearer
# token — the last two MUST be scrubbed by the shared redactor before reaching the browser.
_LOG_LINES = [
    "2026-07-17T00:00:00Z INFO messagefoundry: engine started, 2 connections",
    "2026-07-17T00:00:01Z ERROR messagefoundry: bad msg PID|1||MRN9001^^^H^MR||DOE^JANE",
    "2026-07-17T00:00:02Z INFO messagefoundry: token=supersecretvalue123",
]


@pytest.fixture(autouse=True)
def _restore_log_levels() -> Iterator[None]:
    """set_runtime_level mutates GLOBAL logging state; snapshot + restore around each test so a level
    change never leaks into another test."""
    root = logging.getLogger()
    saved = {
        name: logging.getLogger(name).level
        for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access")
    }
    root_level = root.level
    try:
        yield
    finally:
        root.setLevel(root_level)
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)


# --- set_runtime_level unit -----------------------------------------------------


def test_set_runtime_level_applies_root_and_uvicorn() -> None:
    set_runtime_level("DEBUG")
    assert logging.getLogger().level == logging.DEBUG
    # The three uvicorn loggers are re-levelled to match (so the override reaches request logs too).
    assert logging.getLogger("uvicorn").level == logging.DEBUG
    assert logging.getLogger("uvicorn.access").level == logging.DEBUG
    assert current_log_level() == "DEBUG"


def test_set_runtime_level_is_case_insensitive_and_returns_normalized() -> None:
    assert set_runtime_level("warning") == "WARNING"
    assert current_log_level() == "WARNING"


def test_set_runtime_level_rejects_unknown_level() -> None:
    with pytest.raises(ValueError, match="invalid log level"):
        set_runtime_level("VERBOSE")


# --- API fixtures (modelled on tests/test_content_search.py) --------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "logsurf.db", cipher=make_cipher(generate_key()))
    eng = Engine(store)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, *, log_dir: str | None = None
) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, log_dir=log_dir, configured_log_level="INFO")
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add_user(service: AuthService, username: str, roles: list[str]) -> None:
    user_id = await service.create_local_user(
        username=username, password=PW, display_name=None, email=None, roles=roles, actor="test"
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _write_log(log_dir: Path) -> None:
    (log_dir / "app.log").write_text("\n".join(_LOG_LINES) + "\n", encoding="utf-8")


# --- GET/PATCH /logging/level ---------------------------------------------------


async def test_get_logging_level_reports_effective_configured_and_choices(engine: Engine) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.get("/logging/level", headers=_auth(token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["level"] == current_log_level()
        assert body["configured"] == "INFO"
        assert body["levels"] == list(LOG_LEVELS)


async def test_patch_logging_level_changes_and_audits(engine: Engine) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.patch("/logging/level", headers=_auth(token), json={"level": "DEBUG"})
        assert r.status_code == 200, r.text
        assert r.json()["level"] == "DEBUG"
        assert logging.getLogger().level == logging.DEBUG
    rows = await engine.store.list_audit(limit=50)
    change = [dict(x) for x in rows if x["action"] == "logging_level_change"]
    assert change, "a logging_level_change audit row must be written"
    detail = json.loads(change[0]["detail"])
    assert detail["to"] == "DEBUG" and "from" in detail


async def test_patch_logging_level_rejects_bad_level_400(engine: Engine) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service) as c:
        token = await _login(c, "op")
        r = await c.patch("/logging/level", headers=_auth(token), json={"level": "LOUD"})
        assert r.status_code == 400


async def test_logging_level_denied_without_monitoring_diagnose(engine: Engine) -> None:
    """VIEWER holds monitoring:read + messages:read but NOT monitoring:diagnose → 403 on both halves."""
    service = await _service(engine)
    await _add_user(service, "view", [Role.VIEWER.value])
    async with _client(engine, service) as c:
        token = await _login(c, "view")
        assert (await c.get("/logging/level", headers=_auth(token))).status_code == 403
        r = await c.patch("/logging/level", headers=_auth(token), json={"level": "DEBUG"})
        assert r.status_code == 403


# --- GET /logs/tail -------------------------------------------------------------


async def test_logs_tail_redacts_and_audits(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _write_log(log_dir)
    async with _client(engine, service, log_dir=str(log_dir)) as c:
        token = await _login(c, "op")
        r = await c.get("/logs/tail", headers=_auth(token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["available"] is True
        assert body["total_lines"] == 3
        joined = "\n".join(body["lines"])
        # The plain operational line survives; the PHI + secret spans are scrubbed.
        assert "engine started" in joined
        assert "MRN9001" not in joined and "JANE" not in joined
        assert "supersecretvalue123" not in joined
    rows = await engine.store.list_audit(limit=50)
    views = [dict(x) for x in rows if x["action"] == "logs_view"]
    assert views, "a logs_view audit row must be written"
    detail = json.loads(views[0]["detail"])
    assert detail["lines"] == 3  # counts every exposed line (metadata only)
    assert "MRN9001" not in views[0]["detail"]  # never the content


async def test_logs_tail_paginates_from_the_end(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _write_log(log_dir)
    async with _client(engine, service, log_dir=str(log_dir)) as c:
        token = await _login(c, "op")
        # offset=0, limit=1 → the most recent (last) line only.
        r0 = await c.get("/logs/tail", headers=_auth(token), params={"limit": 1, "offset": 0})
        assert r0.status_code == 200
        assert len(r0.json()["lines"]) == 1 and "supersecretvalue" not in r0.json()["lines"][0]
        # offset=1 pages one line back → the middle (HL7) line, redacted.
        r1 = await c.get("/logs/tail", headers=_auth(token), params={"limit": 1, "offset": 1})
        assert len(r1.json()["lines"]) == 1 and "MRN9001" not in r1.json()["lines"][0]


async def test_logs_tail_degrades_when_no_log_dir(engine: Engine) -> None:
    """With no [logging].log_dir configured the viewer returns an empty, unavailable page — never 500."""
    service = await _service(engine)
    await _add_user(service, "op", [Role.OPERATOR.value])
    async with _client(engine, service, log_dir=None) as c:
        token = await _login(c, "op")
        r = await c.get("/logs/tail", headers=_auth(token))
        assert r.status_code == 200, r.text
        assert r.json()["available"] is False and r.json()["lines"] == []


async def test_logs_tail_denied_without_logs_view(engine: Engine, tmp_path: Path) -> None:
    """VIEWER lacks logs:view → 403 (the redacted log is a PHI read surface, not free ops text)."""
    service = await _service(engine)
    await _add_user(service, "view", [Role.VIEWER.value])
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    _write_log(log_dir)
    async with _client(engine, service, log_dir=str(log_dir)) as c:
        token = await _login(c, "view")
        r = await c.get("/logs/tail", headers=_auth(token))
        assert r.status_code == 403
