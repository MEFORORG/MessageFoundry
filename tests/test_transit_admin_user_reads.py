# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520's admin user reads under the Transit row sealer (ADR 0217). An account record Vault
transit cannot verify is listed as integrity-failed, audited under its own action and paged; an
Outage on one account answers ``GET /users`` 503 with ``Retry-After``, pages the Outage subject and
writes no seal audit row. Synthetic data only."""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    AUTHORITY_SEAL_UNVERIFIABLE_ACTION,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    TRANSIT_OUTAGE_SUBJECT,
    UNVERIFIABLE_SUBJECT_PREFIX,
    TransitRowSealer,
)
from messagefoundry.store.store import MessageStore
from tests._transit_seal_fake import FakeBackend, with_version
from tests.test_api_auth import _auth, _login
from tests.test_user_seal_routes import _client, _setup


@pytest.fixture
async def transit(tmp_path: Path) -> AsyncIterator[tuple[Engine, FakeBackend, Path]]:
    path = tmp_path / "transit_routes.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    backend = FakeBackend()
    store._row_sealer = TransitRowSealer(backend)
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield engine, backend, path
    finally:
        await engine.stop()


def _plant(path: Path, user_id: str) -> None:
    """Name version 5 in the account's stored seal, which the stand-in does not hold: Transit
    answers 400, and the probe then decides between Unverifiable and Outage."""
    conn = sqlite3.connect(path)
    try:
        (seal,) = conn.execute("SELECT authz_seal FROM users WHERE id=?", (user_id,)).fetchone()
        conn.execute(
            "UPDATE users SET authz_seal=? WHERE id=?", (with_version(str(seal), "5"), user_id)
        )
        conn.commit()
    finally:
        conn.close()


async def _rows(engine: Engine, action: str, user_id: str) -> int:
    rows = await engine.store.list_audit(action=action, limit=10_000)
    return sum(1 for row in rows if user_id in str(row["detail"]))


async def test_an_unverifiable_account_is_listed_as_integrity_failed_audited_and_paged(
    transit: tuple[Engine, FakeBackend, Path],
) -> None:
    engine, _, path = transit
    service, _alerts, intact, victim = await _setup(engine)
    pages: list[str] = []
    cast(MessageStore, engine.store).seal_pager().arm(
        lambda subject, _reason: pages.append(subject)
    )
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        _plant(path, victim)
        resp = await c.get("/users", headers=_auth(token))
    assert resp.status_code == 200
    rows = {row["id"]: row for row in resp.json()}
    assert rows[victim] == {"id": victim, "integrity_failed": True}
    assert rows[intact]["username"] == "intact"  # control: an intact account is served whole
    assert await _rows(engine, AUTHORITY_SEAL_UNVERIFIABLE_ACTION, victim) == 1
    assert await _rows(engine, AUTHORITY_SEAL_FAILED_ACTION, victim) == 0
    assert [p for p in pages if p.startswith(f"{UNVERIFIABLE_SUBJECT_PREFIX}:user:")] != []


async def test_an_outage_on_one_account_answers_get_users_503_with_retry_after(
    transit: tuple[Engine, FakeBackend, Path],
) -> None:
    engine, backend, path = transit
    service, _alerts, _intact, victim = await _setup(engine)
    pages: list[str] = []
    cast(MessageStore, engine.store).seal_pager().arm(
        lambda subject, _reason: pages.append(subject)
    )
    async with _client(engine, service) as c:
        token = (await _login(c, "root")).json()["token"]
        control = await c.get("/users", headers=_auth(token))
        assert control.status_code == 200  # control: Transit up, the list is served
        _plant(path, victim)
        # The probe fails, so the victim's 400 reads as an Outage; every sound row still verifies.
        backend.probe_down = True
        try:
            resp = await c.get("/users", headers=_auth(token))
        finally:
            backend.probe_down = False
    assert resp.status_code == 503
    assert "retry-after" in resp.headers
    assert pages == [TRANSIT_OUTAGE_SUBJECT]
    assert await _rows(engine, AUTHORITY_SEAL_UNVERIFIABLE_ACTION, victim) == 0
    assert await _rows(engine, AUTHORITY_SEAL_FAILED_ACTION, victim) == 0
