# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2446: the audit API says when the caller's permissions withheld rows, and never which.

``GET /audit`` carries ``withheld`` and ``GET /audit/export`` carries the ``X-Audit-Withheld``
header and a ``withheld`` key in its ``audit.export`` row. Each is decided by the permission alone.
The trail here holds NO lock row, which is the discriminating arm: an answer computed from the rows
would say ``false`` to the Auditor, and so would say "no lock happened" whenever it did not.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.auth import Role
from messagefoundry.auth.audit_visibility import AUDIT_WITHHELD_HEADER
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _add, _auth, _client, _login, _service


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "withheld_api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


@pytest.mark.parametrize(("role", "withheld"), [(Role.AUDITOR, True), (Role.ADMINISTRATOR, False)])
async def test_audit_list_and_export_state_withheld_by_permission(
    engine: Engine, role: Role, withheld: bool
) -> None:
    service = await _service(engine)
    await _add(service, "reader", role)
    await engine.store.record_audit("message_view", actor="alice", detail="{}", now=100.0)
    async with _client(engine, service) as c:
        h = _auth((await _login(c, "reader")).json()["token"])
        listed = (await c.get("/audit", params={"actor": "alice"}, headers=h)).json()
        assert listed["withheld"] is withheld
        exported = await c.get("/audit/export", params={"actor": "alice"}, headers=h)
        assert exported.status_code == 200
        assert exported.headers[AUDIT_WITHHELD_HEADER] == ("true" if withheld else "false")
    rows = await engine.store.list_audit(action="audit.export", limit=1)
    assert json.loads(rows[0]["detail"])["withheld"] is withheld
