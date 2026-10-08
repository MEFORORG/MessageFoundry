# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3260 on the JSON plane: each self-target refusal writes its own audit row.

Before this, the step-up gate's ``auth.permission_granted`` was the attempt's only row, so the
refusal itself went unrecorded. Each of the six admin routes that refuse the caller's own account
now writes ``auth.self_target_refused``, naming the actor and the caller's stored id. The console
plane, and the case-spelling bypass of vault BACKLOG #3259, are pinned in
``packaging/messagefoundry-webconsole/tests/test_ui_self_target_guard.py``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import Role
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests.test_api_auth import _DEFAULT_PEER, _add, _auth, _client, _login, _reauth, _service


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """Local rather than imported: a fixture resolves by name in the module that requests it."""
    eng = await Engine.create(
        tmp_path / "self_target.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


_UNBOUND = {"expected_issuer": None, "expected_subject": None}

#: (op, method, path after /users/{id}, step-up purpose or None for the window, body, refusal text).
ROUTES: list[tuple[str, str, str, str | None, Any, str]] = [
    ("password_reset", "POST", "/reset-password", "admin_reset_password", None, "change-password"),
    ("mfa_reset", "POST", "/reset-mfa", "admin_reset_mfa", None, "self-service MFA settings"),
    (
        "federated_bind",
        "PUT",
        "/federated-identity",
        "admin_federated_identity",
        {"subject": "S-1-me", **_UNBOUND},
        "your own binding",
    ),
    (
        "federated_unbind",
        "DELETE",
        "/federated-identity",
        "admin_federated_identity",
        _UNBOUND,
        "your own binding",
    ),
    ("disable", "PATCH", "", "admin_user_update", {"disabled": True}, "cannot disable your own"),
    ("delete", "DELETE", "", None, None, "cannot delete your own"),
]


@pytest.mark.parametrize(("op", "method", "suffix", "purpose", "body", "words"), ROUTES)
async def test_each_self_target_refusal_writes_its_own_audit_row(
    engine: Engine,
    op: str,
    method: str,
    suffix: str,
    purpose: str | None,
    body: Any,
    words: str,
) -> None:
    service = await _service(
        engine,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            oidc_issuer="https://idp.example",
        ),
    )
    await _add(service, "root", Role.ADMINISTRATOR)
    me = await engine.store.get_user_by_username("root")
    assert me is not None
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        r, tok = await _reauth(c, tok, purpose=purpose)
        assert r.status_code == 200, r.text
        r = await c.request(method, f"/users/{me.id}{suffix}", json=body, headers=_auth(tok))
    assert r.status_code == 400, r.text
    assert words in r.json()["detail"]
    rows = await engine.store.list_audit(action="auth.self_target_refused", limit=10)
    assert len(rows) == 1, "one refusal, one audit row"
    assert rows[0]["actor"] == "root"
    assert rows[0]["client"] == _DEFAULT_PEER[0], "the refusal row dropped the caller's address"
    # The route and the caller's stored id: no credential, no body, no message content.
    assert json.loads(str(rows[0]["detail"])) == {"op": op, "user_id": me.id}


async def test_another_account_writes_no_refusal_row(engine: Engine) -> None:
    """The control: the same route on another account is not a refusal, so it writes no such row."""
    service = await _service(engine)
    await _add(service, "root", Role.ADMINISTRATOR)
    await _add(service, "viewer1", Role.VIEWER)
    other = await engine.store.get_user_by_username("viewer1")
    assert other is not None
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        _r, tok = await _reauth(c, tok)
        r = await c.delete(f"/users/{other.id}", headers=_auth(tok))
    assert r.status_code == 200, r.text
    assert await engine.store.list_audit(action="auth.self_target_refused", limit=10) == []
