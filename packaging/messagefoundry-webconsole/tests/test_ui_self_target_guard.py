# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3259 and #3260: the console's self-target refusals, by stored id, each audited.

Six admin routes refuse the caller's own account: reset-password, reset-mfa, federated link and
unlink, disable and delete. The console's ``/ui/users/{user_id}/`` routes call the API handlers
through the seam with the path as a plain str, past the JSON plane's ``ResourceId`` pattern. So a
store whose id column compares case-insensitively (SQL Server) finds the caller's row from an
upper-cased spelling. #3259 is that bypass: four of the six guards compared only the path.

The default SQLite test store compares case-sensitively, where a naive test gets a 404 "no such
user" whether or not the fix is in. So ``get_user`` is wrapped to fold case first, as a
case-insensitive collation would answer. The ``exact`` spelling is the control.

#3260 is the audit row: each refusal writes ``auth.self_target_refused`` naming the actor and the
caller's stored id, on both planes. The JSON plane's twin is ``tests/test_self_target_refusal_audit.py``.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
from _ui_clients import SAME_ORIGIN, cookie_login, mint_bound_proof, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import UserRecord

#: (op, the path after /ui/users/{id}, the page whose re-auth mints the grant, form, refusal text).
#: ``None`` for the grant page means the route takes the login window, which a fresh login holds.
ROUTES = [
    ("password_reset", "/reset-password", "/reset-password", {}, "use change-password"),
    ("mfa_reset", "/reset-mfa", "/reset-mfa", {}, "use the self-service MFA settings"),
    (
        "federated_bind",
        "/federated-identity/link",
        "/federated-identity",
        {"subject": "S-1-me", "shown_issuer": "", "shown_subject": ""},
        "another administrator must change your own binding",
    ),
    (
        "federated_unbind",
        "/federated-identity/unlink",
        "/federated-identity/unlink-confirm",
        {"shown_issuer": "", "shown_subject": ""},
        "another administrator must change your own binding",
    ),
    (
        "disable",
        "/update",
        "",
        {"display_name": "", "email": "", "disabled": "on"},
        "cannot disable your own account",
    ),
    ("delete", "/delete", None, {}, "cannot delete your own account"),
]


@pytest.fixture
async def root(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[httpx.AsyncClient, AuthService, str]]:
    """An administrator signed in over a store whose ``get_user`` folds case."""
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_write_min_interval_seconds=0,
            oidc_issuer="https://idp.example",
        ),
    )
    await service.initialize()
    me = await provision(service, "root", [Role.ADMINISTRATOR.value])
    real = engine.store.get_user

    async def folded(user_id: str) -> UserRecord | None:
        return await real(user_id.lower())

    monkeypatch.setattr(engine.store, "get_user", folded)
    async with ui_client(engine, service) as c:
        await cookie_login(c, "root")
        yield c, service, me


@pytest.mark.parametrize("spelling", ["exact", "upper"])
@pytest.mark.parametrize(("op", "suffix", "grant_page", "form", "words"), ROUTES)
async def test_each_self_target_refusal_is_by_stored_id_and_audited(
    engine: Engine,
    root: tuple[httpx.AsyncClient, AuthService, str],
    spelling: str,
    op: str,
    suffix: str,
    grant_page: str | None,
    form: dict[str, str],
    words: str,
) -> None:
    c, _service, me = root
    assert me == me.lower(), "the stored id is lower-case hex, so upper-casing changes it"
    spelled = me if spelling == "exact" else me.upper()
    base = f"/ui/users/{spelled}"
    if grant_page is not None:
        await mint_bound_proof(c, base + grant_page)
    before = await engine.store.get_user(me)

    r = await c.post(base + suffix, data=form, headers=SAME_ORIGIN)

    assert r.status_code == 400, (r.status_code, r.text[:300])
    assert words in r.text
    rows = await engine.store.list_audit(action="auth.self_target_refused", limit=10)
    assert len(rows) == 1, "one refusal, one audit row"
    assert rows[0]["actor"] == "root"
    # The caller's stored id and the route, nothing more: no path spelling, no message content.
    assert json.loads(str(rows[0]["detail"])) == {"op": op, "user_id": me}
    after = await engine.store.get_user(me)
    assert after is not None and before is not None
    assert (after.disabled, after.oidc_subject) == (before.disabled, before.oidc_subject)
    assert after.password_hash == before.password_hash, "a refused reset changed the credential"
