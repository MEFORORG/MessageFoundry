# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3260, limb 2, on the console plane: a session revoke that ends nothing is audited.

Owner ruling 2026-10-16: one ``auth.session_revoke_missed`` row per miss, with the id cut to its
first 12 characters, and the answer unchanged and the same for an unknown id and another account's.
The console takes the id as plain text, so the cut also bounds what a caller can put in the row.
The JSON plane's twin is ``tests/test_self_target_refusal_audit.py``.
"""

from __future__ import annotations

import json

import pytest
from _ui_clients import PW, SAME_ORIGIN, cookie_login, mint_bound_proof, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine


@pytest.mark.parametrize(
    "kind",
    [
        "unknown",
        "foreign",
        # Plain text on this plane, so the row must cut it, not copy it.
        "long",
    ],
)
async def test_a_missed_console_revoke_writes_one_row_and_the_same_answer(
    engine: Engine, kind: str
) -> None:
    """RED when: the console's revoke of a session it cannot end writes no audit row of its own, or
    its answer or row tells an unknown id from another account's (vault BACKLOG #3260, limb 2)."""
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, admin_write_min_interval_seconds=0)
    )
    await service.initialize()
    await provision(service, "a", [Role.VIEWER.value])
    await provision(service, "b", [Role.VIEWER.value])
    theirs = await service.login("b", PW)
    assert theirs.token is not None
    target = {
        "unknown": "0" * 64,
        "foreign": hash_token(theirs.token),
        "long": "x" * 200,
    }[kind]
    path = f"/ui/account/sessions/{target}/revoke"
    async with ui_client(engine, service) as c:
        await cookie_login(c, "a")
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    assert r.headers["location"] == "/ui/account/sessions?m=revoke_missed"
    assert await service.identity_for_token(theirs.token, activity=False) is not None, (
        "a missed revoke ended another account's session"
    )
    rows = await engine.store.list_audit(action="auth.session_revoke_missed", limit=10)
    assert len(rows) == 1, "one miss, one row"
    assert rows[0]["actor"] == "a"
    assert rows[0]["client"] == "127.0.0.1", "the miss row dropped the caller's address"
    # The cut id and nothing else, so the row records no ownership either.
    assert json.loads(str(rows[0]["detail"])) == {"session": target[:12]}
