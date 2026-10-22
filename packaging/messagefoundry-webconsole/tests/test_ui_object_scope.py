# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console twins of the flag route and the alert-rules view answer by the caller's scope
(BACKLOG #1152, ASVS 8.2.2).

Each /ui route calls the JSON handler in-process, past that route's ``Depends`` gates, so a fix in
the handler reaches the console only if the console passes the caller's identity through. These
tests check that it does. ``tests/test_object_scope_flag_and_alert_rules.py`` covers the JSON side.
"""

from __future__ import annotations

import json

import pytest
from _ui_clients import SAME_ORIGIN, auth_service, cookie_login, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AlertRule, AlertsSettings
from messagefoundry.pipeline import Engine


async def _scoped(service: AuthService, username: str, role: Role, scope: list[str]) -> None:
    uid = await provision(service, username, [role.value])  # provision grants every channel
    await service.set_channel_scope(uid, scope, actor="test")


async def test_ui_flag_refuses_a_connection_outside_the_scope(engine: Engine) -> None:
    """With no graph loaded, a name inside the scope reaches the engine and gets its 409 notice. A
    name outside it gets the audited 403 first, so the answer no longer tells it which names the
    connections file holds."""
    service = await auth_service(engine)
    await _scoped(service, "dep", Role.DEPLOYMENT, ["IB_A"])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "dep")
        refused = await c.post(
            "/ui/connections/IB_B/flag",
            data={"direction": "inbound", "flagged": "true"},
            headers=SAME_ORIGIN,
        )
        assert refused.status_code == 403, refused.text[:300]
        rows = await engine.store.list_audit(actor="dep", action="auth.channel_denied")
        assert [row["channel_id"] for row in rows] == ["IB_B"]
        # The control: the in-scope name passes the check and reaches the engine's own refusal.
        reached = await c.post(
            "/ui/connections/IB_A/flag",
            data={"direction": "inbound", "flagged": "true"},
            headers=SAME_ORIGIN,
        )
        assert reached.status_code == 200, reached.status_code
        assert len(await engine.store.list_audit(actor="dep", action="auth.channel_denied")) == 1


async def test_ui_alerts_page_lists_only_rules_inside_the_scope(engine: Engine) -> None:
    # The page shows each rule's connection, not its id, so the connection names are the markers.
    rules = AlertsSettings(
        rules=[AlertRule(connection="IB_MINE"), AlertRule(connection="IB_THEIRS")]
    )
    service = await auth_service(engine)
    await _scoped(service, "op", Role.OPERATOR, ["IB_MINE"])
    await provision(service, "wide", [Role.OPERATOR.value])
    async with ui_client(engine, service, alerts_settings=rules) as c:
        await cookie_login(c, "wide")
        page = (await c.get("/ui/alerts")).text
        assert "IB_MINE" in page and "IB_THEIRS" in page  # the control: both render
    async with ui_client(engine, service, alerts_settings=rules) as c:
        await cookie_login(c, "op")
        r = await c.get("/ui/alerts")
        assert r.status_code == 200
        assert "IB_MINE" in r.text and "IB_THEIRS" not in r.text
    # BACKLOG #3403: the console load writes the JSON handler's count-only row, and only for the
    # caller it withheld a rule from.
    withheld = await engine.store.list_audit(action="alert_rules_withheld")
    assert [(row["actor"], json.loads(str(row["detail"]))) for row in withheld] == [
        ("op", {"shown": 1, "withheld": 1})
    ]
    # docs/SECURITY.md writes one row per load, not coalesced, because this page does not poll. A
    # poll hook here would write a row per tick, so it must coalesce the row first.
    assert "data-poll" not in page and "data-mf-fragment" not in page


async def test_ui_flag_names_the_fix_for_a_toggle_the_audit_log_did_not_record(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault BACKLOG #2945: a toggle whose audit row failed is refused 503 and undone. The console
    names that fix, not ``flag_rejected``'s code-first and cluster-node hints, which do not apply.
    A 503 used to escape the route as an error page."""
    from messagefoundry.pipeline.engine import ConfigWriteAuditTimeout

    async def _not_recorded(*_args: object, **_kwargs: object) -> None:
        raise ConfigWriteAuditTimeout(10.0, undone=True)

    monkeypatch.setattr(engine, "set_connection_flag", _not_recorded)
    service = await auth_service(engine)
    await provision(service, "dep", [Role.DEPLOYMENT.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "dep")
        r = await c.post(
            "/ui/connections/IB_A/flag",
            data={"direction": "inbound", "flagged": "true"},
            headers=SAME_ORIGIN,
        )
    assert r.status_code == 200, r.text[:300]
    assert "The audit log did not record the change, so the engine undid it" in r.text
    assert "was not recorded within 10 s" in r.text
    assert "code-first connection" not in r.text and "cluster node" not in r.text
