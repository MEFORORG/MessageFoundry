# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console twins of the flag route and the alert-rules view answer by the caller's scope
(BACKLOG #1152, ASVS 8.2.2).

Each /ui route calls the JSON handler in-process, past that route's ``Depends`` gates, so a fix in
the handler reaches the console only if the console passes the caller's identity through. These
tests check that it does. ``tests/test_object_scope_flag_and_alert_rules.py`` covers the JSON side.
"""

from __future__ import annotations

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
