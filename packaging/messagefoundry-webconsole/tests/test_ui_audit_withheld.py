# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2446: the console audit pages say what they leave out, and the console exports.

Three limbs. A reader without ``users:manage`` has the lock rows removed (BACKLOG #1131), and the
audit page now says so, by permission and never by the rows. The self-service security-events page
says an administrator's change to the account is not listed there. And ``/ui/audit/export`` streams
the engine's export from the console session, because ``GET /audit/export`` reads only a bearer that
an OIDC-only account never holds.
"""

from __future__ import annotations

import json

from _ui_clients import auth_service, cookie_login, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.auth.audit_visibility import AUDIT_WITHHELD_HEADER
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._html import text
from messagefoundry_webconsole.pages.audit import ADMIN_CHANGES_NOTE, WITHHELD_NOTE


def _rendered(sentence: str) -> str:
    """``sentence`` as the page builder escapes it, so the check matches what the page carries."""
    return str(text(sentence))


async def test_the_audit_page_says_rows_are_withheld_by_permission_not_by_rows(
    engine: Engine,
) -> None:
    """The Auditor is told, on a trail holding NO lock row at all: the sentence is about the
    reader's permission, so it cannot be read as "a lock happened". The Administrator is not told."""
    service = await auth_service(engine)
    await provision(service, "aud", [Role.AUDITOR.value])
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    for who, told in (("aud", True), ("root", False)):
        async with ui_client(engine, service) as c:
            await cookie_login(c, who)
            r = await c.get("/ui/audit")
        assert r.status_code == 200, r.text
        assert (_rendered(WITHHELD_NOTE) in r.text) is told, who
        assert 'href="/ui/audit/export"' in r.text, who


async def test_no_export_link_without_audit_export_and_the_route_refuses(engine: Engine) -> None:
    service = await auth_service(engine)
    role = await service.create_custom_role(
        display_name="Trail reader", description=None, permissions=["audit:read"], actor="test"
    )
    await provision(service, "reader", [role.id])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "reader")
        page = await c.get("/ui/audit")
        assert page.status_code == 200, page.text
        assert "/ui/audit/export" not in page.text
        refused = await c.get("/ui/audit/export")
    assert refused.status_code == 403
    assert not await engine.store.list_audit(action="audit.export", limit=5)


async def test_the_console_export_streams_the_engine_export_from_the_cookie(engine: Engine) -> None:
    """An Auditor with only a console session gets the CSV, minus the lock rows, with the header
    and the ``audit.export`` row the engine route writes."""
    service = await auth_service(engine)
    await provision(service, "aud", [Role.AUDITOR.value])
    await engine.store.record_audit("message_view", actor="alice", detail="{}", now=100.0)
    await engine.store.record_audit(
        "auth.account_locked", actor="alice", detail='{"provider": "local"}', now=200.0
    )
    async with ui_client(engine, service) as c:
        await cookie_login(c, "aud")
        r = await c.get("/ui/audit/export", params={"actor": "alice"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers[AUDIT_WITHHELD_HEADER] == "true"
    lines = [ln for ln in r.text.splitlines() if ln]
    assert lines[0] == "ts,actor,action,channel_id,client,detail"
    assert len(lines) == 2 and "message_view" in lines[1]
    assert "auth.account_locked" not in r.text
    rows = await engine.store.list_audit(action="audit.export", limit=5)
    assert len(rows) == 1 and rows[0]["actor"] == "aud"
    detail = json.loads(rows[0]["detail"])
    assert detail["count"] == 1 and detail["withheld"] is True


async def test_the_console_export_refuses_a_filter_the_engine_route_would(engine: Engine) -> None:
    """The in-process call skips the handler's own validation, so the console route declares the
    same types: a control character in ``actor`` is a 422 here, as on ``GET /audit/export``."""
    service = await auth_service(engine)
    await provision(service, "aud", [Role.AUDITOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "aud")
        r = await c.get("/ui/audit/export", params={"actor": "a\x00b"})
    assert r.status_code == 422
    assert not await engine.store.list_audit(action="audit.export", limit=5)


async def test_the_console_export_needs_a_session(engine: Engine) -> None:
    service = await auth_service(engine)
    async with ui_client(engine, service) as c:
        r = await c.get("/ui/audit/export")
    assert r.status_code in (303, 401), r.status_code
    assert not await engine.store.list_audit(action="audit.export", limit=5)


async def test_the_security_events_page_says_admin_changes_are_not_listed(engine: Engine) -> None:
    service = await auth_service(engine)
    await provision(service, "viewer", [Role.VIEWER.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "viewer")
        r = await c.get("/ui/security-events")
    assert r.status_code == 200, r.text
    assert _rendered(ADMIN_CHANGES_NOTE) in r.text
