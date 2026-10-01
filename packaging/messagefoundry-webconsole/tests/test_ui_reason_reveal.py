# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2443 (ASVS 14.2.6, owner ruling R12): the event and alert pages mask each reason on
load and reveal ONE per request.

``/ui/events``, ``/ui/connection/{name}`` and ``/ui/alerts`` show each reason as ``****`` with a
"Reveal" link. The reveal route returns that one reason whole, the engine audits it, and the next
bare load is masked again. A role without ``messages:view_summary`` sees no reason and no link,
but still sees the event's kind. Every assertion reads the SAME stored text, and the reveal
returning it whole is the control arm that proves the page had something to hide.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from _ui_clients import auth_service, cookie_login, provision, ui_client

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.pages._common import _seg

#: Stands in for an identifier the engine's scrubber missed.
_LOST = "peer refused frame for ZQX7"
_OTHER = "peer reset during ZQY8"
_ALERT = "delivery failed: partner refused ZQX7"


async def _seed(engine: Engine) -> tuple[int, int, int]:
    """Two events on inbound ``ch1`` (so the connection detail page lists them) and one alert."""
    for reason, ts in ((_LOST, 100.0), (_OTHER, 200.0)):
        await engine.store.record_connection_event(
            connection="ch1",
            transport="mllp",
            direction="inbound",
            kind="handler_error",
            peer_host="10.0.0.1",
            reason=reason,
            now=ts,
        )
    await engine.store.upsert_alert_instance(
        event_type="connection_error",
        connection="ch1",
        severity="critical",
        reason=_ALERT,
        now=100.0,
    )
    events = await engine.store.list_connection_events()
    lost = next(e.id for e in events if e.reason == _LOST)
    other = next(e.id for e in events if e.reason == _OTHER)
    (alert,) = await engine.store.list_active_alert_instances(limit=10)
    return lost, other, alert.id


async def _audits(engine: Engine, action: str) -> list[dict[str, Any]]:
    return [
        {"actor": dict(a)["actor"], **json.loads(dict(a)["detail"])}
        for a in await engine.store.list_audit(limit=200)
        if dict(a)["action"] == action
    ]


async def test_the_event_page_masks_each_reason_and_reveals_one_per_request(
    engine: Engine,
) -> None:
    lost, other, _alert = await _seed(engine)
    service = await auth_service(engine)
    await provision(service, "op", ["operator"])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        bare = await c.get("/ui/events", params={"kind": "handler_error"})
        assert bare.status_code == 200
        assert _LOST not in bare.text and _OTHER not in bare.text and "****" in bare.text
        # The link carries the page's filter back, escaped as a query value.
        assert f'href="/ui/events/{lost}/reason?kind=handler_error"' in bare.text

        shown = await c.get(f"/ui/events/{lost}/reason", params={"kind": "handler_error"})
        assert shown.status_code == 200
        assert _LOST in shown.text  # the control arm: the stored text comes back whole
        assert _OTHER not in shown.text  # and only that one
        assert f"/ui/events/{other}/reason" in shown.text
        assert f"/ui/events/{lost}/reason" not in shown.text  # nothing left to reveal on it

        again = await c.get("/ui/events")
        assert _LOST not in again.text and _OTHER not in again.text
    assert await _audits(engine, "connection_event_reveal") == [
        {"actor": "op", "id": lost, "connection": "ch1", "revealed": ["reason"]}
    ]


def _register_ch1(engine: Engine, tmp_path: Path) -> str:
    """An inbound named ``ch1``, so the connection page has a row; returns its page path segment.

    Not started: the page reads the registry's rows and the stored events, not a live listener."""
    (tmp_path / "ch1").mkdir()
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "ch1",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "ch1")}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    engine.add_registry(reg)
    return _seg("ch1 ▸ in")


async def test_the_connection_page_masks_each_reason_and_reveals_one_per_request(
    engine: Engine, tmp_path: Path
) -> None:
    lost, other, _alert = await _seed(engine)
    name = _register_ch1(engine, tmp_path)
    service = await auth_service(engine)
    await provision(service, "op", ["operator"])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        bare = await c.get(f"/ui/connection/{name}")
        assert bare.status_code == 200, bare.text
        assert _LOST not in bare.text and "****" in bare.text
        assert f'href="/ui/connection/{name}/events/{lost}/reason"' in bare.text

        shown = await c.get(f"/ui/connection/{name}/events/{lost}/reason")
        assert shown.status_code == 200
        assert _LOST in shown.text and _OTHER not in shown.text

        again = await c.get(f"/ui/connection/{name}")
        assert _LOST not in again.text
    assert [a["id"] for a in await _audits(engine, "connection_event_reveal")] == [lost]


async def test_the_alert_page_masks_each_reason_and_reveals_one_per_request(
    engine: Engine,
) -> None:
    _lost, _other, alert = await _seed(engine)
    service = await auth_service(engine)
    await provision(service, "op", ["operator"])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        bare = await c.get("/ui/alerts")
        assert bare.status_code == 200
        assert _ALERT not in bare.text and "****" in bare.text
        assert f'href="/ui/alerts/{alert}/reason"' in bare.text

        shown = await c.get(f"/ui/alerts/{alert}/reason")
        assert shown.status_code == 200 and _ALERT in shown.text

        again = await c.get("/ui/alerts")
        assert _ALERT not in again.text
    assert await _audits(engine, "alert_reveal") == [
        {"actor": "op", "id": alert, "connection": "ch1", "revealed": ["reason"]}
    ]


async def test_a_role_without_view_summary_sees_the_kind_and_no_reason_or_link(
    engine: Engine, tmp_path: Path
) -> None:
    """Viewer and Auditor hold ``monitoring:read`` without ``messages:view_summary``. The operator
    arm of the three tests above is the control that the same rows render a link at all."""
    lost, _other, _alert = await _seed(engine)
    name = _register_ch1(engine, tmp_path)
    service = await auth_service(engine)
    await provision(service, "vw", ["viewer"])
    await provision(service, "au", ["auditor"])
    for user in ("vw", "au"):
        async with ui_client(engine, service) as c:
            await cookie_login(c, user)
            for page in ("/ui/events", f"/ui/connection/{name}"):
                r = await c.get(page)
                assert r.status_code == 200, (user, page)
                assert "handler_error" in r.text, (user, page)  # the kind stays visible
                assert _LOST not in r.text and "****" not in r.text, (user, page)
                assert "/reason" not in r.text, (user, page)
            refused = await c.get(f"/ui/events/{lost}/reason")
            assert refused.status_code == 403, user
            assert _LOST not in refused.text
    assert await _audits(engine, "connection_event_reveal") == []
