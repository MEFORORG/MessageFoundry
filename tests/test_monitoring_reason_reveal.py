# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2443 (ASVS 14.2.6, owner ruling R12): the connection-event and alert reasons.

A delivery failure copies its ``safe_exc()`` text into a ``connection_lost`` event's reason and a
``connection_error`` alert's reason. Those routes need only ``monitoring:*``, so the reason is gated
on ``messages:view_summary`` and masked for a holder until a per-item ``reveal=<id>`` act. These
tests pin both halves over the real JSON routes, with a control arm for each: the reveal must
return the stored text (so a mask test cannot pass on a fixture with nothing to hide), and a
reveal of one item must leave its sibling masked (so a reveal cannot pass by unmasking everything).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.field_authz import redact_unauthorized
from messagefoundry.api.models import AlertInstanceInfo
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS, AuthProvider
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "Sup3rSecret!!"

#: Stands in for an identifier the engine's scrubber missed, which is the exposure R12 masks.
_LOST = "peer refused frame for ZQX7"
_OTHER = "peer reset during ZQY8"
_ALERT = "delivery failed: partner refused ZQX7"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "reason.db", poll_interval=0.02)
    await eng.store.record_connection_event(
        connection="OB_X",
        transport="mllp",
        direction="outbound",
        kind="connection_lost",
        message_id="m1",
        reason=_LOST,
        now=100.0,
    )
    await eng.store.record_connection_event(
        connection="OB_X",
        transport="mllp",
        direction="outbound",
        kind="connection_lost",
        message_id="m2",
        reason=_OTHER,
        now=200.0,
    )
    await eng.store.upsert_alert_instance(
        event_type="connection_error",
        connection="OB_X",
        severity="critical",
        reason=_ALERT,
        now=100.0,
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine, **settings: Any) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False, **settings))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, role: Role) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post("/auth/login", json={"username": username, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _by_reason_source(events: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The two seeded events, told apart by their message id rather than by the masked reason."""
    first = next(e for e in events if e["message_id"] == "m1")
    second = next(e for e in events if e["message_id"] == "m2")
    return first, second


async def _reveal_audits(engine: Engine, action: str) -> list[dict[str, Any]]:
    return [
        {
            "actor": dict(a)["actor"],
            "channel": dict(a)["channel_id"],
            **json.loads(dict(a)["detail"]),
        }
        for a in await engine.store.list_audit(limit=200)
        if dict(a)["action"] == action
    ]


@pytest.mark.parametrize("path", ["/events", "/connections/OB_X/events"])
async def test_a_holder_gets_the_event_reason_masked_until_one_audited_reveal(
    engine: Engine, path: str
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        bare = (await c.get(path, headers=h)).json()
        first, second = _by_reason_source(bare)
        assert first["reason"] == "****" and second["reason"] == "****"
        assert first["kind"] == "connection_lost"  # the kind is never masked

        revealed = (await c.get(path, params={"reveal": first["id"]}, headers=h)).json()
        r_first, r_second = _by_reason_source(revealed)
        # The control arm: the reveal returns the STORED text, so the fixture had something to hide.
        assert r_first["reason"] == _LOST
        # And it is per item: the sibling stays masked.
        assert r_second["reason"] == "****"

        # A reveal is an act, not a status: the next bare load is masked again.
        again = (await c.get(path, headers=h)).json()
        assert all(e["reason"] == "****" for e in again)
    audits = await _reveal_audits(engine, "connection_event_reveal")
    assert audits == [
        {
            "actor": "op",
            "channel": "OB_X",
            "id": first["id"],
            "connection": "OB_X",
            "revealed": ["reason"],
        }
    ]


@pytest.mark.parametrize("role", [Role.VIEWER, Role.DEPLOYMENT, Role.CODING, Role.AUDITOR])
async def test_a_monitoring_only_role_gets_no_reason_but_still_sees_the_event(
    engine: Engine, role: Role
) -> None:
    """The four built-in roles that hold ``monitoring:read`` without ``messages:view_summary``."""
    service = await _service(engine)
    await _add(service, "mon", role)
    async with _client(engine, service) as c:
        h = await _login(c, "mon")
        events = (await c.get("/events", headers=h)).json()
        first, second = _by_reason_source(events)
        assert first["reason"] is None and second["reason"] is None
        # THAT the connection went down, and what kind of event it was, stays visible.
        assert first["kind"] == "connection_lost" and first["connection"] == "OB_X"
        # A reveal is refused outright rather than answered with a silent null.
        refused = await c.get("/events", params={"reveal": first["id"]}, headers=h)
        assert refused.status_code == 403
    assert await _reveal_audits(engine, "connection_event_reveal") == []
    # The refusal is audited like every other permission refusal (ASVS 16.3.2).
    denials = [
        json.loads(dict(a)["detail"])
        for a in await engine.store.list_audit(limit=200)
        if dict(a)["action"] == "auth.permission_denied" and dict(a)["actor"] == "mon"
    ]
    assert {"path": "/events", "permission": "messages:view_summary"} in denials


async def test_a_json_reveal_charges_the_phi_read_budget_and_a_bare_load_does_not(
    engine: Engine,
) -> None:
    """A reveal is a PHI read, so it spends the per-actor budget. The bare loads before it are the
    control: were they charged too, the first reveal would already be refused."""
    service = await _service(engine, phi_read_rate_limit_per_actor=1)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        for _ in range(3):
            assert (await c.get("/events", headers=h)).status_code == 200
        first, _second = _by_reason_source((await c.get("/events", headers=h)).json())
        ok = await c.get("/events", params={"reveal": first["id"]}, headers=h)
        assert ok.status_code == 200
        throttled = await c.get("/events", params={"reveal": first["id"]}, headers=h)
        assert throttled.status_code == 429


async def test_a_holder_gets_the_alert_reason_masked_until_one_audited_reveal(
    engine: Engine,
) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        (alert,) = (await c.get("/alerts/active", headers=h)).json()["alerts"]
        assert alert["reason"] == "****"
        assert alert["event_type"] == "connection_error" and alert["status"] == "open"

        (shown,) = (
            await c.get("/alerts/active", params={"reveal": alert["id"]}, headers=h)
        ).json()["alerts"]
        assert shown["reason"] == _ALERT  # the control arm: the stored text comes back whole

        # Acknowledging is not reading: the mutation echo is masked too.
        acked = (await c.post(f"/alerts/{alert['id']}/ack", headers=h)).json()
        assert acked["status"] == "acknowledged" and acked["reason"] == "****"

        (again,) = (await c.get("/alerts/active", headers=h)).json()["alerts"]
        assert again["reason"] == "****"
    audits = await _reveal_audits(engine, "alert_reveal")
    assert audits == [
        {
            "actor": "op",
            "channel": "OB_X",
            "id": alert["id"],
            "connection": "OB_X",
            "revealed": ["reason"],
        }
    ]


async def test_a_reveal_of_an_id_not_on_the_page_is_audited_as_revealing_nothing(
    engine: Engine,
) -> None:
    """The audit records what the response carried, not what was asked for."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        h = await _login(c, "op")
        events = (await c.get("/events", params={"reveal": 999_999}, headers=h)).json()
        assert all(e["reason"] == "****" for e in events)
    assert await _reveal_audits(engine, "connection_event_reveal") == [
        {"actor": "op", "channel": None, "id": 999_999, "connection": None, "revealed": []}
    ]


def test_an_alert_reason_is_null_for_a_diagnose_holder_without_view_summary() -> None:
    """No built-in role holds ``monitoring:diagnose`` without ``messages:view_summary``, but a
    custom role can. The gate reads the permission, not the role, and the holder is the control."""
    info = AlertInstanceInfo(
        id=1,
        event_type="connection_error",
        connection="OB_X",
        severity="critical",
        status="open",
        first_seen=0.0,
        last_seen=0.0,
        count=1,
        reason=_ALERT,
    )

    def _as(*perms: Permission) -> Identity:
        return Identity(
            user_id="u",
            username="u",
            auth_provider=AuthProvider.LOCAL,
            roles=frozenset(),
            permissions=frozenset(perms),
        )

    assert redact_unauthorized(info, _as(Permission.MONITORING_DIAGNOSE)).reason is None
    holder = _as(Permission.MONITORING_DIAGNOSE, Permission.MESSAGES_VIEW_SUMMARY)
    assert redact_unauthorized(info, holder).reason == "****"
    assert redact_unauthorized(info, holder, revealed=frozenset({"reason"})).reason == _ALERT
