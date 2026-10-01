# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2443 (ASVS 14.2.6, owner ruling R12): the connection-event and alert reasons.

A delivery failure copies its ``safe_exc()`` text into a ``connection_lost`` event's reason and a
``connection_error`` alert's reason. Those routes need only ``monitoring:*``, so the reason is gated
on ``messages:view_summary`` and masked for a holder until a per-item ``reveal=<id>`` act. These
tests pin both halves over the real JSON routes, with a control arm for each: the reveal must
return the stored text (so a mask test cannot pass on a fixture with nothing to hide), and a
reveal of one item must leave its sibling masked (so a reveal cannot pass by unmasking everything).

Step 4 of the item adds ``ConnectionRow.error`` on ``GET /connections``, why a connection failed to
start, revealed per connection name with ``reveal=<name>``. The same two control arms apply.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.field_authz import redact_unauthorized
from messagefoundry.api.models import AlertInstanceInfo, ConnectionRow
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


async def _add(
    service: AuthService, username: str, role: Role, *, scope: list[str] | None = None
) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[role.value],
        actor="test",
    )
    # ``is not None``, not ``or``: an empty scope denies every channel (BACKLOG #1152).
    await service.set_channel_scope(
        user_id, scope if scope is not None else [ALL_CHANNELS], actor="test"
    )
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


# --- BACKLOG #2443 step 4: the connections dashboard's ``error`` ----------------------------------
#
# ``ConnectionRow.error`` says why a connection failed to start: ``safe_exc()`` text, on a route that
# needs only ``monitoring:read``. Two outbounds that cannot build give two failed rows, so a reveal
# of one has a sibling that must stay masked.


def _broken_outbound(name: str) -> Any:
    """An outbound whose ``env()`` cannot resolve, so it fails to build (ADR 0031)."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, build_outbound_connection, env

    return build_outbound_connection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": env(f"{name}_dir"), "filename": "{MSH-10}.hl7"}
        ),
    )


@pytest.fixture
async def dash(tmp_path: Path) -> AsyncIterator[Engine]:
    from messagefoundry.config.wiring import Registry

    eng = await Engine.create(tmp_path / "dash.db", poll_interval=0.02)
    try:
        from messagefoundry.config.models import ConnectorType
        from messagefoundry.config.wiring import (
            ConnectionSpec,
            build_inbound_connection,
            env,
        )

        reg = Registry()
        reg.add_outbound(_broken_outbound("OB_A"))
        reg.add_outbound(_broken_outbound("OB_B"))
        # A failed INBOUND too, so a channel-scoped caller has one in-scope connection to reveal.
        reg.add_inbound(
            build_inbound_connection(
                "IB_MINE",
                ConnectionSpec(
                    ConnectorType.FILE, {"directory": env("IB_MINE_dir"), "pattern": "*.hl7"}
                ),
                router="r",
            )
        )
        reg.add_router("r", lambda m: [])
        eng.add_registry(reg)
        await eng.start()  # degraded on both outbounds; does NOT raise (ADR 0031)
        yield eng
    finally:
        await eng.stop()


def _failed_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The destination rows, keyed by outbound name rather than by the masked error."""
    return {r["destination"]: r for r in rows if r["role"] == "destination"}


async def test_a_holder_gets_the_connection_error_masked_until_one_audited_reveal(
    dash: Engine,
) -> None:
    rr = dash.registry_runner
    assert rr is not None
    stored = rr.outbound_failed("OB_A")
    assert stored, "the fixture's outbound did not fail, so there is nothing to mask"
    service = await _service(dash)
    await _add(service, "op", Role.OPERATOR)
    async with _client(dash, service) as c:
        h = await _login(c, "op")
        bare = _failed_rows((await c.get("/connections", headers=h)).json())
        assert bare["OB_A"]["error"] == "****" and bare["OB_B"]["error"] == "****"
        assert bare["OB_A"]["status"] == "failed"  # THAT it failed is never masked

        shown = _failed_rows(
            (await c.get("/connections", params={"reveal": "OB_A"}, headers=h)).json()
        )
        # The control arm: the reveal returns the engine's own reason, so the mask hid something.
        assert shown["OB_A"]["error"] == stored
        # And it is per connection: the sibling stays masked.
        assert shown["OB_B"]["error"] == "****"

        # A reveal is an act, not a status: the next bare load is masked again.
        again = _failed_rows((await c.get("/connections", headers=h)).json())
        assert again["OB_A"]["error"] == "****"
    assert await _reveal_audits(dash, "connection_error_reveal") == [
        {
            "actor": "op",
            "channel": "OB_A",
            "reveal": "OB_A",
            "connection": "OB_A",
            "directions": ["out"],
            "revealed": ["error"],
        }
    ]


@pytest.mark.parametrize("role", [Role.VIEWER, Role.DEPLOYMENT, Role.CODING, Role.AUDITOR])
async def test_a_monitoring_only_role_gets_no_connection_error_but_sees_the_failure(
    dash: Engine, role: Role
) -> None:
    service = await _service(dash)
    await _add(service, "mon", role)
    async with _client(dash, service) as c:
        h = await _login(c, "mon")
        rows = _failed_rows((await c.get("/connections", headers=h)).json())
        assert rows["OB_A"]["error"] is None and rows["OB_B"]["error"] is None
        assert rows["OB_A"]["status"] == "failed"
        refused = await c.get("/connections", params={"reveal": "OB_A"}, headers=h)
        assert refused.status_code == 403
    assert await _reveal_audits(dash, "connection_error_reveal") == []
    denials = [
        json.loads(dict(a)["detail"])
        for a in await dash.store.list_audit(limit=200)
        if dict(a)["action"] == "auth.permission_denied" and dict(a)["actor"] == "mon"
    ]
    assert {"path": "/connections", "permission": "messages:view_summary"} in denials


async def test_a_connection_reveal_charges_the_phi_read_budget_and_a_bare_load_does_not(
    dash: Engine,
) -> None:
    service = await _service(dash, phi_read_rate_limit_per_actor=1)
    await _add(service, "op", Role.OPERATOR)
    async with _client(dash, service) as c:
        h = await _login(c, "op")
        for _ in range(3):
            assert (await c.get("/connections", headers=h)).status_code == 200
        ok = await c.get("/connections", params={"reveal": "OB_A"}, headers=h)
        assert ok.status_code == 200
        throttled = await c.get("/connections", params={"reveal": "OB_A"}, headers=h)
        assert throttled.status_code == 429


async def test_a_reveal_of_a_name_not_on_the_dashboard_is_audited_as_revealing_nothing(
    dash: Engine,
) -> None:
    """The audit records what the response carried, not what was asked for."""
    service = await _service(dash)
    await _add(service, "op", Role.OPERATOR)
    async with _client(dash, service) as c:
        h = await _login(c, "op")
        rows = _failed_rows(
            (await c.get("/connections", params={"reveal": "OB_NOPE"}, headers=h)).json()
        )
        assert rows["OB_A"]["error"] == "****" and rows["OB_B"]["error"] == "****"
    assert await _reveal_audits(dash, "connection_error_reveal") == [
        {
            "actor": "op",
            "channel": None,
            "reveal": "OB_NOPE",
            "connection": None,
            "directions": [],
            "revealed": [],
        }
    ]


async def test_a_scoped_caller_revealing_a_connection_outside_its_scope_is_refused(
    dash: Engine,
) -> None:
    """As on ``GET /connections/{name}/events``: an out-of-scope name is a channel denial, refused
    and audited as one, never answered as a reveal of nothing. The control is the same caller's
    reveal of its OWN failed inbound, which succeeds, so the guard is not refusing every scoped
    reveal."""
    rr = dash.registry_runner
    assert rr is not None
    stored = rr.inbound_failed("IB_MINE")
    assert stored, "the fixture's inbound did not fail, so the control arm has nothing to reveal"
    service = await _service(dash)
    await _add(service, "scoped", Role.OPERATOR, scope=["IB_MINE"])
    async with _client(dash, service) as c:
        h = await _login(c, "scoped")
        refused = await c.get("/connections", params={"reveal": "OB_A"}, headers=h)
        assert refused.status_code == 403
        own = await c.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
        assert own.status_code == 200
        (mine,) = [r for r in own.json() if r["role"] == "source"]
        assert mine["channel_id"] == "IB_MINE" and mine["error"] == stored
    audits = [dict(a) for a in await dash.store.list_audit(limit=200)]
    assert [a["channel_id"] for a in audits if a["action"] == "auth.channel_denied"] == ["OB_A"]
    assert [a["reveal"] for a in await _reveal_audits(dash, "connection_error_reveal")] == [
        "IB_MINE"
    ]


async def test_the_stats_socket_pushes_the_dashboard_rows_masked(dash: Engine) -> None:
    """``/ws/stats`` hands the console's renderer the same rows as ``GET /connections``. The renderer
    reads no ``error`` today, so the rows must arrive redacted rather than rely on that."""
    from tests.test_ws_stats_revalidation import (
        _HARNESS_TIMEOUT,
        _wait_for_first_frame,
        _WSHarness,
    )

    service = await _service(dash)
    await _add(service, "op", Role.OPERATOR)
    token = (await service.login("op", PW)).token
    assert token is not None
    app = create_app(dash, auth=service)
    seen: list[ConnectionRow] = []

    def render(rows: list[ConnectionRow]) -> str:
        seen.extend(rows)
        return ""

    app.state.ui_connections_render = render
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=_HARNESS_TIMEOUT))
    try:
        await _wait_for_first_frame(harness, task)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    errors = {r.destination: r.error for r in seen if r.role == "destination"}
    assert errors.get("OB_A") == "****" and errors.get("OB_B") == "****", errors


def _source_row(name: str, status: str, error: str | None) -> ConnectionRow:
    return ConnectionRow(
        role="source",
        channel_id=name,
        channel_name=name,
        destination=None,
        name=f"{name} in",
        status=status,
        direction="in",
        method="MLLP",
        peer=None,
        port=None,
        queue_depth=None,
        idle_seconds=None,
        alerts_active=0,
        errored=0,
        read=0,
        written=None,
        backlog_seconds=None,
        delivered_age_seconds=None,
        error=error,
    )


def test_the_multishard_attribution_finds_a_failed_lane_by_status_and_reveals_its_reason() -> None:
    """The load harness explains a ``reads == 0`` run with each failed lane's reason. With the error
    null (a caller without ``messages:view_summary``), the lane must still be found by its status,
    and its reason must come from a per-lane reveal. The running lane is the control: no reveal."""
    from harness.load.multishard import _lane_failed, _reveal_failed_reasons

    masked = [_source_row("IB_E0_A", "failed", None), _source_row("IB_E0_B", "running", None)]
    calls: list[str | None] = []

    class _Client:
        def connections(self, *, reveal: str | None = None) -> list[ConnectionRow]:
            calls.append(reveal)
            reason = "bind refused on port 2575" if reveal == "IB_E0_A" else None
            return [_source_row("IB_E0_A", "failed", reason), masked[1]]

    assert _lane_failed(masked[0]) and not _lane_failed(masked[1])
    reasons = _reveal_failed_reasons(cast(Any, _Client()), masked)
    assert reasons == {"IB_E0_A": "bind refused on port 2575"}
    assert calls == ["IB_E0_A"]


@pytest.mark.parametrize("may_reveal", [True, False])
def test_the_multishard_attribution_keeps_a_failed_lane_whose_error_is_withheld(
    monkeypatch: pytest.MonkeyPatch, may_reveal: bool
) -> None:
    """End to end through ``_attribute_engines_sync``. A caller without ``messages:view_summary``
    sees ``error`` null and has its reveal refused; the failed lane must still be reported, with a
    placeholder, and the refusal must stop further reveals. A caller that may reveal gets the
    engine's reason. The running lane is the control in both arms: it is never reported."""
    import messagefoundry.apiclient as apiclient
    from harness.load.multishard import _attribute_engines_sync

    calls: list[str | None] = []

    class _Client:
        def __init__(self, url: str, *, cacert: object = None) -> None:
            del url, cacert

        def connections(self, *, reveal: str | None = None) -> list[ConnectionRow]:
            calls.append(reveal)
            if reveal is not None and not may_reveal:
                raise apiclient.ApiError("forbidden", status=403)
            error = "****" if may_reveal else None
            rows = [
                _source_row("IB_E0_A", "failed", error),
                _source_row("IB_E0_B", "failed", error),
                _source_row("IB_E0_C", "running", None),
            ]
            if reveal is not None:
                rows = [
                    _source_row(r.channel_id, r.status, f"bind refused for {r.channel_id}")
                    if r.channel_id == reveal
                    else r
                    for r in rows
                ]
            return rows

        def close(self) -> None:
            pass

    monkeypatch.setattr(apiclient, "EngineClient", _Client)
    node = cast(Any, type("Node", (), {"url": "https://n", "cacert": None, "node_id": "n0"})())
    (attribution,) = _attribute_engines_sync([node])
    if may_reveal:
        assert attribution.failed_lanes == (
            "IB_E0_A in: bind refused for IB_E0_A",
            "IB_E0_B in: bind refused for IB_E0_B",
        )
        assert calls == [None, "IB_E0_A", "IB_E0_B"]
    else:
        assert attribution.failed_lanes == (
            "IB_E0_A in: (reason withheld)",
            "IB_E0_B in: (reason withheld)",
        )
        assert calls == [None, "IB_E0_A"]  # the first refusal stops the rest


# --- The same error for ONE connection: GET /connections/{name}/metadata ------------------------


async def test_a_holder_gets_the_metadata_error_masked_until_an_audited_reveal(
    dash: Engine,
) -> None:
    """The metadata route names one connection in its path, so its reveal is ``reveal=true``. The
    control arm: the reveal returns the runner's own reason, so the mask hid something. The sibling
    connection's metadata, opened bare after it, is still masked."""
    rr = dash.registry_runner
    assert rr is not None
    stored = rr.outbound_failed("OB_A")
    assert stored
    service = await _service(dash)
    await _add(service, "op", Role.OPERATOR)
    async with _client(dash, service) as c:
        h = await _login(c, "op")
        bare = (await c.get("/connections/OB_A/metadata", headers=h)).json()
        assert bare["error"] == "****"
        assert bare["direction"] == "out" and bare["name"] == "OB_A"  # never masked
        shown = await c.get("/connections/OB_A/metadata", params={"reveal": "true"}, headers=h)
        assert shown.status_code == 200 and shown.json()["error"] == stored
        sibling = (await c.get("/connections/OB_B/metadata", headers=h)).json()
        assert sibling["error"] == "****"
        again = (await c.get("/connections/OB_A/metadata", headers=h)).json()
        assert again["error"] == "****"
    assert await _reveal_audits(dash, "connection_error_reveal") == [
        {
            "actor": "op",
            "channel": "OB_A",
            "reveal": "OB_A",
            "connection": "OB_A",
            "directions": ["out"],
            "revealed": ["error"],
        }
    ]


@pytest.mark.parametrize("role", [Role.VIEWER, Role.DEPLOYMENT, Role.CODING, Role.AUDITOR])
async def test_a_monitoring_only_role_gets_no_metadata_error_and_its_reveal_is_refused(
    dash: Engine, role: Role
) -> None:
    service = await _service(dash)
    await _add(service, "mon", role)
    async with _client(dash, service) as c:
        h = await _login(c, "mon")
        bare = (await c.get("/connections/OB_A/metadata", headers=h)).json()
        assert bare["error"] is None and bare["name"] == "OB_A"
        refused = await c.get("/connections/OB_A/metadata", params={"reveal": "true"}, headers=h)
        assert refused.status_code == 403
    assert await _reveal_audits(dash, "connection_error_reveal") == []
    denials = [
        json.loads(dict(a)["detail"])
        for a in await dash.store.list_audit(limit=200)
        if dict(a)["action"] == "auth.permission_denied" and dict(a)["actor"] == "mon"
    ]
    assert {"path": "/connections/OB_A/metadata", "permission": "messages:view_summary"} in denials


async def test_a_metadata_reveal_charges_the_phi_read_budget_and_a_bare_open_does_not(
    dash: Engine,
) -> None:
    service = await _service(dash, phi_read_rate_limit_per_actor=1)
    await _add(service, "op", Role.OPERATOR)
    async with _client(dash, service) as c:
        h = await _login(c, "op")
        for _ in range(3):
            assert (await c.get("/connections/OB_A/metadata", headers=h)).status_code == 200
        reveal = {"reveal": "true"}
        ok = await c.get("/connections/OB_A/metadata", params=reveal, headers=h)
        assert ok.status_code == 200
        throttled = await c.get("/connections/OB_A/metadata", params=reveal, headers=h)
        assert throttled.status_code == 429


async def test_a_scoped_caller_revealing_its_own_inbound_metadata_succeeds(dash: Engine) -> None:
    """The scope check comes first and is unchanged: an outbound is refused to a scoped caller
    with no budget spent, and its own failed inbound reveals whole."""
    rr = dash.registry_runner
    assert rr is not None
    stored = rr.inbound_failed("IB_MINE")
    assert stored
    service = await _service(dash, phi_read_rate_limit_per_actor=1)
    await _add(service, "scoped", Role.OPERATOR, scope=["IB_MINE"])
    async with _client(dash, service) as c:
        h = await _login(c, "scoped")
        reveal = {"reveal": "true"}
        refused = await c.get("/connections/OB_A/metadata", params=reveal, headers=h)
        assert refused.status_code == 403
        # Budget of one, still unspent by the refusal above, so this reveal is admitted.
        own = await c.get("/connections/IB_MINE/metadata", params=reveal, headers=h)
        assert own.status_code == 200 and own.json()["error"] == stored
