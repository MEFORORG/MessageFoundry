# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-actor pacing on six monitoring:read GETs (vault BACKLOG #1191, ASVS 15.2.2).

Driven through the real routes, so a route that drops back to plain ``require`` goes red here. The
six paced routes, their key and the default's basis are stated in docs/SECURITY.md,
*Monitoring-read pacing*.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.config.tls_policy import HopDisposition
from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Row
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"

#: The routes docs/SECURITY.md names as paced.
PACED = ("/graph/edges", "/status", "/stats", "/metrics", "/metrics/history", "/connections")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "monitoring-pacing.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine, **overrides: object) -> AuthService:
    settings: dict[str, object] = {"require_mfa": False, "admin_new_ip_step_up": False}
    service = AuthService(engine.store, AuthSettings(**(settings | overrides)))  # type: ignore[arg-type]
    await service.initialize()
    for name in ("vw", "other"):
        user_id = await create_local_user_chosen(
            service,
            username=name,
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="test",
        )
        user = await service.store.get_user(user_id)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            user_id,
            password_hash=user.password_hash,
            must_change_password=False,
            password_generated=False,
        )
        await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    return service


def _client(
    engine: Engine, service: AuthService, *, serve_ui: bool = False, ip: str = "127.0.0.1"
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=serve_ui), client=(ip, 123)
    )
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _bearer(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_default_is_on_at_600_per_60_seconds_with_the_global_count_off() -> None:
    s = AuthSettings()
    assert s.monitoring_read_rate_limit_enabled is True
    assert s.monitoring_read_rate_limit_per_actor == 600
    assert s.monitoring_read_rate_limit_global == 0
    assert s.monitoring_read_rate_limit_window_seconds == 60.0


@pytest.mark.parametrize("path", PACED)
async def test_each_paced_route_admits_under_the_limit_and_refuses_over_it(
    engine: Engine, path: str
) -> None:
    service = await _service(engine, monitoring_read_rate_limit_per_actor=2)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        for _ in range(2):
            assert (await c.get(path, headers=h)).status_code == 200
        refused = await c.get(path, headers=h)
        assert refused.status_code == 429
        assert int(refused.headers["Retry-After"]) >= 1


async def test_the_six_routes_share_one_bucket_per_actor(engine: Engine) -> None:
    service = await _service(engine, monitoring_read_rate_limit_per_actor=len(PACED))
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        for path in PACED:
            assert (await c.get(path, headers=h)).status_code == 200, path
        assert (await c.get(PACED[0], headers=h)).status_code == 429
        # Another account keeps its own budget.
        assert (await c.get(PACED[0], headers=await _bearer(c, "other"))).status_code == 200


async def test_retry_after_is_the_actors_wait(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    service = await _service(
        engine,
        monitoring_read_rate_limit_per_actor=1,
        monitoring_read_rate_limit_window_seconds=37.5,
    )
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        assert (await c.get("/stats", headers=h)).status_code == 200  # t=1000
        clock[0] = 1020.0
        refused = await c.get("/stats", headers=h)  # the t=1000 read leaves at 1037.5
        assert (refused.status_code, refused.headers["Retry-After"]) == (429, "18")


async def test_a_refusal_writes_a_throttled_gate_record_and_no_grant(engine: Engine) -> None:
    service = await _service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        assert (await c.get("/metrics/history", headers=h)).status_code == 200
        assert (await c.get("/metrics/history", headers=h)).status_code == 429
    rows = sorted(await engine.store.list_audit(limit=1000), key=lambda row: int(row["id"]))
    decisions = [
        (str(row["action"]), json.loads(str(row["detail"] or "{}")))
        for row in rows
        if row["action"] in {"auth.permission_granted", "auth.gate_refused"}
    ]
    on_path = [(a, d) for a, d in decisions if d.get("path") == "/metrics/history"]
    assert [a for a, _ in on_path] == ["auth.permission_granted", "auth.gate_refused"], on_path
    assert on_path[1][1]["reason"] == "throttled"
    assert on_path[1][1]["permission"] == "monitoring:read"


async def test_an_unpaced_monitoring_route_is_unaffected(engine: Engine) -> None:
    service = await _service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        assert (await c.get("/stats", headers=h)).status_code == 200
        assert (await c.get("/stats", headers=h)).status_code == 429  # the budget is spent
        for _ in range(5):
            assert (await c.get("/security/posture", headers=h)).status_code == 200


async def test_disabled_knob_means_no_pacing(engine: Engine) -> None:
    service = await _service(
        engine, monitoring_read_rate_limit_enabled=False, monitoring_read_rate_limit_per_actor=1
    )
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        for _ in range(5):
            assert (await c.get("/status", headers=h)).status_code == 200


async def test_retry_after_is_the_whole_window_while_the_global_count_is_spent(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the all-accounts count spent, the value is the whole window, not the refused actor's
    own wait: that wait depends on other accounts' reads, which a caller must not read."""
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    service = await _service(
        engine,
        monitoring_read_rate_limit_per_actor=100,
        monitoring_read_rate_limit_global=1,
        monitoring_read_rate_limit_window_seconds=37.5,
    )
    async with _client(engine, service) as c:
        h_vw = await _bearer(c, "vw")
        h_other = await _bearer(c, "other")
        assert (await c.get("/stats", headers=h_vw)).status_code == 200  # t=1000, global full
        clock[0] = 1020.0
        # "other" has no reads of its own; the global read leaves at 1037.5 (17.5 s away), but
        # the header names the whole window.
        refused = await c.get("/stats", headers=h_other)
        assert (refused.status_code, refused.headers["Retry-After"]) == (429, "38")


def _decisions_on(rows: Sequence[Row], path: str) -> list[tuple[str, dict[str, object]]]:
    """The gate decision rows on ``path``, oldest first."""
    ordered = sorted(rows, key=lambda row: int(str(row["id"])))
    return [
        (str(row["action"]), json.loads(str(row["detail"] or "{}")))
        for row in ordered
        if row["action"] in {"auth.permission_granted", "auth.gate_refused"}
        and json.loads(str(row["detail"] or "{}")).get("path") == path
    ]


async def _scoped_service(engine: Engine, **overrides: object) -> AuthService:
    """``vw`` (Viewer) and ``op`` (Operator, so it holds ``messages:view_summary``), each scoped
    to ``IB_MINE``."""
    service = await _service(engine, **overrides)
    op_id = await create_local_user_chosen(
        service,
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    op = await service.store.get_user(op_id)
    assert op is not None and op.password_hash is not None
    await service.store.set_password(
        op_id, password_hash=op.password_hash, must_change_password=False, password_generated=False
    )
    for name in ("vw", "op"):
        user = await service.store.get_user_by_username(name)
        assert user is not None
        await service.set_channel_scope(user.id, ["IB_MINE"], actor="test")
    return service


def _actions(rows: Sequence[Row], action: str) -> list[dict[str, object]]:
    return [json.loads(str(row["detail"] or "{}")) for row in rows if row["action"] == action]


async def test_an_out_of_scope_reveal_is_denied_and_audited_with_the_budget_spent(
    engine: Engine,
) -> None:
    """The scope check's 403 and ``auth.channel_denied`` row come before the monitoring 429, as
    main's 403 and row came with no pace at all: an account whose budget is spent still gets the
    channel denial, not a 429 that hides the probe. An in-scope reveal past the budget is refused
    429, with one ``auth.gate_refused`` row and no grant row (BACKLOG #1197)."""
    service = await _scoped_service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service) as c:
        h = await _bearer(c, "op")
        assert (await c.get("/status", headers=h)).status_code == 200
        assert (await c.get("/status", headers=h)).status_code == 429  # the budget is spent
        denied = await c.get("/connections", params={"reveal": "IB_THEIRS"}, headers=h)
        assert denied.status_code == 403, denied.text
        paced = await c.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
        assert paced.status_code == 429
        assert int(paced.headers["Retry-After"]) >= 1
    rows = await engine.store.list_audit(limit=1000)
    assert any("IB_THEIRS" in json.dumps(d) for d in _actions(rows, "auth.channel_denied"))
    on_path = _decisions_on(rows, "/connections")
    # The out-of-scope reveal was answered, and recorded, as a channel denial; its held 429 was
    # never raised.
    assert [a for a, _ in on_path] == ["auth.gate_refused"], on_path
    assert {d["reason"] for _, d in on_path} == {"throttled"}


async def test_a_reveal_without_view_summary_is_denied_with_the_budget_spent(
    engine: Engine,
) -> None:
    """As before pacing, a reveal by a caller without ``messages:view_summary`` gets the 403 and its
    ``auth.permission_denied`` row, not a monitoring 429, even with the budget spent."""
    service = await _scoped_service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        assert (await c.get("/status", headers=h)).status_code == 200
        refused = await c.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"] == "a reveal needs messages:view_summary"
    rows = await engine.store.list_audit(limit=1000)
    assert any(
        d.get("permission") == "messages:view_summary"
        for d in _actions(rows, "auth.permission_denied")
    )


async def test_a_reveal_from_a_new_address_is_refused_for_it_with_the_budget_spent(
    engine: Engine,
) -> None:
    """With the budget spent, an in-scope reveal on a token replayed from a host the session has
    not verified from gets the new-address refusal (403 + ``X-Step-Up-Required``) and its
    ``auth.new_address_reverify_required`` row, not a 429 that hides it (vault BACKLOG #2620)."""
    service = await _scoped_service(
        engine, monitoring_read_rate_limit_per_actor=1, admin_new_ip_step_up=True
    )
    async with _client(engine, service, ip="10.0.0.1") as a:
        h = await _bearer(a, "op")
        assert (await a.get("/status", headers=h)).status_code == 200
        assert (await a.get("/status", headers=h)).status_code == 429  # the budget is spent
    async with _client(engine, service, ip="10.9.9.9") as b:
        # The second request from the same, already-flagged address gets no new-address row (it
        # is deduped), so the throttled row is the only record it leaves.
        for _ in range(2):
            r = await b.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
            assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), r.text
    rows = await engine.store.list_audit(limit=1000)
    assert [d.get("seen_ip") for d in _actions(rows, "auth.new_address_reverify_required")] == [
        "10.9.9.9"
    ]
    on_path = _decisions_on(rows, "/connections")
    # Each row keeps the throttle fact, and records what the caller was actually answered.
    assert [
        (a, d.get("reason"), d.get("answered_status"), d.get("answered_reason")) for a, d in on_path
    ] == [
        ("auth.gate_refused", "throttled", 403, "step_up"),
        ("auth.gate_refused", "throttled", 403, "step_up"),
    ], on_path


async def test_a_serve_hop_refusal_over_the_budget_writes_a_throttled_row(engine: Engine) -> None:
    """The serve-hop refusal writes no row of its own, so with the budget spent the held
    decision's throttled row is written before the 403 propagates, and no grant row."""
    service = await _scoped_service(engine, monitoring_read_rate_limit_per_actor=1)
    app = create_app(engine, auth=service)
    app.state.phi_read_hop_disposition = HopDisposition.REFUSE
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 123))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _bearer(c, "op")
        assert (await c.get("/status", headers=h)).status_code == 200
        refused = await c.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
        assert refused.status_code == 403, refused.text
        assert "PHI read refused" in refused.json()["detail"]
    rows = await engine.store.list_audit(limit=1000)
    on_path = _decisions_on(rows, "/connections")
    assert [
        (a, d.get("reason"), d.get("answered_status"), d.get("answered_reason")) for a, d in on_path
    ] == [("auth.gate_refused", "throttled", 403, "serve_hop")], on_path


async def test_an_invalid_reveal_over_the_budget_writes_a_decision_row(engine: Engine) -> None:
    """A reveal value that will fail validation is not deferred: over the budget it is refused 429
    at the gate with its ``auth.gate_refused`` row, so the request leaves a decision row, as the
    pre-pacing grant row did."""
    service = await _scoped_service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        invalid = await c.get("/connections", params={"reveal": ""}, headers=h)
        assert invalid.status_code == 422  # under the budget: charged, granted, then invalid
        again = await c.get("/connections", params={"reveal": ""}, headers=h)
        assert again.status_code == 429
    rows = await engine.store.list_audit(limit=1000)
    assert [a for a, _ in _decisions_on(rows, "/connections")] == [
        "auth.permission_granted",
        "auth.gate_refused",
    ]


async def test_an_out_of_scope_reveal_under_the_budget_spends_a_read(engine: Engine) -> None:
    """While the budget has room, a reveal the scope check denies spends a read like any other.
    The over-budget case is the out-of-scope test above."""
    service = await _scoped_service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        denied = await c.get("/connections", params={"reveal": "IB_THEIRS"}, headers=h)
        assert denied.status_code == 403
        assert (await c.get("/status", headers=h)).status_code == 429


async def test_an_in_scope_reveal_under_the_budget_is_charged_once(engine: Engine) -> None:
    service = await _scoped_service(engine, monitoring_read_rate_limit_per_actor=2)
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        # A Viewer passes the scope check and the pace, and is then refused by the reveal's own
        # permission check.
        passed = await c.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
        assert passed.status_code == 403
        assert passed.json()["detail"] == "a reveal needs messages:view_summary"
        # One read of the budget of 2 is left.
        assert (await c.get("/status", headers=h)).status_code == 200
        assert (await c.get("/status", headers=h)).status_code == 429


async def test_the_web_console_reads_are_not_charged(engine: Engine) -> None:
    """The console calls the paced handlers in process through ``require_ui``, so the route's own
    dependency never runs and the account's budget is untouched (docs/SECURITY.md, *Monitoring-read
    pacing*, *What it does not charge*)."""
    service = await _service(engine, monitoring_read_rate_limit_per_actor=1)
    async with _client(engine, service, serve_ui=True) as c:
        r = await c.post(
            "/ui/login",
            data={"username": "vw", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        # A failed sign-in also answers 303, so the session cookie is what proves it worked.
        assert r.status_code == 303 and c.cookies.get("mf_session"), r.status_code
        # Signed out, these pages answer 303; a 200 here means the signed-in handler ran. Each
        # calls a paced handler (``/ui/connections`` the ``GET /connections`` one,
        # ``/ui/monitoring/live`` the ``GET /graph/edges`` and ``/metrics/history`` ones,
        # ``/ui/nav-status`` the ``GET /status`` one; it swallows that call's other failures but
        # re-raises an HTTPException, so a charged 429 would show here). The bearer reads below
        # prove none of them spent the budget.
        for path in ("/ui/connections", "/ui/monitoring/live", "/ui/nav-status"):
            for _ in range(3):
                assert (await c.get(path)).status_code == 200, path
        # The same account's budget of 1 is still whole: one bearer read is admitted, the next
        # is refused, so the pace itself is live.
        h = await _bearer(c, "vw")
        assert (await c.get("/status", headers=h)).status_code == 200
        assert (await c.get("/status", headers=h)).status_code == 429
