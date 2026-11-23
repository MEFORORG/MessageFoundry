# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-actor pacing on six monitoring:read GETs (vault BACKLOG #1191, ASVS 15.2.2).

Driven through the real routes, so a route that drops back to plain ``require`` goes red here. The
six paced routes, their key and the default's basis are stated in docs/SECURITY.md,
*Monitoring-read pacing*.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
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


def _client(engine: Engine, service: AuthService, *, serve_ui: bool = False) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service, serve_ui=serve_ui), client=("127.0.0.1", 123)
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


async def test_an_out_of_scope_reveal_is_denied_and_audited_with_the_budget_spent(
    engine: Engine,
) -> None:
    """As on main, the scope check and its ``auth.channel_denied`` row come before the monitoring
    pace: an account whose budget is spent still gets the channel denial for an out-of-scope
    reveal, not a 429 that hides the probe."""
    service = await _service(engine, monitoring_read_rate_limit_per_actor=1)
    scoped = await service.store.get_user_by_username("vw")
    assert scoped is not None
    await service.set_channel_scope(scoped.id, ["IB_MINE"], actor="test")
    async with _client(engine, service) as c:
        h = await _bearer(c, "vw")
        assert (await c.get("/status", headers=h)).status_code == 200
        assert (await c.get("/status", headers=h)).status_code == 429  # the budget is spent
        denied = await c.get("/connections", params={"reveal": "IB_THEIRS"}, headers=h)
        assert denied.status_code == 403, denied.text
        # An in-scope reveal past the budget is still paced.
        paced = await c.get("/connections", params={"reveal": "IB_MINE"}, headers=h)
        assert paced.status_code == 429
        assert int(paced.headers["Retry-After"]) >= 1
    rows = await engine.store.list_audit(limit=1000)
    denials = [
        json.loads(str(row["detail"] or "{}"))
        for row in rows
        if row["action"] == "auth.channel_denied"
    ]
    assert any("IB_THEIRS" in json.dumps(d) for d in denials), denials
    # The in-scope reveal's 429, charged in the route body, still writes its throttled row.
    refused = [
        json.loads(str(row["detail"] or "{}"))
        for row in rows
        if row["action"] == "auth.gate_refused"
    ]
    assert any(d.get("path") == "/connections" and d.get("reason") == "throttled" for d in refused)


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
        # ``/ui/nav-status`` the ``GET /status`` one, though it answers 200 even if that call
        # fails). The bearer reads below are what prove none of them spent the budget.
        for path in ("/ui/connections", "/ui/monitoring/live", "/ui/nav-status"):
            for _ in range(3):
                assert (await c.get(path)).status_code == 200, path
        # The same account's budget of 1 is still whole: one bearer read is admitted, the next
        # is refused, so the pace itself is live.
        h = await _bearer(c, "vw")
        assert (await c.get("/status", headers=h)).status_code == 200
        assert (await c.get("/status", headers=h)).status_code == 429
