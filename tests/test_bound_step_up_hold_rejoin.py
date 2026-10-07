# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2625 with #2445: a repeat of an open purge or reload rejoins its hold without a proof.

Purge and reload take a single-use step-up proof bound to their action (#2625). Under dual control
a repeat of the requester's own open request files nothing and answers the same 202 (#2445). When
the proof was spent before the gate looked for the open request, a retry got a re-auth 403 instead
of its hold id. These tests run with BOTH controls on, as shipped for the proof and as an
operator enables dual control, and pin for each action that:

* a first request without a proof is refused, and with one it is held (202);
* a repeat with no new proof gets the same hold id;
* a repeat that brings a proof spends it and still gets the same hold id;
* a different request with no proof is refused, and holds nothing new;
* another requester's identical request is their own, so it needs its own proof.

They also pin that the rest of the gate still applies to a proof-free repeat (the opt-out's window,
the new-address check), that a purge repeat is refused once the purge would be, and, by reading the
source, that each route spends its proof before any return other than a rejoin.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.service import (
    STEP_UP_ACTION_CONFIG_RELOAD,
    STEP_UP_ACTION_CONNECTION_PURGE,
    AuthService,
)
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings, EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from tests.test_bound_step_up_injection import _add, _login, _reauth, _refused_for
from tests.test_dual_control_reload import _write_valid_config

# min_dwell_seconds=0 is irrelevant here (nothing is released) and kept only to match the siblings.
GATED = ApprovalsSettings(
    enabled=True, operations=["connection_purge", "config_reload"], min_dwell_seconds=0.0
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "cfg_in", tmp_path / "cfg_out")
    eng = await Engine.create(
        tmp_path / "rejoin.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine, *, require_action_step_up: bool = True) -> AuthService:
    # require_action_step_up is pinned ON, the shipped default, because it is half of the subject.
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            require_action_step_up=require_action_step_up,
        ),
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, approvals=GATED)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _pending_ids(c: httpx.AsyncClient, admin: str) -> list[str]:
    r = await c.get("/approvals", headers=_auth(admin))
    assert r.status_code == 200, r.text
    return sorted(str(p["id"]) for p in r.json()["approvals"] if p["status"] == "pending")


async def _repeat_rows(engine: Engine) -> int:
    return len(await engine.store.list_audit(action="approval.request_repeated"))


async def _quiesced_outbound(engine: Engine, tmp_path: Path) -> None:
    """A started graph whose outbound ``OB`` is stopped and quiesced, so a purge passes its 409."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    (tmp_path / "out").mkdir()
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB", m))
    engine.add_registry(reg)
    await engine.start()
    rr = engine.registry_runner
    assert rr is not None
    await rr.stop_outbound("OB")
    for _ in range(200):
        if rr.outbound_quiesced("OB"):
            break
        await asyncio.sleep(0.02)
    assert rr.outbound_quiesced("OB") is True


async def test_a_repeated_purge_rejoins_its_hold_without_a_new_proof(
    engine: Engine, tmp_path: Path
) -> None:
    await _quiesced_outbound(engine, tmp_path)
    service = await _service(engine)
    await _add(service, "op", ["operator"])
    await _add(service, "other", ["operator"])
    await _add(service, "admin", ["administrator"])
    action = STEP_UP_ACTION_CONNECTION_PURGE
    async with _client(engine, service) as c:
        admin = await _login(c, "admin")
        token = await _login(c, "op")
        # A first purge needs the proof.
        refused = await c.post("/connections/OB/purge", headers=_auth(token))
        assert _refused_for(refused, action), refused.text
        assert await _pending_ids(c, admin) == []

        token = await _reauth(c, token, action)
        first = await c.post("/connections/OB/purge", headers=_auth(token))
        assert first.status_code == 202, first.text
        held = str(first.json()["approval_id"])
        assert first.json()["operation"] == "connection_purge"

        # The repeat carries no proof (the first one is spent) and still gets the same hold.
        again = await c.post("/connections/OB/purge", headers=_auth(token))
        assert again.status_code == 202, again.text
        assert again.json()["approval_id"] == held
        assert await _repeat_rows(engine) == 1
        assert await _pending_ids(c, admin) == [held]

        # A different purge (another scope) is a new request, so it needs a proof of its own.
        other = await c.post("/connections/OB/purge?scope=top", headers=_auth(token))
        assert _refused_for(other, action), other.text
        assert await _pending_ids(c, admin) == [held]

        # Another requester's identical purge is theirs, never folded into op's hold.
        theirs = await c.post("/connections/OB/purge", headers=_auth(await _login(c, "other")))
        assert _refused_for(theirs, action), theirs.text
        assert await _pending_ids(c, admin) == [held]

        # A repeat that brings a proof spends it, so it cannot open a different purge afterwards.
        token = await _reauth(c, token, action)
        paid = await c.post("/connections/OB/purge", headers=_auth(token))
        assert paid.status_code == 202 and paid.json()["approval_id"] == held
        assert await _repeat_rows(engine) == 2
        top = await c.post("/connections/OB/purge?scope=top", headers=_auth(token))
        assert _refused_for(top, action), top.text
        assert await _pending_ids(c, admin) == [held]

        # Once the purge would be refused, a repeat is refused too, never told it is still held.
        rr = engine.registry_runner
        assert rr is not None
        await rr.start_outbound("OB")
        assert rr.outbound_quiesced("OB") is False
        doomed = await c.post("/connections/OB/purge", headers=_auth(token))
        assert _refused_for(doomed, action), doomed.text
        token = await _reauth(c, token, action)
        doomed = await c.post("/connections/OB/purge", headers=_auth(token))
        assert doomed.status_code == 409, doomed.text
        assert await _repeat_rows(engine) == 2


async def test_a_repeated_reload_rejoins_its_hold_without_a_new_proof(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", ["administrator"])
    await _add(service, "other", ["administrator"])
    await _add(service, "admin", ["administrator"])
    action = STEP_UP_ACTION_CONFIG_RELOAD
    cfg = engine.config_dir
    assert cfg is not None
    async with _client(engine, service) as c:
        admin = await _login(c, "admin")
        token = await _login(c, "deployer")
        refused = await c.post("/config/reload", json={}, headers=_auth(token))
        assert _refused_for(refused, action), refused.text
        assert await _pending_ids(c, admin) == []

        token = await _reauth(c, token, action)
        first = await c.post("/config/reload", json={}, headers=_auth(token))
        assert first.status_code == 202, first.text
        held = str(first.json()["approval_id"])
        assert first.json()["operation"] == "config_reload"

        again = await c.post("/config/reload", json={}, headers=_auth(token))
        assert again.status_code == 202, again.text
        assert again.json()["approval_id"] == held
        assert await _repeat_rows(engine) == 1
        assert await _pending_ids(c, admin) == [held]

        # Naming the directory captures different params, so this is a new reload.
        named = {"config_dir": str(cfg)}
        other = await c.post("/config/reload", json=named, headers=_auth(token))
        assert _refused_for(other, action), other.text
        assert await _pending_ids(c, admin) == [held]

        theirs = await c.post("/config/reload", json={}, headers=_auth(await _login(c, "other")))
        assert _refused_for(theirs, action), theirs.text
        assert await _pending_ids(c, admin) == [held]

        token = await _reauth(c, token, action)
        paid = await c.post("/config/reload", json={}, headers=_auth(token))
        assert paid.status_code == 202 and paid.json()["approval_id"] == held
        assert await _repeat_rows(engine) == 2
        second = await c.post("/config/reload", json=named, headers=_auth(token))
        assert _refused_for(second, action), second.text
        assert await _pending_ids(c, admin) == [held]


async def test_a_proof_free_repeat_still_meets_the_rest_of_the_gate(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rejoin skips the proof and nothing else: a repeat from a new address is refused."""
    service = await _service(engine)
    await _add(service, "deployer", ["administrator"])
    action = STEP_UP_ACTION_CONFIG_RELOAD
    async with _client(engine, service) as c:
        token = await _reauth(c, await _login(c, "deployer"), action)
        first = await c.post("/config/reload", json={}, headers=_auth(token))
        assert first.status_code == 202, first.text

        async def _new_address(*_args: object, **_kwargs: object) -> bool:
            return True

        monkeypatch.setattr(service, "flag_new_client_ip", _new_address)
        again = await c.post("/config/reload", json={}, headers=_auth(token))
        assert _refused_for(again, action), again.text
        assert await _repeat_rows(engine) == 0


async def test_under_the_opt_out_a_repeat_still_needs_a_live_window(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no grant to spend, the window is the whole step-up, and reading it spends nothing."""
    service = await _service(engine, require_action_step_up=False)
    await _add(service, "deployer", ["administrator"])
    async with _client(engine, service) as c:
        token = await _login(c, "deployer")  # a local login opens the window
        first = await c.post("/config/reload", json={}, headers=_auth(token))
        assert first.status_code == 202, first.text
        held = first.json()["approval_id"]
        again = await c.post("/config/reload", json={}, headers=_auth(token))
        assert again.status_code == 202 and again.json()["approval_id"] == held

        async def _stale(*_args: object, **_kwargs: object) -> bool:
            return False

        monkeypatch.setattr(service, "has_recent_step_up", _stale)
        stale = await c.post("/config/reload", json={}, headers=_auth(token))
        assert stale.status_code == 403, stale.text
        assert stale.headers.get("X-Step-Up-Required") == "1"
        assert await _repeat_rows(engine) == 1


def _proof_in_route_routes() -> dict[str, ast.AsyncFunctionDef]:
    """Every route function in ``api/app.py`` whose gate is ``require_step_up_action(...,
    proof_in_route=True)``, by name."""
    app_py = Path(__file__).resolve().parents[1] / "messagefoundry" / "api" / "app.py"
    found: dict[str, ast.AsyncFunctionDef] = {}
    for node in ast.walk(ast.parse(app_py.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for default in node.args.defaults:
            for call in ast.walk(default):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "require_step_up_action"
                    and any(
                        k.arg == "proof_in_route"
                        and isinstance(k.value, ast.Constant)
                        and k.value.value is True
                        for k in call.keywords
                    )
                ):
                    found[node.name] = node
    return found


def _calls(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name
        for n in ast.walk(node)
    )


def test_each_proof_in_route_route_spends_before_it_returns_anything_but_a_rejoin() -> None:
    """``proof_in_route=True`` leaves the pop to the route, so a route that returns before its
    spend, other than with a rejoined hold, would run with no proof while every gate-classifying
    guard still reads it as action-bound. The spend must be a top-level statement of the body,
    and every return before it must be ``_held_reply``."""
    routes = _proof_in_route_routes()
    # Positive control: the walk finds the two routes vault BACKLOG #2625 moved, by name.
    assert set(routes) == {"purge_connection", "reload_config"}, sorted(routes)
    for name, func in routes.items():
        spend_at = next(
            (i for i, stmt in enumerate(func.body) if _calls(stmt, "spend_step_up_action")), None
        )
        assert spend_at is not None, f"{name} never calls spend_step_up_action"
        spend_stmt = func.body[spend_at]
        assert isinstance(spend_stmt, ast.Expr) and isinstance(spend_stmt.value, ast.Await), (
            f"{name}: the spend must be a plain top-level await, not inside a branch"
        )
        for stmt in func.body[:spend_at]:
            for ret in (n for n in ast.walk(stmt) if isinstance(n, ast.Return)):
                assert (
                    isinstance(ret.value, ast.Call)
                    and isinstance(ret.value.func, ast.Name)
                    and ret.value.func.id == "_held_reply"
                ), f"{name} returns something other than a rejoined hold before its spend"
