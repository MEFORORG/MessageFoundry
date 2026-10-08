# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2625 with #2445: a repeat of an open purge or reload rejoins its hold without a proof.

Purge and reload take a single-use step-up proof bound to their action (#2625). Under dual control
a repeat of the requester's own open request files nothing and answers the same 202 (#2445). When
the proof was spent before the gate looked for the open request, a retry got a re-auth 403 instead
of its hold id. The two main tests run with both controls on, the proof as shipped and dual control
as an operator enables it. They pin for each action that:

* a first request without a proof is refused, and with one it is held (202);
* a repeat with no new proof gets the same hold id;
* a rejoin spends no proof, even one the repeat brought;
* a different request with no proof is refused, and holds nothing new;
* another requester's identical request is their own, so it needs its own proof.

The rest pin that the gate still applies to a proof-free repeat (a live window, the new-address
check, the opt-out), that a purge repeat is refused once the purge would be, and, by reading the
source, what each route may do before its spend.
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
    # The default is the shipped one. Only the opt-out test passes False.
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


async def _never(*_args: object, **_kwargs: object) -> bool:
    return False


async def _always(*_args: object, **_kwargs: object) -> bool:
    return True


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

        # A rejoin spends nothing, even a proof the repeat brought: it still opens the next request.
        token = await _reauth(c, token, action)
        rejoined = await c.post("/connections/OB/purge", headers=_auth(token))
        assert rejoined.status_code == 202 and rejoined.json()["approval_id"] == held
        assert await _repeat_rows(engine) == 2
        top = await c.post("/connections/OB/purge?scope=top", headers=_auth(token))
        assert top.status_code == 202, top.text
        assert top.json()["approval_id"] != held
        assert await _pending_ids(c, admin) == sorted([held, str(top.json()["approval_id"])])

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
        rejoined = await c.post("/config/reload", json={}, headers=_auth(token))
        assert rejoined.status_code == 202 and rejoined.json()["approval_id"] == held
        assert await _repeat_rows(engine) == 2
        second = await c.post("/config/reload", json=named, headers=_auth(token))
        assert second.status_code == 202, second.text
        assert second.json()["approval_id"] != held
        assert await _pending_ids(c, admin) == sorted([held, str(second.json()["approval_id"])])


@pytest.mark.parametrize("require_action_step_up", [True, False], ids=["bound", "opt_out"])
async def test_a_proof_free_repeat_needs_a_live_window(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, require_action_step_up: bool
) -> None:
    """The rejoin skips the proof, never the window: a lapsed session goes to the step-up."""
    service = await _service(engine, require_action_step_up=require_action_step_up)
    await _add(service, "deployer", ["administrator"])
    action = STEP_UP_ACTION_CONFIG_RELOAD
    async with _client(engine, service) as c:
        token = await _login(c, "deployer")  # a local login opens the window
        if require_action_step_up:
            token = await _reauth(c, token, action)
        first = await c.post("/config/reload", json={}, headers=_auth(token))
        assert first.status_code == 202, first.text
        again = await c.post("/config/reload", json={}, headers=_auth(token))
        assert (
            again.status_code == 202 and again.json()["approval_id"] == first.json()["approval_id"]
        )

        monkeypatch.setattr(service, "has_recent_step_up", _never)
        stale = await c.post("/config/reload", json={}, headers=_auth(token))
        assert _refused_for(stale, action), stale.text
        assert await _repeat_rows(engine) == 1


async def test_a_proof_free_repeat_from_a_new_address_is_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    await _add(service, "deployer", ["administrator"])
    action = STEP_UP_ACTION_CONFIG_RELOAD
    async with _client(engine, service) as c:
        token = await _reauth(c, await _login(c, "deployer"), action)
        first = await c.post("/config/reload", json={}, headers=_auth(token))
        assert first.status_code == 202, first.text

        monkeypatch.setattr(service, "flag_new_client_ip", _always)
        again = await c.post("/config/reload", json={}, headers=_auth(token))
        assert _refused_for(again, action), again.text
        assert await _repeat_rows(engine) == 0


def _proof_in_route_routes() -> dict[str, ast.AsyncFunctionDef]:
    """Every function in ``api/app.py`` with a parameter default that calls
    ``require_step_up_action(..., proof_in_route=True)``, by name. It reads parameter defaults in
    that one module, which is where every JSON route declares its gate today."""
    app_py = Path(__file__).resolve().parents[1] / "messagefoundry" / "api" / "app.py"
    found: dict[str, ast.AsyncFunctionDef] = {}
    for node in ast.walk(ast.parse(app_py.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is None:
                continue
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


def _called_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                names.add(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                names.add(n.func.attr)
    return names


#: What a ``proof_in_route`` route may call before its spend: reads, the rejoin and its reply.
#: Nothing here holds a new request or runs the operation.
_BEFORE_THE_SPEND = frozenset(
    {
        "_purge_in_scope",
        "_purge_target_refusal",
        "_purge_hold_params",
        "_reload_hold_params",
        "_rejoin_without_proof",
        "_held_reply",
    }
)


def test_each_proof_in_route_route_spends_before_it_holds_or_runs_anything() -> None:
    """``proof_in_route=True`` leaves the step-up to the route. A route that held or ran anything
    before its spend would do so with no proof, while every gate-classifying guard still reads it
    as action-bound. So the spend must be a top-level statement of the body, every call before it
    must be on :data:`_BEFORE_THE_SPEND`, and every return before it must be ``_held_reply``."""
    routes = _proof_in_route_routes()
    # Positive control: the walk finds the two routes vault BACKLOG #2625 moved, by name.
    assert set(routes) == {"purge_connection", "reload_config"}, sorted(routes)
    for name, func in routes.items():
        spend_at = next(
            (
                i
                for i, stmt in enumerate(func.body)
                if "spend_step_up_action" in _called_names(stmt)
            ),
            None,
        )
        assert spend_at is not None, f"{name} never calls spend_step_up_action"
        spend_stmt = func.body[spend_at]
        assert isinstance(spend_stmt, ast.Expr) and isinstance(spend_stmt.value, ast.Await), (
            f"{name}: the spend must be a plain top-level await, not inside a branch"
        )
        before = func.body[:spend_at]
        called = set().union(*(_called_names(stmt) for stmt in before)) if before else set()
        assert called <= _BEFORE_THE_SPEND, (
            f"{name} calls {sorted(called - _BEFORE_THE_SPEND)} before its spend"
        )
        for stmt in before:
            for ret in (n for n in ast.walk(stmt) if isinstance(n, ast.Return)):
                assert (
                    isinstance(ret.value, ast.Call)
                    and isinstance(ret.value.func, ast.Name)
                    and ret.value.func.id == "_held_reply"
                ), f"{name} returns something other than a rejoined hold before its spend"
