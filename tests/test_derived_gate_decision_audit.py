# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A derived gate writes its grant row only once its own checks pass (BACKLOG #1197, ASVS 16.3.2).

Each JSON gate built on ``require()`` adds checks of its own: pacing, the new-address question, a
step-up. Before this fix each called ``require()``'s dependency first, which had already written
``auth.permission_granted``, so a request those checks then refused kept a grant row and got no
denial row. Each case below drives one such refusal through a probe route mounted on the gate, and
asserts that the refused request left no grant row and one ``auth.gate_refused`` row naming the
permission and the reason. Where a case has a request the gate admits first, that request is the
positive control: it leaves one grant row and no refusal row.
"""

from __future__ import annotations

import ast
import inspect
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request

from messagefoundry.api import create_app
from messagefoundry.api.security import (
    _GateRefusal,
    _mfa_refusal,
    _recorded_decision,
    require_paced,
    require_phi_read,
    require_reauth_only,
    require_reauth_only_action,
    require_step_up,
    require_step_up_action,
)
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.service import (
    STEP_UP_ACTION_ADMIN_USER_UPDATE,
    STEP_UP_ACTION_SESSION_TERMINATE,
    AuthService,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms, satisfies the ASVS policy (WP-3)
_PROBE = "/test/derived-gate-probe"
_HOME = "10.0.0.1"
_AWAY = "10.9.9.9"
_GRANTED = "auth.permission_granted"
_REFUSED = "auth.gate_refused"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "derived-gate.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    """One administrator; one paced write and one PHI read per window; the new-address check on.

    ``require_mfa`` is off so the base gate's factor refusal does not answer first, and the minimum
    write interval is off so the second write is refused by the count alone."""
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_new_ip_step_up=True,
            admin_write_min_interval_seconds=0,
            admin_write_rate_limit_per_actor=1,
            phi_read_rate_limit_per_actor=1,
        ),
    )
    await service.initialize()
    user_id = await create_local_user_chosen(
        service,
        username="boss",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
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
    return service


def _app(
    engine: Engine,
    service: AuthService,
    gate: Callable[[Request], Any],
    method: str,
    **app_kwargs: Any,
) -> FastAPI:
    app = create_app(engine, auth=service, **app_kwargs)
    dependency = Depends(gate)

    async def probe(_: Identity = dependency) -> dict[str, str]:
        return {"ok": "1"}

    app.add_api_route(_PROBE, probe, methods=[method])
    return app


def _client(app: FastAPI, ip: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, 12345)), base_url="http://t"
    )


async def _login(app: FastAPI) -> str:
    async with _client(app, _HOME) as c:
        r = await c.post(
            "/auth/login", json={"username": "boss", "password": PW, "provider": "local"}
        )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _call(app: FastAPI, method: str, token: str, ip: str) -> httpx.Response:
    async with _client(app, ip) as c:
        return await c.request(method, _PROBE, headers={"Authorization": f"Bearer {token}"})


async def _decisions(engine: Engine) -> list[tuple[str, dict[str, Any], str | None]]:
    """``(action, detail, client)`` of every grant and gate-refusal row on the probe path, oldest
    first."""
    rows = sorted(await engine.store.list_audit(limit=1000), key=lambda row: int(row["id"]))
    out = []
    for row in rows:
        if row["action"] not in {_GRANTED, _REFUSED}:
            continue
        detail = json.loads(str(row["detail"] or "{}"))
        if detail.get("path") == _PROBE:
            assert row["actor"] == "boss", row
            out.append((str(row["action"]), detail, row["client"]))
    return out


@dataclass(frozen=True)
class _Case:
    gate: Callable[[Permission], Callable[[Request], Any]]
    permission: Permission
    method: str
    #: ``throttled``: the first request, from the sign-in address, is admitted (the positive
    #: control) and spends the one-request budget, so the second, from the same address, gets 429.
    #: ``step_up``: the only request, from ``refused_from``, gets the step-up 403.
    reason: str
    refused_from: str = _HOME


_PACED, _PHI_READ, _STEP_UP = require_paced, require_phi_read, require_step_up
_CONTROL, _READ, _MANAGE = (
    Permission.CONNECTIONS_CONTROL,
    Permission.MESSAGES_READ,
    Permission.USERS_MANAGE,
)

#: At least one case per derived gate in ``api/security.py`` that called ``require()`` before its
#: own checks. ``require_step_up_action`` has two branches, so it has two cases. A ``no proof``
#: case mints no proof bound to the action, so the gate refuses from the sign-in address.
_CASES = {
    "require_paced, throttled": _Case(_PACED, _CONTROL, "POST", "throttled"),
    "require_paced, new address": _Case(_PACED, _CONTROL, "POST", "step_up", _AWAY),
    "require_phi_read, throttled": _Case(_PHI_READ, _READ, "GET", "throttled"),
    "require_phi_read, new address": _Case(_PHI_READ, _READ, "GET", "step_up", _AWAY),
    "require_step_up, throttled": _Case(_STEP_UP, _MANAGE, "POST", "throttled"),
    "require_step_up, new address": _Case(_STEP_UP, _MANAGE, "POST", "step_up", _AWAY),
    "require_reauth_only, new address": _Case(
        require_reauth_only, _MANAGE, "POST", "step_up", _AWAY
    ),
    "require_step_up_action, no proof": _Case(
        lambda p: require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE, p),
        _MANAGE,
        "POST",
        "step_up",
    ),
    "require_step_up_action proof_in_route, new address": _Case(
        lambda p: require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE, p, proof_in_route=True),
        _MANAGE,
        "POST",
        "step_up",
        _AWAY,
    ),
    "require_reauth_only_action, no proof": _Case(
        lambda p: require_reauth_only_action(STEP_UP_ACTION_SESSION_TERMINATE, p),
        _MANAGE,
        "POST",
        "step_up",
    ),
}


@pytest.mark.parametrize("name", sorted(_CASES))
async def test_a_refused_request_leaves_a_refusal_row_and_no_grant_row(
    engine: Engine, name: str
) -> None:
    """RED when: a derived gate writes its grant row before its own checks again, or its refusal
    writes no ``auth.gate_refused`` row. Mutation: restore the gate's ``await base(request)`` and
    the refused request leaves a grant row."""
    case = _CASES[name]
    service = await _service(engine)
    app = _app(engine, service, case.gate(case.permission), case.method)
    token = await _login(app)
    permission = case.permission.value

    expected: list[tuple[str, dict[str, Any], str | None]] = []
    if case.reason == "throttled":
        admitted = await _call(app, case.method, token, _HOME)
        assert admitted.status_code == 200, (name, admitted.text)
        expected.append((_GRANTED, {"permission": permission, "path": _PROBE}, _HOME))
        assert await _decisions(engine) == expected, "the admitted request is the positive control"

    refused = await _call(app, case.method, token, case.refused_from)
    assert refused.status_code == (429 if case.reason == "throttled" else 403), (name, refused.text)
    expected.append(
        (
            _REFUSED,
            {"permission": permission, "path": _PROBE, "reason": case.reason},
            case.refused_from,
        )
    )
    assert await _decisions(engine) == expected, name


async def test_a_gate_that_writes_no_grant_row_writes_no_refusal_row(engine: Engine) -> None:
    """The refusal row takes the grant row's place and adds none: a PHI-view grant writes no grant
    row, so its throttled read writes no refusal row. That refusal keeps only its WARNING line, a
    gap this test records rather than closes. The control is the same throttle on
    ``messages:read``, which does write one."""
    service = await _service(engine)
    app = _app(engine, service, require_phi_read(Permission.MESSAGES_VIEW_RAW), "GET")
    token = await _login(app)
    assert (await _call(app, "GET", token, _HOME)).status_code == 200
    assert (await _call(app, "GET", token, _HOME)).status_code == 429
    assert await _decisions(engine) == []

    control = _app(engine, service, require_phi_read(Permission.MESSAGES_READ), "GET")
    assert (await _call(control, "GET", token, _HOME)).status_code == 429
    assert [action for action, _detail, _client in await _decisions(engine)] == [_REFUSED]


async def test_the_narrowed_trail_writes_no_refusal_row_for_a_read(engine: Engine) -> None:
    """With ``audit_all_authz`` off a GET writes no grant row, so its refusal writes no refusal row.
    The control is a refused POST on the same app, which the narrowed trail still records."""
    service = await _service(engine)
    read = _app(
        engine, service, require_phi_read(Permission.MESSAGES_READ), "GET", audit_all_authz=False
    )
    token = await _login(read)
    assert (await _call(read, "GET", token, _AWAY)).status_code == 403
    assert await _decisions(engine) == []

    write = _app(
        engine, service, require_step_up(Permission.USERS_MANAGE), "POST", audit_all_authz=False
    )
    assert (await _call(write, "POST", token, _AWAY)).status_code == 403
    assert [action for action, _detail, _client in await _decisions(engine)] == [_REFUSED]


async def test_require_step_up_action_records_its_throttle_too(engine: Engine) -> None:
    """``require_step_up_action`` charges the write budget before it asks for the proof, so with no
    proof minted the first write is the step-up refusal and the second, over budget, the throttle.
    Each leaves its own refusal row and neither a grant row."""
    service = await _service(engine)
    gate = require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE, Permission.USERS_MANAGE)
    app = _app(engine, service, gate, "POST")
    token = await _login(app)
    assert (await _call(app, "POST", token, _HOME)).status_code == 403
    assert (await _call(app, "POST", token, _HOME)).status_code == 429
    reasons = [(action, detail.get("reason")) for action, detail, _ in await _decisions(engine)]
    assert reasons == [(_REFUSED, "step_up"), (_REFUSED, "throttled")]


#: The calls in a derived gate that can refuse a request or spend something on it. Each must run
#: inside the gate's ``_recorded_decision`` block, or the grant row is written before it decides.
_GATE_CHECKS = frozenset(
    {
        "_enforce_admin_write_pacing",
        "enforce_phi_read_pacing",
        "refuse_from_new_address",
        "_step_up_refusal",
        "_mfa_refusal",
        "_action_step_up_ok",
    }
)


def _names_called(node: ast.AST) -> list[str]:
    return [
        n.func.id if isinstance(n.func, ast.Name) else n.func.attr
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name | ast.Attribute)
    ]


def test_every_gate_that_runs_admit_decides_inside_its_decision_block() -> None:
    """RED when: a gate factory calls ``_admit`` with no ``_recorded_decision`` block, so it writes
    no grant row for the requests it admits, or makes one of its own checks outside that block, so
    the grant row is written before that check decides. ``require`` is the one factory that writes
    its grant directly. The counts are the positive control: the walk found the six gates, and a
    check in each."""
    from messagefoundry.api import security

    tree = ast.parse(inspect.getsource(security))
    gates = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name not in {"_admit", "require"}
        and "_admit" in _names_called(node)
    ]
    assert len(gates) == 6, sorted(g.name for g in gates)
    for gate in gates:
        blocks = [
            node
            for node in ast.walk(gate)
            if isinstance(node, ast.AsyncWith)
            and any("_recorded_decision" in _names_called(item.context_expr) for item in node.items)
        ]
        assert len(blocks) == 1, (gate.name, len(blocks))
        inside = [name for stmt in blocks[0].body for name in _names_called(stmt)]
        everywhere = _names_called(gate)
        checks = [name for name in everywhere if name in _GATE_CHECKS]
        assert checks, gate.name
        assert sorted(checks) == sorted(name for name in inside if name in _GATE_CHECKS), (
            f"{gate.name} makes a check outside its _recorded_decision block"
        )


class _Recorder:
    """Stands in for :class:`AuthService`: records which decision row was asked for."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def audit_permission_granted(self, *_: object, **__: object) -> None:
        self.calls.append(_GRANTED)

    async def audit_mfa_denied(self, *_: object, **__: object) -> None:
        self.calls.append("auth.mfa_denied")

    async def audit_gate_refused(self, *_: object, **__: object) -> None:
        self.calls.append(_REFUSED)


def _post_request() -> Request:
    app = FastAPI()
    app.state.audit_all_authz = True
    scope = {
        "type": "http",
        "method": "POST",
        "path": _PROBE,
        "headers": [],
        "query_string": b"",
        "client": (_HOME, 1),
        "app": app,
    }
    return Request(scope)


async def test_only_a_refusal_with_a_reason_writes_a_gate_refusal_row() -> None:
    """The second-factor refusal writes ``auth.mfa_denied`` where it is raised (``_mfa_refusal``),
    and the decision block writes no second row for it, as for any refusal that is not a
    ``_GateRefusal``.
    The control is a step-up refusal through the same block, which does write one. A derived
    gate's own factor check is reached only past ``_admit``'s, which refuses the same sessions
    first, so this is driven on the block directly."""
    identity: Any = object()  # the recorder never reads it
    recorder = _Recorder()
    auth: Any = recorder
    request = _post_request()
    for make, rows in (
        (lambda: _mfa_refusal(request, auth, identity), ["auth.mfa_denied"]),
        (lambda: _as_coro(HTTPException(403, "refused")), []),
        (lambda: _as_coro(_GateRefusal(403, "refused", reason="step_up")), [_REFUSED]),
    ):
        recorder.calls.clear()
        with pytest.raises(HTTPException):
            async with _recorded_decision(request, auth, identity, (Permission.USERS_MANAGE,)):
                raise await make()
        assert recorder.calls == rows, rows


async def _as_coro(refusal: HTTPException) -> HTTPException:
    return refusal


def test_a_gate_refusal_survives_copy_and_pickle_with_its_reason() -> None:
    """An ``HTTPException`` copies and pickles; the subclass must too, reason included."""
    import copy
    import pickle

    refusal = _GateRefusal(429, "slow down", reason="throttled", headers={"Retry-After": "3"})
    for clone in (copy.copy(refusal), pickle.loads(pickle.dumps(refusal))):
        assert isinstance(clone, _GateRefusal)
        assert (clone.status_code, clone.detail, clone.reason, clone.headers) == (
            429,
            "slow down",
            "throttled",
            {"Retry-After": "3"},
        )
