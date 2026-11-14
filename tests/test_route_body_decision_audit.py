# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A refusal a route body makes after its gate admitted the request leaves exactly one decision
row, the refusal (BACKLOG #1197 steps 1 to 3, ASVS 16.3.2).

``spend_step_up_action``, ``refuse_unless_step_up_window_live`` and ``_admit_reveal`` refuse in the
route body. Their gate used to have written ``auth.permission_granted`` already, so a request they
refused kept a grant row and no refusal row. The gate now defers its decision to the body, which
records one ``auth.gate_refused`` row naming the gate's permission and the reason, or the grant
row once its check passes. Each refusal case is paired with a control that the same check admits
and that leaves exactly one grant row.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request

from messagefoundry.api import create_app
from messagefoundry.api.security import (
    refuse_unless_step_up_window_live,
    require_step_up_action,
    spend_step_up_action,
)
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.service import STEP_UP_ACTION_ADMIN_USER_UPDATE, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen
from tests._bound_proof import prove

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms, satisfies the ASVS policy (WP-3)
_SPEND = "/test/route-body-spend"
_WINDOW = "/test/route-body-window"
_REVEAL = "/alerts/active"
_HOME = "10.0.0.1"
_AWAY = "10.9.9.9"
_GRANTED = "auth.permission_granted"
_REFUSED = "auth.gate_refused"
_ACTION = STEP_UP_ACTION_ADMIN_USER_UPDATE
_MANAGE = Permission.USERS_MANAGE.value


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "route-body-decision.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _app(engine: Engine) -> FastAPI:
    """One administrator; one PHI read per window, and no minimum gap between writes, so only the
    checks under test refuse; the new-address check on; and two probe routes
    on a ``proof_in_route`` gate, one spending the proof and one checking only the window."""
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_new_ip_step_up=True,
            admin_write_min_interval_seconds=0,
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
    app = create_app(engine, auth=service)
    gate = Depends(require_step_up_action(_ACTION, Permission.USERS_MANAGE, proof_in_route=True))

    async def spend(request: Request, skip: bool = False, _: Identity = gate) -> dict[str, str]:
        if skip:
            # A refusal that is not the gate's, before the spend: the gate's grant stands.
            raise HTTPException(404, "no such thing")
        await spend_step_up_action(request, _ACTION)
        return {"ok": "1"}

    async def window(request: Request, _: Identity = gate) -> dict[str, str]:
        await refuse_unless_step_up_window_live(request)
        return {"ok": "1"}

    app.add_api_route(_SPEND, spend, methods=["POST"])
    app.add_api_route(_WINDOW, window, methods=["POST"])
    return app


def _client(app: FastAPI, ip: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, 12345)), base_url="http://t"
    )


async def _login(c: httpx.AsyncClient) -> str:
    r = await c.post("/auth/login", json={"username": "boss", "password": PW, "provider": "local"})
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _decisions(engine: Engine, path: str) -> list[tuple[str, dict[str, Any]]]:
    """``(action, detail)`` of every decision row on ``path``, oldest first: the grant and the
    gate-refusal rows, and the denials, so a second row of any of them shows up."""
    rows = sorted(await engine.store.list_audit(limit=1000), key=lambda row: int(row["id"]))
    out = []
    for row in rows:
        if row["action"] not in {_GRANTED, _REFUSED, "auth.permission_denied", "auth.mfa_denied"}:
            continue
        detail = json.loads(str(row["detail"] or "{}"))
        if detail.get("path") == path:
            out.append((str(row["action"]), detail))
    return out


def _refused(permission: str, path: str, reason: str) -> tuple[str, dict[str, Any]]:
    return (_REFUSED, {"permission": permission, "path": path, "reason": reason})


def _granted(permission: str, path: str) -> tuple[str, dict[str, Any]]:
    return (_GRANTED, {"permission": permission, "path": path})


async def test_a_refused_spend_leaves_one_refusal_row(engine: Engine) -> None:
    """Step 1. RED when: ``spend_step_up_action`` refuses after its ``proof_in_route`` gate wrote
    the grant row, as on ``origin/main``. The control spends a proof bound to the action and leaves
    one grant row."""
    app = await _app(engine)
    async with _client(app, _HOME) as c:
        token = await _login(c)
        r = await c.post(_SPEND, headers=_auth(token))
        assert (r.status_code, r.headers.get("X-Step-Up-Action")) == (403, _ACTION), r.text
        assert await _decisions(engine, _SPEND) == [_refused(_MANAGE, _SPEND, "step_up")]

        token = await prove(c, token, PW, _ACTION)
        r = await c.post(_SPEND, headers=_auth(token))
        assert r.status_code == 200, r.text
    assert await _decisions(engine, _SPEND) == [
        _refused(_MANAGE, _SPEND, "step_up"),
        _granted(_MANAGE, _SPEND),
    ]


async def test_a_route_that_never_reaches_its_spend_still_records_the_grant(
    engine: Engine,
) -> None:
    """The gate's deferred grant is written after the endpoint when the body never decides, as on a
    dual-control rejoin or a 404 before the spend. RED when: that settling step is lost, and such a
    request leaves no decision row at all."""
    app = await _app(engine)
    async with _client(app, _HOME) as c:
        token = await _login(c)
        r = await c.post(_SPEND, params={"skip": "true"}, headers=_auth(token))
        assert r.status_code == 404, r.text
    assert await _decisions(engine, _SPEND) == [_granted(_MANAGE, _SPEND)]


async def test_a_lapsed_window_leaves_one_refusal_row(engine: Engine) -> None:
    """Step 2. RED when: ``refuse_unless_step_up_window_live`` refuses after the gate wrote the
    grant row. The control is the same caller after a plain re-proof, with one grant row."""
    app = await _app(engine)
    async with _client(app, _HOME) as c:
        token = await _login(c)
        await engine.store.mark_session_reauthed(hash_token(token), now=0.0)  # lapse the window
        r = await c.post(_WINDOW, headers=_auth(token))
        assert r.status_code == 403, r.text
        assert "X-Step-Up-Action" not in r.headers
        assert await _decisions(engine, _WINDOW) == [_refused(_MANAGE, _WINDOW, "step_up")]

        r = await c.post("/me/reauth", json={"password": PW}, headers=_auth(token))
        assert r.status_code == 200, r.text
        r = await c.post(_WINDOW, headers=_auth(str(r.json()["token"])))
        assert r.status_code == 200, r.text
    assert await _decisions(engine, _WINDOW) == [
        _refused(_MANAGE, _WINDOW, "step_up"),
        _granted(_MANAGE, _WINDOW),
    ]


async def test_a_reveal_from_a_new_address_leaves_one_refusal_row(engine: Engine) -> None:
    """Step 3, the new-address refusal. RED when: ``_admit_reveal`` refuses after the route's
    ``monitoring:diagnose`` gate wrote the grant row. The row names that gate's permission. The
    control is the same reveal from the sign-in address, with one grant row."""
    app = await _app(engine)
    diagnose = Permission.MONITORING_DIAGNOSE.value
    async with _client(app, _HOME) as c:
        token = await _login(c)
    async with _client(app, _AWAY) as away:
        r = await away.get(_REVEAL, params={"reveal": 1}, headers=_auth(token))
        assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), r.text
    assert await _decisions(engine, _REVEAL) == [_refused(diagnose, _REVEAL, "step_up")]
    async with _client(app, _HOME) as c:
        assert (await c.get(_REVEAL, params={"reveal": 1}, headers=_auth(token))).status_code == 200
    assert await _decisions(engine, _REVEAL) == [
        _refused(diagnose, _REVEAL, "step_up"),
        _granted(diagnose, _REVEAL),
    ]


async def test_a_reveal_over_the_phi_budget_leaves_one_refusal_row(engine: Engine) -> None:
    """Step 3, the PHI-budget refusal. The first reveal spends the one-read budget and is the
    control, with one grant row; the second gets 429 and one refusal row. A request with no reveal
    is not charged, and leaves one grant row too."""
    app = await _app(engine)
    diagnose = Permission.MONITORING_DIAGNOSE.value
    async with _client(app, _HOME) as c:
        token = await _login(c)
        assert (await c.get(_REVEAL, params={"reveal": 1}, headers=_auth(token))).status_code == 200
        r = await c.get(_REVEAL, params={"reveal": 1}, headers=_auth(token))
        assert r.status_code == 429, r.text
        assert (await c.get(_REVEAL, headers=_auth(token))).status_code == 200
    assert await _decisions(engine, _REVEAL) == [
        _granted(diagnose, _REVEAL),
        _refused(diagnose, _REVEAL, "throttled"),
        _granted(diagnose, _REVEAL),
    ]
