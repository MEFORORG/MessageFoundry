# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0215 slice 2, first half: the engine-side prerequisites the web console's sub-requests read.

At least these: the gate-only ``GET /auth/check`` routes, one per permission plus a bare one; the
read-only step-up status route ``GET /me/step-up``; the must-change refusal's
``X-Password-Change-Next`` header; and the step-up refusal's ``X-Step-Up-Reason`` header. Every
check is made on the JSON plane with a bearer token, as a bearer client would make it. Synthetic
accounts only.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.api import create_app, security
from messagefoundry.api.auth_models import (
    MUST_CHANGE_NEXT_ENROL_FACTOR,
    MUST_CHANGE_NEXT_HEADER,
    MUST_CHANGE_NEXT_ROTATE,
    MUST_CHANGE_NEXT_VERIFY_FACTOR,
    STEP_UP_REASON_HEADER,
    STEP_UP_REASON_NEW_ADDRESS,
    STEP_UP_REASON_REVERIFY,
)
from messagefoundry.auth import BUILTIN_ROLE_PERMISSIONS, Permission, Role
from messagefoundry.auth.service import STEP_UP_ACTION_CONFIG_RELOAD, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_admin
from tests.test_mfa_access_gate import PW, _add, _enroll_totp_out_of_band

_GRANTED = "auth.permission_granted"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "gate_check.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine, **overrides: object) -> AuthService:
    settings = AuthSettings(
        mfa_verify_min_elapsed_seconds=0,
        admin_write_min_interval_seconds=0,
        login_rate_limit_enabled=False,
        require_mfa=False,
        **overrides,  # type: ignore[arg-type]
    )
    service = AuthService(engine.store, settings)
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, *, peer: tuple[str, int] = ("127.0.0.1", 123)
) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=peer)
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(c: httpx.AsyncClient, username: str, password: str = PW) -> str:
    r = await c.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


# --- GET /auth/check and GET /auth/check/<permission> ----------------------------------------------


async def test_the_bare_check_route_admits_a_session_and_refuses_none(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    async with _client(engine, service) as c:
        assert (await c.get("/auth/check")).status_code == 401
        tok = await _login(c, "vic")
        r = await c.get("/auth/check", headers=_auth(tok))
        assert r.status_code == 200, r.text


async def test_each_permission_has_a_check_route_gated_on_that_permission(engine: Engine) -> None:
    """A viewer is admitted on exactly the check routes for the permissions its role holds, and
    refused, naming the permission, on every other one. A route missing for a permission answers
    404, which fails both arms."""
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    held = BUILTIN_ROLE_PERMISSIONS[Role.VIEWER]
    assert held and set(Permission) - held, "the viewer role must hold some and lack some"
    async with _client(engine, service) as c:
        tok = await _login(c, "vic")
        for permission in Permission:
            r = await c.get(f"/auth/check/{permission.value}", headers=_auth(tok))
            if permission in held:
                assert r.status_code == 200, (permission, r.text)
            else:
                assert r.status_code == 403, (permission, r.text)
                assert r.json()["detail"] == f"missing permission: {permission.value}"
        assert (await c.get("/auth/check/not:a-permission", headers=_auth(tok))).status_code == 404


async def test_a_check_route_writes_the_grant_row_its_permission_names(engine: Engine) -> None:
    """The check route is the console's authority for a page with no engine data of its own, so
    it must leave the decision row a bearer request to a require(p) route leaves."""
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    async with _client(engine, service) as c:
        tok = await _login(c, "vic")
        r = await c.get("/auth/check/monitoring:read", headers=_auth(tok))
        assert r.status_code == 200, r.text
    rows = await engine.store.list_audit(limit=200)
    assert any(
        row["action"] == _GRANTED and "/auth/check/monitoring:read" in str(row["detail"])
        for row in rows
    ), [row["action"] for row in rows]


async def test_the_check_routes_are_confined_for_a_must_change_session(engine: Engine) -> None:
    """Unlike GET /auth/me, the check routes are not must-change exempt: a confined session is
    refused there as on any other gated route, so a console page behind one is confined too."""
    service = await _service(engine)
    admin = await create_admin(service)
    async with _client(engine, service) as c:
        tok = await _login(c, admin.username, admin.password)
        assert (await c.get("/auth/me", headers=_auth(tok))).status_code == 200
        for path in ("/auth/check", "/auth/check/users:read"):
            r = await c.get(path, headers=_auth(tok))
            assert r.status_code == 403, (path, r.text)
            assert r.json()["detail"].startswith("password change required")


# --- the must-change refusal header -------------------------------------------------------------


async def test_a_must_change_refusal_names_the_password_change_next(engine: Engine) -> None:
    service = await _service(engine)
    admin = await create_admin(service)
    async with _client(engine, service) as c:
        tok = await _login(c, admin.username, admin.password)
        r = await c.get("/users", headers=_auth(tok))
        assert r.status_code == 403
        assert r.headers.get(MUST_CHANGE_NEXT_HEADER) == MUST_CHANGE_NEXT_ROTATE


async def test_a_must_change_refusal_names_enrolment_when_the_account_enrols_first(
    engine: Engine,
) -> None:
    """ADR 0197 Amendment A: under require_mfa, a must-change account with no factor enrols first."""
    service = AuthService(
        engine.store, AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False)
    )
    await service.initialize()
    admin = await create_admin(service)
    async with _client(engine, service) as c:
        tok = await _login(c, admin.username, admin.password)
        r = await c.get("/users", headers=_auth(tok))
        assert r.status_code == 403
        assert "enrol an authenticator app first" in r.json()["detail"]
        assert r.headers.get(MUST_CHANGE_NEXT_HEADER) == MUST_CHANGE_NEXT_ENROL_FACTOR


async def test_a_must_change_refusal_names_the_factor_a_reset_account_owes(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An administrator reset keeps the account's factor, so the session proves it first: the
    password route refuses it until then (BACKLOG #1954)."""
    service = AuthService(
        engine.store, AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False)
    )
    await service.initialize()
    user_id = await _add(service, "vic", Role.VIEWER)
    pin_totp_clock(monkeypatch, 1_000_000.0)
    await _enroll_totp_out_of_band(service, "vic", now=1_000_000.0)
    temp = (await service.admin_reset_password(user_id, actor="test")).password
    async with _client(engine, service) as c:
        tok = await _login(c, "vic", temp)
        r = await c.get("/messages", headers=_auth(tok))
        assert r.status_code == 403
        assert r.json()["detail"].startswith("password change required")
        assert r.headers.get(MUST_CHANGE_NEXT_HEADER) == MUST_CHANGE_NEXT_VERIFY_FACTOR


# --- the step-up refusal's reason header --------------------------------------------------------


async def test_a_stale_window_refusal_names_reverify(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        tok = await _login(c, "boss")
        await service.store.mark_session_reauthed(hash_token(tok), now=0.0)
        r = await c.delete("/users/no-such-user", headers=_auth(tok))
        assert r.status_code == 403 and r.headers.get("X-Step-Up-Required") == "1", r.text
        assert r.headers.get(STEP_UP_REASON_HEADER) == STEP_UP_REASON_REVERIFY


async def test_a_new_address_refusal_names_the_new_address(engine: Engine) -> None:
    """The same 403 as a stale window, told apart only by the reason header, which the console's
    refusal map reads to pick where a re-authentication resumes (ADR 0215 section 2)."""
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service, peer=("10.1.1.1", 4000)) as c:
        tok = await _login(c, "boss")
    async with _client(engine, service, peer=("10.2.2.2", 4000)) as c:
        r = await c.delete("/users/no-such-user", headers=_auth(tok))
        assert r.status_code == 403 and r.headers.get("X-Step-Up-Required") == "1", r.text
        assert r.headers.get(STEP_UP_REASON_HEADER) == STEP_UP_REASON_NEW_ADDRESS


async def test_a_paced_route_new_address_refusal_names_the_new_address(engine: Engine) -> None:
    """The require_paced path reaches the same refusal through refuse_from_new_address."""
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service, peer=("10.1.1.1", 4000)) as c:
        tok = await _login(c, "boss")
    async with _client(engine, service, peer=("10.2.2.2", 4000)) as c:
        r = await c.post("/connections/IB_NONE/start", headers=_auth(tok))
        assert r.status_code == 403 and r.headers.get("X-Step-Up-Required") == "1", r.text
        assert r.headers.get(STEP_UP_REASON_HEADER) == STEP_UP_REASON_NEW_ADDRESS


async def test_a_store_fault_on_the_factor_read_keeps_the_must_change_refusal(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fault on the refusal-only read keeps the 403, answered as owing no factor."""
    service = await _service(engine)
    admin = await create_admin(service)

    async def _fault(_token: str | None) -> bool:
        raise OSError("synthetic store fault")

    async with _client(engine, service) as c:
        tok = await _login(c, admin.username, admin.password)
        monkeypatch.setattr(service, "password_change_owes_factor", _fault)
        r = await c.get("/users", headers=_auth(tok))
        assert r.status_code == 403, r.text
        assert r.headers.get(MUST_CHANGE_NEXT_HEADER) == MUST_CHANGE_NEXT_ROTATE


async def test_a_phi_view_check_route_writes_no_grant_row(engine: Engine) -> None:
    """Pins the documented state (docs/SECURITY.md, Gate-only check routes): a PHI-view grant is
    left to the PHI-access audit row, and a check route writes none. A change here is deliberate."""
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        tok = await _login(c, "boss")
        for permission in ("messages:view_raw", "messages:view_summary"):
            r = await c.get(f"/auth/check/{permission}", headers=_auth(tok))
            assert r.status_code == 200, r.text
    rows = await engine.store.list_audit(limit=200)
    assert not [row for row in rows if "/auth/check/messages:view_" in str(row["detail"])]


async def test_an_action_bound_new_address_refusal_names_the_new_address(engine: Engine) -> None:
    """The require_step_up_action path: DELETE /me/mfa from a host the session has not verified."""
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service, peer=("10.1.1.1", 4000)) as c:
        tok = await _login(c, "boss")
    async with _client(engine, service, peer=("10.2.2.2", 4000)) as c:
        r = await c.delete("/me/mfa", headers=_auth(tok))
        assert r.status_code == 403 and r.headers.get("X-Step-Up-Required") == "1", r.text
        assert r.headers.get("X-Step-Up-Action") == "mfa_disable"
        assert r.headers.get(STEP_UP_REASON_HEADER) == STEP_UP_REASON_NEW_ADDRESS


async def test_a_lapsed_temporary_credential_gets_no_next_step_header(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the deadline passes between the session check and the refusal, the detail names an
    administrator reset (BACKLOG #2298), so the header names no step the session could take."""
    service = await _service(engine)
    admin = await create_admin(service)

    async def _lapsed(_auth: object, _user_id: str) -> float:
        return time.time() - 60

    async with _client(engine, service) as c:
        tok = await _login(c, admin.username, admin.password)
        monkeypatch.setattr(security, "pending_credential_deadline_for", _lapsed)
        r = await c.get("/users", headers=_auth(tok))
        assert r.status_code == 403, r.text
        assert "ask an administrator to reset it" in r.json()["detail"]
        assert MUST_CHANGE_NEXT_HEADER not in r.headers


# --- GET /me/step-up ------------------------------------------------------------------------------


async def test_step_up_status_reports_the_window_without_moving_it(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    async with _client(engine, service) as c:
        assert (await c.get("/me/step-up")).status_code == 401
        tok = await _login(c, "vic")
        r = await c.get("/me/step-up", headers=_auth(tok))
        assert r.status_code == 200, r.text
        assert r.json() == {"window_live": True, "action_proof_live": None}
        # The read moves nothing: the session's step-up stamp is where the login left it.
        before = await service.store.get_session(hash_token(tok))
        await c.get("/me/step-up", headers=_auth(tok))
        after = await service.store.get_session(hash_token(tok))
        assert before is not None and after is not None and before.reauth_at == after.reauth_at
        await service.store.mark_session_reauthed(hash_token(tok), now=0.0)
        r = await c.get("/me/step-up", headers=_auth(tok))
        assert r.json()["window_live"] is False


async def test_step_up_status_reads_an_action_proof_without_spending_it(engine: Engine) -> None:
    """The proof is still held after two reads, and still spendable by the action's own gate."""
    service = await _service(engine)
    await _add(service, "boss", Role.ADMINISTRATOR)
    action = STEP_UP_ACTION_CONFIG_RELOAD
    async with _client(engine, service) as c:
        tok = await _login(c, "boss")
        r = await c.get("/me/step-up", params={"action": action}, headers=_auth(tok))
        assert r.json() == {"window_live": True, "action_proof_live": False}
        r = await c.post("/me/reauth", json={"password": PW, "purpose": action}, headers=_auth(tok))
        assert r.status_code == 200, r.text
        tok = str(r.json()["token"])
        for _ in range(2):
            r = await c.get("/me/step-up", params={"action": action}, headers=_auth(tok))
            assert r.status_code == 200, r.text
            assert r.json()["action_proof_live"] is True
        assert await service.holds_action_step_up(tok, action) is True
        assert await service.has_action_step_up(tok, action) is True  # spends it
        r = await c.get("/me/step-up", params={"action": action}, headers=_auth(tok))
        assert r.json()["action_proof_live"] is False


async def test_step_up_status_refuses_an_overlong_action(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    async with _client(engine, service) as c:
        tok = await _login(c, "vic")
        r = await c.get("/me/step-up", params={"action": "a" * 65}, headers=_auth(tok))
        assert r.status_code == 422
