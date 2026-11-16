# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The browser credential forms refuse what the JSON routes refuse (BACKLOG #5397, #5398).

The JSON login, MFA-verify and reauth routes bound their credential fields through their request
models, so an oversized value is a 422 before any hash runs. The /ui form handlers parse the body
by hand, so each must apply the same bound itself, or an oversized value reaches the password hash,
the recovery-code loop or the directory. Each test pins both sides of the bound: one past it never
reaches the service call, and one at it still does.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from _ui_clients import PW, SAME_ORIGIN, held_totp_code, provision, ui_client

from messagefoundry.api.auth_models import _MFA_CODE_MAX, _NAME_MAX, _PASSWORD_MAX
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_enabled=False,
            admin_write_min_interval_seconds=0,
            # One slot keeps the enrolment and the recovery-code walk to one argon2 hash each.
            mfa_recovery_code_count=1,
        ),
    )
    await service.initialize()
    return service


async def _add(service: AuthService) -> None:
    await provision(service, "op", [Role.OPERATOR.value])


def _spy(monkeypatch: pytest.MonkeyPatch, service: AuthService, name: str) -> list[tuple[Any, ...]]:
    """Record each call of ``service.<name>`` and still run it. Returns the positional args seen."""
    calls: list[tuple[Any, ...]] = []
    real: Callable[..., Awaitable[Any]] = getattr(service, name)

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return await real(*args, **kwargs)

    monkeypatch.setattr(service, name, spy)
    return calls


async def _enrol_totp(service: AuthService) -> None:
    """Activate a TOTP factor for "op" out-of-band, so a fresh browser sign-in is pending on it."""
    user = await service.store.get_user_by_username("op")
    assert user is not None
    identity = await service.identity_for_user_id(user.id)
    assert identity is not None
    outcome = await service.login("op", PW)
    assert outcome.ok and outcome.token is not None
    enrollment = await service.begin_mfa_enrollment(identity)
    with held_totp_code(enrollment.secret) as code:
        confirmed = await service.confirm_mfa_enrollment(identity, code, token=outcome.token)
    assert confirmed.ok


# --- BACKLOG #5397: POST /ui/login ------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "bound", "arg"),
    (("username", _NAME_MAX, 0), ("password", _PASSWORD_MAX, 1)),
    ids=("username", "password"),
)
async def test_an_oversized_sign_in_credential_never_reaches_login(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, field: str, bound: int, arg: int
) -> None:
    """RED when: ui_login stops checking the field's length before it calls auth.login, or the
    bound is off by one and refuses a value the JSON route accepts."""
    service = await _service(engine)
    calls = _spy(monkeypatch, service, "login")
    async with ui_client(engine, service) as c:
        r = await c.post(
            "/ui/login", data={"username": "op", "password": PW, field: "a" * (bound + 1)}
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        assert calls == []
        assert "mf_session" not in c.cookies
        # At the bound the credential is checked, as the JSON route checks it.
        await c.post("/ui/login", data={"username": "op", "password": PW, field: "a" * bound})
    assert len(calls) == 1 and calls[0][arg] == "a" * bound


# --- BACKLOG #5398: POST /ui/mfa --------------------------------------------------------------


async def test_an_oversized_factor_code_never_reaches_verify_mfa(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_mfa_submit stops checking the code's length before it calls verify_mfa."""
    service = await _service(engine)
    await _add(service)
    await _enrol_totp(service)
    calls = _spy(monkeypatch, service, "verify_mfa")
    async with ui_client(engine, service) as c:
        assert (await c.post("/ui/login", data={"username": "op", "password": PW})).headers[
            "location"
        ] == "/ui/mfa"
        r = await c.post("/ui/mfa", data={"code": "1" * (_MFA_CODE_MAX + 1)}, headers=SAME_ORIGIN)
        assert r.status_code == 400 and "accepted. Try again." in r.text
        assert calls == []
        # At the bound the code is checked, as the JSON route checks it.
        r = await c.post("/ui/mfa", data={"code": "1" * _MFA_CODE_MAX}, headers=SAME_ORIGIN)
        assert r.status_code == 400
        assert len(calls) == 1
