# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The browser credential forms refuse what the JSON routes refuse (BACKLOG #5397, #5398, #5399).

The JSON login, MFA-verify, reauth and enrolment-confirm routes bound their credential fields
through their request models, so an oversized value is a 422 before any hash runs. The /ui form
handlers parse the body by hand, so each must apply the same bound itself, or an oversized value
reaches the password hash, the recovery-code loop or the directory. Each test pins both sides of the
bound: one past it never reaches the service call, and one at it still does.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from _ui_clients import PW, SAME_ORIGIN, held_totp_code, mint_bound_proof, provision, ui_client

from messagefoundry.api.auth_models import (
    _CONFIRM_CODE_MAX,
    _ENROLMENT_CODE_MAX,
    _MFA_CODE_MAX,
    _NAME_MAX,
    _PASSWORD_MAX,
)
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.totp import MAX_DIGITS
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._auth import PASSKEY_SIGN_IN_COOKIE_NAME

_REVOKE_OTHERS = "/ui/account/sessions/revoke-others"


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
    """Record each call of ``service.<name>`` and still run it. Returns, per call, the positional
    args seen followed by the keyword args as one dict."""
    calls: list[tuple[Any, ...]] = []
    real: Callable[..., Awaitable[Any]] = getattr(service, name)

    async def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append((*args, kwargs))
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
        # At the bound the credential is checked, as the JSON route checks it.
        await c.post("/ui/login", data={"username": "op", "password": PW, field: "a" * bound})
    assert len(calls) == 1 and calls[0][arg] == "a" * bound


async def test_an_oversized_sign_in_clears_the_passkey_handle_it_consumed(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the oversized-credential exit stops clearing the passkey sign-in cookie, as every
    other refused sign-in clears it. The handle was popped before the bound was checked."""
    service = await _service(engine)
    calls = _spy(monkeypatch, service, "login")
    async with ui_client(engine, service) as c:
        c.cookies.set(PASSKEY_SIGN_IN_COOKIE_NAME, "a-forged-handle")
        r = await c.post(
            "/ui/login", data={"username": "op", "password": "a" * (_PASSWORD_MAX + 1)}
        )
        assert r.headers["location"] == "/ui/login?e=bad" and calls == []
        cleared = [h for h in r.headers.get_list("set-cookie") if PASSKEY_SIGN_IN_COOKIE_NAME in h]
        assert cleared and all("Max-Age=0" in h for h in cleared)


async def test_an_oversized_sign_in_code_never_reaches_login(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_login cuts the authenticator code to a length instead of refusing it, checks it
    against a bound other than LoginRequest's, or refuses a code within the bound for its content.
    The form bounds the code by length only, so a non-digit or a space is passed on as before."""
    service = await _service(engine)
    calls = _spy(monkeypatch, service, "login")
    async with ui_client(engine, service) as c:
        base = {"username": "op", "password": PW}
        r = await c.post("/ui/login", data={**base, "totp_code": "1" * (MAX_DIGITS + 1)})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        assert calls == []
        # At the bound the code is passed on whole.
        await c.post("/ui/login", data={**base, "totp_code": "1" * MAX_DIGITS})
        assert len(calls) == 1 and calls[0][-1]["totp_code"] == "1" * MAX_DIGITS
        # Within the bound, content is not the form's to judge: each reaches auth.login unchanged.
        # The bound is on the code with surrounding space stripped, as the engine strips it, so a
        # padded code at the bound and a long run of spaces both still pass.
        passed = ("12345a", " 12345", "   ", " " + "1" * MAX_DIGITS + " ", " " * (MAX_DIGITS + 5))
        for code in passed:
            await c.post("/ui/login", data={**base, "totp_code": code})
        assert [call[-1]["totp_code"] for call in calls[1:]] == list(passed)
        # A blank code is the two-step flow, passed on as no code.
        await c.post("/ui/login", data={**base, "totp_code": ""})
    assert len(calls) == 7 and calls[6][-1]["totp_code"] is None


async def test_a_space_only_sign_in_code_is_still_the_two_step_flow(engine: Engine) -> None:
    """RED when: ui_login refuses a space-only authenticator code instead of passing it on, which
    the engine reads as no code. The control is a blank code, which lands on the same gate."""
    service = await _service(engine)
    await _add(service)
    await _enrol_totp(service)
    async with ui_client(engine, service) as c:
        for code in ("", "   ", " " * (MAX_DIGITS + 5)):
            r = await c.post(
                "/ui/login", data={"username": "op", "password": PW, "totp_code": code}
            )
            assert r.status_code == 303 and r.headers["location"] == "/ui/mfa", (code, r.headers)
            c.cookies.clear()


async def test_a_stray_sign_in_code_does_not_refuse_an_account_with_no_factor(
    engine: Engine,
) -> None:
    """RED when: ui_login refuses a sign-in for a non-digit authenticator code within the bound,
    which on an account with no TOTP factor the engine has always ignored. The control is a blank
    code, and an oversized one is still refused."""
    service = await _service(engine)
    await _add(service)
    async with ui_client(engine, service) as c:
        for code in ("", "12a"):
            r = await c.post(
                "/ui/login", data={"username": "op", "password": PW, "totp_code": code}
            )
            assert r.status_code == 303 and r.headers["location"] != "/ui/login?e=bad", code
            c.cookies.clear()
        r = await c.post(
            "/ui/login",
            data={"username": "op", "password": PW, "totp_code": "1" * (MAX_DIGITS + 1)},
        )
        assert r.headers["location"] == "/ui/login?e=bad"


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


# --- BACKLOG #5399: POST /ui/reauth -----------------------------------------------------------


async def test_an_oversized_step_up_code_never_reaches_verify_mfa(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_reauth's code leg stops checking the code's length before verify_mfa."""
    service = await _service(engine)
    await _add(service)
    await _enrol_totp(service)
    calls = _spy(monkeypatch, service, "verify_mfa")
    async with ui_client(engine, service) as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        form = {"next": "/ui/account/mfa/disable", "password": PW}
        r = await c.post(
            "/ui/reauth", data={**form, "code": "1" * (_MFA_CODE_MAX + 1)}, headers=SAME_ORIGIN
        )
        assert r.status_code == 200 and "Invalid code." in r.text
        assert calls == []
        # The bound is on the value as submitted, as the JSON route's is, so trailing space the
        # handler strips does not carry a code past it.
        padded = "1" * _MFA_CODE_MAX + " "
        r = await c.post("/ui/reauth", data={**form, "code": padded}, headers=SAME_ORIGIN)
        assert "Invalid code." in r.text
        assert calls == []
        r = await c.post(
            "/ui/reauth", data={**form, "code": "1" * _MFA_CODE_MAX}, headers=SAME_ORIGIN
        )
        assert "Invalid code." in r.text
        assert len(calls) == 1


async def test_an_oversized_step_up_password_never_reaches_reauth(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_reauth's password leg stops checking the password's length before reauth.

    An account with no factor goes straight to the password leg, which is the one a directory
    account's step-up would bind with."""
    service = await _service(engine)
    await _add(service)
    calls = _spy(monkeypatch, service, "reauth")
    async with ui_client(engine, service) as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        refused = await c.post(_REVOKE_OTHERS, headers=SAME_ORIGIN)
        assert refused.headers["location"] == f"/ui/reauth?next={_REVOKE_OTHERS}"
        r = await c.post(
            "/ui/reauth",
            data={"next": _REVOKE_OTHERS, "password": "a" * (_PASSWORD_MAX + 1)},
            headers=SAME_ORIGIN,
        )
        assert r.status_code == 200 and "Incorrect password." in r.text
        assert calls == []
        # The refusal put the continuation back, so a correct password still completes the step-up.
        r = await c.post(
            "/ui/reauth", data={"next": _REVOKE_OTHERS, "password": PW}, headers=SAME_ORIGIN
        )
        assert r.status_code == 200 and "Continuing:" in r.text
        assert len(calls) == 1
        r = await c.post(
            "/ui/reauth",
            data={"next": _REVOKE_OTHERS, "password": "a" * _PASSWORD_MAX},
            headers=SAME_ORIGIN,
        )
        assert "Incorrect password." in r.text
        assert len(calls) == 2


# --- POST /ui/account/mfa/verify, the enrolment confirm ------------------------------------------


async def test_an_oversized_enrolment_confirm_code_never_reaches_the_service(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_mfa_verify stops checking the code or the enrolment code against
    MfaConfirmRequest before it calls confirm_mfa_enrollment, checks the stripped code rather than
    the one submitted, or cuts the enrolment code instead of refusing it."""
    service = await _service(engine)
    await _add(service)
    calls = _spy(monkeypatch, service, "confirm_mfa_enrollment")
    async with ui_client(engine, service) as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        await mint_bound_proof(c, "/ui/account/mfa/enroll")
        staged = await c.post("/ui/account/mfa/enroll", headers=SAME_ORIGIN)
        assert staged.status_code == 200 and "Secret:" in staged.text
        for refused in (
            {"code": "1" * (_CONFIRM_CODE_MAX + 1)},
            {"code": "1" * _CONFIRM_CODE_MAX + " "},
            # The enrolment code is refused past MfaConfirmRequest's bound too, never cut to it.
            {"code": "123456", "enrolment_code": "e" * (_ENROLMENT_CODE_MAX + 1)},
        ):
            await mint_bound_proof(c, "/ui/account/mfa/confirm")
            r = await c.post("/ui/account/mfa/verify", data=refused, headers=SAME_ORIGIN)
            assert r.status_code == 400 and "Invalid code." in r.text
        assert calls == []
        # At the bound the code is checked, as the JSON route checks it.
        await mint_bound_proof(c, "/ui/account/mfa/confirm")
        r = await c.post(
            "/ui/account/mfa/verify", data={"code": "1" * _CONFIRM_CODE_MAX}, headers=SAME_ORIGIN
        )
        assert r.status_code == 400 and "Invalid code." in r.text
    assert len(calls) == 1 and calls[0][1] == "1" * _CONFIRM_CODE_MAX
