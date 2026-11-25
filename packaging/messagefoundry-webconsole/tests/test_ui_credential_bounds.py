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
    _MFA_CODE_MAX,
    _NAME_MAX,
    _PASSWORD_MAX,
)
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import ENROLMENT_CODE_MAX
from messagefoundry.auth.totp import MAX_DIGITS
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._auth import PASSKEY_SIGN_IN_COOKIE_NAME

_REVOKE_OTHERS = "/ui/account/sessions/revoke-others"


async def _service(engine: Engine, *, require_mfa: bool = True) -> AuthService:
    service = AuthService(
        engine.store,
        AuthSettings(
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_enabled=False,
            admin_write_min_interval_seconds=0,
            # One slot keeps the enrolment and the recovery-code walk to one argon2 hash each.
            mfa_recovery_code_count=1,
            require_mfa=require_mfa,
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


async def _enrol_totp(service: AuthService) -> str:
    """Activate a TOTP factor for "op" out-of-band, so a fresh browser sign-in is pending on it.
    Returns the factor's secret."""
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
    return enrollment.secret


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
    """RED when: the oversized-credential exit stops clearing the passkey sign-in cookie, as a
    refused auth.login clears it. The route takes the handle's challenge before it checks the
    bound. Not every exit after that clears the cookie: at least the rate limiter's 429 does not."""
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
        # A non-digit one too: only the pattern is waived on this field, never the length.
        for oversized in ("1" * (MAX_DIGITS + 1), "a" * (MAX_DIGITS + 1)):
            r = await c.post("/ui/login", data={**base, "totp_code": oversized})
            assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=bad"
        assert calls == []
        # At the bound the code is passed on whole.
        await c.post("/ui/login", data={**base, "totp_code": "1" * MAX_DIGITS})
        assert len(calls) == 1 and calls[0][-1]["totp_code"] == "1" * MAX_DIGITS
        # Within the bound, content is not the form's to judge. The bound is on the code with
        # surrounding space stripped, as the engine strips it, and that stripped code is what
        # reaches auth.login: a padded code at the bound passes as the bare code, and a run of
        # spaces as no code.
        passed = {
            "12345a": "12345a",
            " 12345": "12345",
            "   ": None,
            " " + "1" * MAX_DIGITS + " ": "1" * MAX_DIGITS,
            " " * (MAX_DIGITS + 5): None,
        }
        for code in passed:
            await c.post("/ui/login", data={**base, "totp_code": code})
        assert [call[-1]["totp_code"] for call in calls[1:]] == list(passed.values())
        # A blank code is the two-step flow, passed on as no code.
        await c.post("/ui/login", data={**base, "totp_code": ""})
    assert len(calls) == 7 and calls[6][-1]["totp_code"] is None


async def test_a_padded_sign_in_code_reaches_login_within_the_bound(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_login measures the stripped code but passes the submitted one on, so a code
    padded with most of the 1 MiB body cap in space reaches auth.login whole (BACKLOG #5397)."""
    service = await _service(engine)
    calls = _spy(monkeypatch, service, "login")
    pad = " " * 450_000
    async with ui_client(engine, service) as c:
        for code in (pad + "123456" + pad, pad):
            await c.post("/ui/login", data={"username": "op", "password": PW, "totp_code": code})
    assert [call[-1]["totp_code"] for call in calls] == ["123456", None]


async def test_a_padded_correct_sign_in_code_still_signs_in(engine: Engine) -> None:
    """RED when: ui_login refuses or loses a correct authenticator code padded with space, which the
    combined sign-in has always accepted. The control is a blank code, which lands on the gate."""
    service = await _service(engine)
    await _add(service)
    secret = await _enrol_totp(service)
    # The next time step, so the code is not the one the enrolment confirm already consumed.
    with held_totp_code(secret, steps_ahead=1) as code:
        async with ui_client(engine, service) as c:
            r = await c.post("/ui/login", data={"username": "op", "password": PW, "totp_code": ""})
            assert r.headers["location"] == "/ui/mfa"
            c.cookies.clear()
            padded = " " * 50 + code + " " * 50
            r = await c.post(
                "/ui/login", data={"username": "op", "password": PW, "totp_code": padded}
            )
    assert r.status_code == 303 and r.headers["location"] == "/ui", r.headers


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
    """RED when: ui_mfa_submit stops checking the code's length before it calls verify_mfa,
    measures the code as submitted rather than stripped, or passes on the padded code."""
    service = await _service(engine)
    await _add(service)
    await _enrol_totp(service)
    calls = _spy(monkeypatch, service, "verify_mfa")
    async with ui_client(engine, service) as c:
        assert (await c.post("/ui/login", data={"username": "op", "password": PW})).headers[
            "location"
        ] == "/ui/mfa"
        oversized = "1" * (_MFA_CODE_MAX + 1)
        for code in (oversized, " " * 40 + oversized + " " * 40):
            r = await c.post("/ui/mfa", data={"code": code}, headers=SAME_ORIGIN)
            assert r.status_code == 400 and "accepted. Try again." in r.text
        assert calls == []
        # At the bound the code is checked, as the JSON route checks it, and surrounding space
        # neither refuses it nor reaches verify_mfa.
        for code in ("1" * _MFA_CODE_MAX, " " * 60 + "1" * _MFA_CODE_MAX + " " * 60):
            r = await c.post("/ui/mfa", data={"code": code}, headers=SAME_ORIGIN)
            assert r.status_code == 400
    assert [call[1] for call in calls] == ["1" * _MFA_CODE_MAX] * 2


# --- BACKLOG #5399: POST /ui/reauth -----------------------------------------------------------


async def test_an_oversized_step_up_code_never_reaches_verify_mfa(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_reauth's code leg stops checking the code's length before verify_mfa, measures
    the code as submitted rather than stripped, or passes on the padded code."""
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
        # The bound is on the code with surrounding space stripped, so padding does not hide an
        # oversized code, and does not refuse one within the bound.
        padded = " " * 40 + "1" * (_MFA_CODE_MAX + 1) + " " * 40
        r = await c.post("/ui/reauth", data={**form, "code": padded}, headers=SAME_ORIGIN)
        assert "Invalid code." in r.text
        assert calls == []
        for code in ("1" * _MFA_CODE_MAX, " " * 60 + "1" * _MFA_CODE_MAX + " " * 60):
            r = await c.post("/ui/reauth", data={**form, "code": code}, headers=SAME_ORIGIN)
            assert "Invalid code." in r.text
    # Each reached verify_mfa as the stripped code.
    assert [call[1] for call in calls] == ["1" * _MFA_CODE_MAX] * 2


async def test_an_oversized_step_up_password_never_reaches_reauth(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ui_reauth's password leg stops checking the password's length before reauth.

    An account with no factor goes straight to the password leg, which is the one a directory
    account's step-up would bind with. ``require_mfa`` is off: under it this session is
    MFA-pending, and the terminate it starts from sends it to enrol instead (BACKLOG #1149)."""
    service = await _service(engine, require_mfa=False)
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
    """RED when: ui_mfa_verify stops checking the code against MfaConfirmRequest before it calls
    confirm_mfa_enrollment, lets surrounding space hide an oversized code, or cuts or refuses the
    enrolment code instead of passing it on for the service to bound."""
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
            {"code": " " * 20 + "1" * (_CONFIRM_CODE_MAX + 1) + " " * 20},
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
        # The enrolment code is not the route's to bound: it goes on uncut, and the service bounds
        # it where it reads one (a local account owes none, so this one is ignored).
        oversized = "e" * (ENROLMENT_CODE_MAX + 1)
        await mint_bound_proof(c, "/ui/account/mfa/confirm")
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456", "enrolment_code": oversized},
            headers=SAME_ORIGIN,
        )
        assert r.status_code == 400 and "Invalid code." in r.text
    assert len(calls) == 2 and calls[0][1] == "1" * _CONFIRM_CODE_MAX
    assert calls[1][-1]["enrolment_code"] == oversized


# --- A correct code padded with space still counts on every form that takes one ------------------
#
# Main accepted these, because each route stripped the code before the service saw it; a bound on
# the code as submitted refused one padded past the bound. Each control is the bare code.


@pytest.mark.parametrize("pad", (0, 60), ids=("bare", "padded"))
async def test_a_padded_correct_factor_code_still_satisfies_the_gate(
    engine: Engine, pad: int
) -> None:
    """RED when: ui_mfa_submit measures the code as submitted, so a correct code padded past
    MfaVerifyRequest's bound with space is refused (BACKLOG #5398)."""
    service = await _service(engine)
    await _add(service)
    secret = await _enrol_totp(service)
    with held_totp_code(secret, steps_ahead=1) as code:
        async with ui_client(engine, service) as c:
            await c.post("/ui/login", data={"username": "op", "password": PW})
            r = await c.post(
                "/ui/mfa", data={"code": " " * pad + code + " " * pad}, headers=SAME_ORIGIN
            )
    assert r.status_code == 303 and r.headers["location"] == "/ui", r.text


@pytest.mark.parametrize("pad", (0, 60), ids=("bare", "padded"))
async def test_a_padded_correct_step_up_code_still_steps_up(engine: Engine, pad: int) -> None:
    """RED when: ui_reauth's code leg measures the code as submitted, so a correct code padded
    past MfaVerifyRequest's bound with space is refused (BACKLOG #5399)."""
    service = await _service(engine)
    await _add(service)
    secret = await _enrol_totp(service)
    with held_totp_code(secret, steps_ahead=1) as code:
        async with ui_client(engine, service) as c:
            await c.post("/ui/login", data={"username": "op", "password": PW})
            r = await c.post(
                "/ui/reauth",
                data={
                    "next": "/ui/account/mfa/disable",
                    "password": PW,
                    "code": " " * pad + code + " " * pad,
                },
                headers=SAME_ORIGIN,
            )
    # No continuation was staged, so a verified step-up lands on the "Verified" page.
    assert r.status_code == 200 and "<h1>Verified</h1>" in r.text, r.text


@pytest.mark.parametrize("pad", (0, 20), ids=("bare", "padded"))
async def test_a_padded_correct_enrolment_confirm_code_still_enrols(
    engine: Engine, pad: int
) -> None:
    """RED when: ui_mfa_verify measures the code as submitted, so a correct code padded past
    MfaConfirmRequest's bound with space is refused (BACKLOG #5399)."""
    service = await _service(engine)
    await _add(service)
    async with ui_client(engine, service) as c:
        await c.post("/ui/login", data={"username": "op", "password": PW})
        await mint_bound_proof(c, "/ui/account/mfa/enroll")
        assert (await c.post("/ui/account/mfa/enroll", headers=SAME_ORIGIN)).status_code == 200
        user = await service.store.get_user_by_username("op")
        assert user is not None
        secret = await service.store.get_totp_secret(user.id)
        assert secret
        await mint_bound_proof(c, "/ui/account/mfa/confirm")
        with held_totp_code(secret) as code:
            r = await c.post(
                "/ui/account/mfa/verify",
                data={"code": " " * pad + code + " " * pad},
                headers=SAME_ORIGIN,
            )
    assert r.status_code == 200 and "shown once" in r.text, r.text
