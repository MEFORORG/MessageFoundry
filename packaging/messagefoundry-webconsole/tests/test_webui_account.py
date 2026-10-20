# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui self-service account: change password and the TOTP MFA lifecycle, BACKLOG #75 phase 4, and its
review-driven regressions."""

from __future__ import annotations

import time

import httpx
import pytest
from _ui_clients import create_local_user_chosen
from _webui_support import (
    PW,
    _add,
    _client,
    _cookie_login,
    _mint_action,
    _service,
    _uid,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

# --- L4b: self-service account (change password + TOTP MFA lifecycle), #75 phase 4 -----------------
#
# Change-password has NO step-up gate (the current password in the body IS the proof) and its POST is
# in neither continuation registry. MFA enroll/disable are body-less auto_retry actions gated by the
# password-only require_ui_reauth_only (an MFA gate would deadlock first enrollment); the confirm-code
# POST (/verify) is body-carrying with a standalone GET form (/confirm) as its unlock re-entry point.

NEW_PW = "another-strong-test-passphrase"


async def test_account_page_renders(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.get("/ui/account")
        assert r.status_code == 200
        assert "Signed in as op" in r.text
        assert "Not enrolled" in r.text  # MFA posture
        assert 'href="/ui/account/password"' in r.text
        assert 'href="/ui/account"' in r.text  # the nav entry
        # Anonymous → login.
        c.cookies.clear()
        assert (await c.get("/ui/account")).status_code == 303


async def test_password_change_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login?e=pwchanged"
        assert 'mf_session=""' in r.headers.get("set-cookie", "")  # cookie cleared
        # Every session was revoked server-side — the old cookie no longer works.
        c.cookies.clear()
        assert (await _cookie_login(c, "op")).headers[
            "location"
        ] == "/ui/login?e=bad"  # old PW dead
        r = await c.post("/ui/login", data={"username": "op", "password": NEW_PW})
        assert r.headers["location"] == "/ui"  # new password signs in


async def test_password_change_wrong_current_rerenders(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={
                "current_password": "not-the-password-at-all",
                "new_password": NEW_PW,
                "new_password2": NEW_PW,
            },
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 403
        assert "current password is incorrect" in r.text
        assert NEW_PW not in r.text  # passwords are never echoed back
        # Unchanged: the old password still logs in.
        c.cookies.clear()
        assert (await _cookie_login(c, "op")).headers["location"] == "/ui"


async def test_password_change_policy_and_mismatch(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": "short", "new_password2": "short"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "password must" in r.text
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": "different"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "do not match" in r.text
        # Neither attempt changed anything.
        c.cookies.clear()
        assert (await _cookie_login(c, "op")).headers["location"] == "/ui"


async def test_password_change_rejects_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403


async def test_must_change_account_is_confined_to_rotation(engine: Engine) -> None:
    # A must-change account: login lands on the rotation page, every other /ui route bounces back
    # there, and completing the rotation releases it (browser-only — no desktop console needed).
    service = await _service(engine)
    await create_local_user_chosen(
        service,
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )  # create_local_user leaves must_change_password=True
    async with _client(engine, service) as c:
        r = await _cookie_login(c, "fresh")
        assert r.headers["location"] == "/ui/account/password"  # login → rotation page
        for path in ("/ui", "/ui/account", "/ui/messages"):
            r = await c.get(path)
            assert r.status_code == 303, path
            assert r.headers["location"] == "/ui/account/password", path
        r = await c.get("/ui/account/password")
        assert r.status_code == 200
        assert "must be changed before you can continue" in r.text  # the forced variant
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=pwchanged"
        c.cookies.clear()
        r = await c.post("/ui/login", data={"username": "fresh", "password": NEW_PW})
        assert r.headers["location"] == "/ui"  # released
        assert (await c.get("/ui")).status_code == 200


async def test_mfa_enroll_confirm_disable_lifecycle(engine: Engine) -> None:

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # 7.5.1: the login window no longer unlocks a factor bind — enroll needs a fresh action grant.
        assert (
            await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        ).status_code == 303
        await _mint_action(c, "/ui/account/mfa/enroll")
        # Enroll: stages a secret, renders it once with the confirm form.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200
        assert "Secret:" in r.text and "otpauth://" in r.text
        assert 'action="/ui/account/mfa/verify"' in r.text
        uid = await _uid(service, "op")
        secret = await service.store.get_totp_secret(uid)
        # The staged secret is what the page shows: the bare key, without the parameters the cell
        # also records (BACKLOG #3422).
        assert secret and totp.parse_enrolment(secret)[0] in r.text
        # Confirm with a live code → recovery codes shown once; MFA active. Needs the MFA_CONFIRM grant.
        await _mint_action(c, "/ui/account/mfa/confirm")
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": _totp_not_near_a_step_boundary(secret)},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200
        assert "Recovery codes" in r.text or "MFA is active" in r.text
        assert "shown once" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled
        r = await c.get("/ui/account")
        assert "Enabled" in r.text and "recovery code(s) remaining" in r.text
        # Disable: full step-up bound to MFA_DISABLE. The session is MFA-verified (confirm marked it),
        # so the reauth is password-only (no code demand, core.py:610), then the grant lets it through.
        assert (
            await c.post("/ui/account/mfa/disable", headers={"Sec-Fetch-Site": "same-origin"})
        ).status_code == 303
        await _mint_action(c, "/ui/account/mfa/disable")
        r = await c.post("/ui/account/mfa/disable", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=mfa_off"
        user = await service.store.get_user(uid)
        assert user is not None and not user.totp_enabled
        assert "MFA disabled." in (await c.get("/ui/account?m=mfa_off")).text


async def test_mfa_verify_wrong_code_and_no_enrollment(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # No enrollment staged yet → back to the account page with the service's message (mint the
        # MFA_CONFIRM grant first, else the verify bounces to reauth before reaching its body).
        await _mint_action(c, "/ui/account/mfa/confirm")
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "no enrollment in progress" in r.text
        # Stage one, then a wrong (non-numeric) code re-renders the confirm form; MFA stays off.
        await _mint_action(c, "/ui/account/mfa/enroll")
        await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        await _mint_action(c, "/ui/account/mfa/confirm")
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "badcod"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "Invalid code." in r.text
        uid = await _uid(service, "op")
        user = await service.store.get_user(uid)
        assert user is not None and not user.totp_enabled


async def test_mfa_confirm_form_is_unlock_reentry(engine: Engine) -> None:
    # The standalone GET confirm form never re-shows the secret, and the L4b actions sit in the
    # right continuation registries (password POST in NEITHER).
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    create_app(engine, auth=service, serve_ui=True)
    assert is_safe_ui_action("/ui/account/mfa/enroll")
    assert is_safe_ui_action("/ui/account/mfa/disable")
    assert is_unlock_action("/ui/account/mfa/confirm")
    assert not is_safe_ui_action("/ui/account/mfa/confirm")
    assert not is_unlock_action("/ui/account/mfa/verify")
    assert not is_safe_ui_action("/ui/account/password")
    assert not is_unlock_action("/ui/account/password")
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, "/ui/account/mfa/enroll")
        await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        uid = await _uid(service, "op")
        secret = await service.store.get_totp_secret(uid)
        r = await c.get("/ui/account/mfa/confirm")
        assert r.status_code == 200
        assert secret is not None and secret not in r.text  # the secret is never re-shown
        assert 'action="/ui/account/mfa/verify"' in r.text


async def test_stale_reauth_only_bounces_to_reauth(engine: Engine) -> None:
    # require_ui_reauth_only_action under a stale window: enroll (body-less) carries its own path;
    # the body-carrying verify maps to its unlock confirm form via reauth_next.
    #
    # NOT the require_mfa=False shape of the step-up twins (BACKLOG #1850), and the _action suffix
    # in that factory name is the load-bearing part. Its base passes allow_mfa_pending=True
    # precisely so an un-enrolled account can reach the route that enrolls it -- there is no MFA leg
    # to take out, and require_mfa=False would pin nothing here. Under ADR 0077 the gate reads
    # has_action_step_up, never has_recent_step_up, so the negative window is load-bearing only
    # through the GRANT's TTL, which _grant_action_step_up sets to now + step_up_max_age_seconds.
    # So each lane below is driven TWICE (BACKLOG #1851): an ungranted arm, which bounces under
    # every window and therefore measures the window not at all, and a minted arm, which bounces
    # only because the negative window expired the grant on its way out of the mint.
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, step_up_max_age_seconds=-1)
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # Arm 1, ungranted and window-independent, kept when the minted arm was added. The ENROLL
        # half of it is driven independently by test_require_mfa_unenrolled_can_enroll_end_to_end
        # under a DEFAULT window -- which is also the proof that the -1 above changed nothing here
        # before arm 2 existed. The VERIFY half is why this arm stays: every other verify POST in
        # this file mints a grant first, to get past this very refusal. That is a census of the
        # file, not a proof about the suite, so re-measure before deleting the arm.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"
        # Arm 2: a grant IS minted, and the negative window has already expired it. Not read back
        # with has_action_step_up -- that read POPS the grant (single-use), so checking it here
        # would consume what the route must find and the gate would go untested. The re-auth
        # response is the non-destructive evidence instead: 200 plus the auto-submit form for a
        # body-less auto_retry action, 303 to the target for an unlock one. BOTH halves are
        # asserted, because a WRONG password also answers 200 -- pages.reauth carrying an error.
        minted = await _mint_action(c, "/ui/account/mfa/enroll")
        assert minted.status_code == 200
        assert 'action="/ui/account/mfa/enroll"' in minted.text
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"
        # The verify lane, both arms again. Its grant binds to the REGISTERED confirm action, never
        # to the body-carrying verify path -- deliberately not a continuation, so /ui/reauth would
        # mint nothing for it. That is the same mapping reauth_next applies to the refusal.
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/confirm"
        minted = await _mint_action(c, "/ui/account/mfa/confirm")
        assert minted.status_code == 303
        assert minted.headers["location"] == "/ui/account/mfa/confirm"
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/confirm"
        # The change-password POST has NO step-up gate, but under require_mfa this account holds no
        # TOTP, so it is sent to enrol first (ADR 0197 Amendment A, AC-A3) -- not refused by the
        # stale window, which it never reaches.
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=enroll_first"


async def test_reauth_never_demands_code_from_unenrolled_user(engine: Engine) -> None:
    # The deadlock fix, half 1: a require_mfa deployment with an UNENROLLED user under a stale
    # window — the reauth page must ask for the password only (the user has no authenticator yet),
    # and a password-only re-auth must unlock the enroll action. (The -1 window keeps step-up
    # permanently stale, so the enroll completion itself is the next test, under a normal window.)
    service = AuthService(engine.store, AuthSettings(require_mfa=True, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        # Stale window → enroll bounces to reauth (issuing the continuation, vault BACKLOG #2764);
        # the form must NOT demand a TOTP code.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"
        r = await c.get("/ui/reauth", params={"next": "/ui/account/mfa/enroll"})
        assert r.status_code == 200
        assert 'name="password"' in r.text
        assert 'name="code"' not in r.text  # nothing to type — no authenticator exists yet
        # Password-only re-auth unlocks the body-less enroll action (auto-submit page).
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/enroll", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and "data-autosubmit" in r.text


async def test_require_mfa_unenrolled_can_enroll_end_to_end(engine: Engine) -> None:
    # The deadlock fix, half 2 — the TRUE production flow: under require_mfa an MFA-pending session
    # deliberately gets NO step-up freshness from login (WP-14: a stolen pre-MFA token must not bind
    # an attacker's authenticator), so browser enrollment goes login → enroll → reauth (password
    # ONLY, no impossible code demand) → auto-retried enroll → confirm — completing end-to-end.

    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, mfa_verify_min_elapsed_seconds=0, require_mfa=True
        ),
    )
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        # The MFA-pending session has no step-up freshness → enroll bounces to reauth.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"
        # The reauth form asks for the password ONLY (no authenticator exists yet — the fix).
        r = await c.get("/ui/reauth", params={"next": "/ui/account/mfa/enroll"})
        assert r.status_code == 200 and 'name="code"' not in r.text
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/enroll", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and "data-autosubmit" in r.text  # auto-retry the enroll
        # The re-POSTed enroll now succeeds inside the refreshed window.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200 and "Secret:" in r.text
        uid = await _uid(service, "boss")
        secret = await service.store.get_totp_secret(uid)
        assert secret is not None
        # Confirm needs its OWN grant (MFA_CONFIRM) — a second password re-proof, the exact enroll→
        # confirm two-reauth friction ADR 0077 accepts. The staged-but-unconfirmed secret keeps
        # mfa.enabled False, so this reauth stays password-only (no impossible code demand).
        await _mint_action(c, "/ui/account/mfa/confirm")
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": _totp_not_near_a_step_boundary(secret)},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and "shown once" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled


async def test_ui_factor_bind_is_single_use(engine: Engine) -> None:
    # 7.5.1: a /ui factor-action grant is single-use — after one enroll bind consumes it, a second
    # enroll POST re-prompts (303 to reauth) rather than riding the login window.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _mint_action(c, "/ui/account/mfa/enroll")
        assert (
            await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        ).status_code == 200  # consumes the grant
        # The grant is spent → a second enroll bounces to reauth (the login window never unlocks it).
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/enroll"


async def test_ui_factor_bind_opt_out_uses_window(engine: Engine) -> None:
    # 7.5.1 opt-out: with [auth].require_action_step_up=False the /ui twins fall back to the session
    # window, so a fresh login unlocks the enroll bind directly (byte-identical to pre-amendment /ui).
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, require_action_step_up=False)
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200 and "Secret:" in r.text


@pytest.mark.parametrize("action_step_up", (True, False), ids=("enforced", "opted-out"))
async def test_ui_factor_bind_needs_the_existing_factor_whatever_the_knob_says(
    engine: Engine, action_step_up: bool
) -> None:
    """The /ui twin of the engine's 6.3.3 factor-binding refusal.

    RED when: the ``factor_binding_is_blocked`` refusal leaves ``_ui_action_step_up_ok``. The
    ``opted-out`` arm is the regression that matters: under
    ``[auth].require_action_step_up = false`` this lane's whole gate is the session window, so a
    refreshed window alone would let an MFA-pending session bind a NEW factor on an account that
    already holds one -- and the confirm ceremony then promotes it to MFA-satisfied.

    The window is stamped directly rather than staged through a ceremony, because the reachable
    chain crosses planes and the crossing is not what this test is about: /ui and the JSON API share
    one session store, so somebody holding the password signs in at /ui, replays that same session
    token as a Bearer to ``POST /me/reauth`` (MFA-exempt, and purpose-less so the mint-time guard
    never fires), and comes back to the cookie lane with the window fresh. What this pins is that
    the /ui gate must not open on a fresh window alone, however the window got there.

    The victim holds a PASSKEY rather than a TOTP secret for the reason the JSON twin gives: against
    a TOTP holder the enroll route refuses on its own with a 400, so a 303 assertion would grade a
    gate that is wide open. Measured against the unfixed code, the opted-out arm stages a secret and
    returns **200** on the TOTP enroll lane.
    """
    from messagefoundry.store.store import WebAuthnCredential

    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, require_action_step_up=action_step_up)
    )
    await service.initialize()
    await _add(service, "vic", Role.OPERATOR)

    # The victim really holds a factor, so the enrollment deadlock carve-out does not cover them.
    uid = await _uid(service, "vic")
    await engine.store.add_webauthn_credential(
        WebAuthnCredential(
            credential_id_hash="ui-vic-passkey-hash",
            credential_id="ui-vic-passkey-id-b64url",
            user_id=uid,
            rp_id="t",
            public_key="cose-public-key-b64url",
            sign_count=0,
            transports=None,
            device_type="multi_device",
            backed_up=True,
            label="yubikey",
            aaguid="aaguid-0000",
            created_at=1000.0,
            last_used_at=None,
        )
    )
    assert await service.store.has_webauthn_credentials(uid) is True

    async with _client(engine, service) as c:
        r = await _cookie_login(c, "vic")  # the attacker knows the password and nothing else
        assert r.status_code == 303
        tok = c.cookies.get("mf_session")
        assert tok is not None
        await service.store.mark_session_reauthed(hash_token(tok))
        # The positive controls. Without them a refusal for some OTHER reason -- a stale window, a
        # spent grant -- would read as this guard working and the opted-out arm would pass anyway.
        assert await service.has_recent_step_up(tok) is True
        assert await service.mfa_satisfied(tok) is False

        for path, continuation in (
            ("/ui/account/mfa/enroll", "/ui/account/mfa/enroll"),
            ("/ui/account/webauthn/enroll", "/ui/account/webauthn/enroll"),
        ):
            r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
            assert r.status_code == 303, f"{path} bound a factor on the password alone"
            assert r.headers["location"] == f"/ui/reauth?next={continuation}"
        # The confirm lane is refused on its own, not merely starved of a staged secret.
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "000000"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/confirm"
        # No promotion happened: the session is still behind the 6.3.3 gate.
        assert await service.mfa_satisfied(tok) is False


# --- L4b review-driven regressions (adversarial review: 2 behavior bugs + coverage gaps) -----------


async def _enroll_mfa(c: httpx.AsyncClient, service: AuthService, username: str) -> str:
    """Enroll + confirm TOTP for `username` via the /ui flow; return the secret (for later codes).

    7.5.1 (ADR 0077): each factor bind now needs its own single-use action grant — mint MFA_ENROLL
    before enroll and MFA_CONFIRM before verify (the login window no longer unlocks factor binding)."""

    await _mint_action(c, "/ui/account/mfa/enroll")
    r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200, r.text
    uid = await _uid(service, username)
    secret = await service.store.get_totp_secret(uid)
    assert secret is not None
    await _mint_action(c, "/ui/account/mfa/confirm")
    r = await c.post(
        "/ui/account/mfa/verify",
        data={"code": _totp_not_near_a_step_boundary(secret)},
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert r.status_code == 200, r.text
    return secret


def _totp_not_near_a_step_boundary(secret: str, *, margin: float = 3.0) -> str:
    """A TOTP code with enough of its step left to survive the round trip.

    ``[auth].totp_skew_steps`` defaults to **0** — strict current-step only, deliberately, so that
    tolerating a fast-clock code cannot advance the single-use high-water mark (SEC-014). That makes
    every ``totp(secret)`` computed near a step boundary a race: the code is minted in step N and
    verified in step N+1, and the server correctly rejects it (400). It is not a product defect, but
    it makes any test that enrolls MFA fail a few percent of the time — which is how it blocked PRs
    that touch nothing near auth.

    Waiting out the remaining sliver of the step (never more than ``margin`` seconds) makes the helper
    deterministic without widening the product's replay window.
    """
    from messagefoundry.auth import totp as _totp_mod

    period = _totp_mod.DEFAULT_PERIOD
    remaining = period - (time.time() % period)
    if remaining < margin:
        time.sleep(remaining + 0.05)
    return _totp_mod.totp(secret)


async def test_reauth_confines_must_change_session(engine: Engine) -> None:
    # Review bug [0]: /ui/reauth (GET+POST) must mirror require_ui's must-change confinement — the JSON
    # /me/reauth twin refuses a must-change session, so the /ui gate must not be weaker.
    service = await _service(engine)
    await create_local_user_chosen(
        service,
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )  # must_change_password stays True
    async with _client(engine, service) as c:
        await _cookie_login(c, "fresh")
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/M1/replay"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/messages/M1/replay", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"


async def test_required_unenrolled_full_stepup_routes_to_enroll_not_loop(engine: Engine) -> None:
    # Review bug [1]: under require_mfa an unenrolled user hitting a FULL-step-up action must be sent to
    # enroll — never a password form that "accepts" the credential then bounces straight back forever.
    service = AuthService(engine.store, AuthSettings(require_mfa=True))
    await service.initialize()
    await _add(service, "boss", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "boss")
        # A full-step-up admin form (L4a) → require_ui_step_up bounces to /ui/reauth...
        r = await c.get("/ui/users/new")
        assert r.status_code == 303 and r.headers["location"] == "/ui/reauth?next=/ui/users/new"
        # ...and /ui/reauth sends an unenrolled required user to enroll, not a looping password form.
        r = await c.get("/ui/reauth", params={"next": "/ui/users/new"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=enroll_first"
        # The POST does the same BEFORE consuming a rate-limit token (no correct-password → 429 loop).
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/users/new", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=enroll_first"
        assert "enroll an authenticator" in (await c.get("/ui/account?m=enroll_first")).text
        # But the enrollment path (step_up=False) is NOT diverted — password-only reauth still unlocks it.
        r = await c.get("/ui/reauth", params={"next": "/ui/account/mfa/enroll"})
        assert r.status_code == 200 and 'name="code"' not in r.text


async def test_reauth_demands_code_from_enrolled_unverified_session(engine: Engine) -> None:
    # WP-14 positive case: an ENROLLED-but-unverified session must still get the TOTP code demand
    # (the enrolled-aware condition must not have weakened the code requirement).
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, mfa_verify_min_elapsed_seconds=0),
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _enroll_mfa(c, service, "op")
        # A fresh login is enrolled but NOT MFA-verified (login leaves the 2nd factor pending).
        c.cookies.clear()
        await _cookie_login(c, "op")
        r = await c.get("/ui/reauth", params={"next": "/ui/messages/M1/replay"})
        assert r.status_code == 200
        assert 'name="password"' in r.text and 'name="code"' in r.text  # BOTH factors demanded


async def test_disable_mfa_enforces_full_stepup_when_stale(engine: Engine) -> None:
    # Disable is require_ui_step_up (full step-up incl. MFA), matching the JSON DELETE /me/mfa: an
    # enrolled-but-unverified session is bounced to /ui/reauth, and MFA stays on until re-verified.
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, mfa_verify_min_elapsed_seconds=0),
    )
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _enroll_mfa(c, service, "op")
        uid = await _uid(service, "op")
        c.cookies.clear()  # a fresh (enrolled, MFA-unverified) session
        await _cookie_login(c, "op")
        r = await c.post("/ui/account/mfa/disable", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/account/mfa/disable"
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled  # still on — the gate held


async def test_disabling_the_LAST_factor_renders_the_page_not_raw_json(engine: Engine) -> None:
    """BACKLOG #1022: this route DELEGATES to the JSON handler, so its refusal arrives as an
    HTTPException -- and without a translation here FastAPI renders that as a bare ``{"detail": ...}``
    into a browser form navigation. Every sibling refusal in this module answers with the account page
    carrying the message; this one did not, so adding the guard to the service made the console worse
    at exactly the moment it started refusing. The remedy is the operator's to act on (enroll another
    factor first), so it has to reach somewhere they can read it.
    """
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, mfa_verify_min_elapsed_seconds=0),
    )  # default posture: require_mfa=True
    await service.initialize()
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        await _enroll_mfa(c, service, "op")
        uid = await _uid(service, "op")
        await _mint_action(c, "/ui/account/mfa/disable")
        r = await c.post("/ui/account/mfa/disable", headers={"Sec-Fetch-Site": "same-origin"})

        assert r.status_code == 400, r.text
        # THE ASSERTION THAT DISCRIMINATES: a raw JSON refusal is also a 400, so the status code
        # alone would pass against the defect. What distinguishes them is the body being a page.
        assert "<html" in r.text.lower(), f"refusal did not render as HTML:\n{r.text[:300]}"
        assert "last second factor" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.totp_enabled  # refused, and nothing was stripped


async def test_mfa_posts_reject_cross_site(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # 7.5.1 consume-before-CSRF (ADR 0077): even WITH a fresh action grant, a cross-site POST is
        # rejected by the in-body assert_same_origin (403) — the grant is consumed harmlessly, never a
        # bypass. Minting the grant first keeps this a real assert_same_origin test (not a no-grant 303).
        for path, mint_next in (
            ("/ui/account/mfa/enroll", "/ui/account/mfa/enroll"),
            ("/ui/account/mfa/verify", "/ui/account/mfa/confirm"),
            ("/ui/account/mfa/disable", "/ui/account/mfa/disable"),
        ):
            await _mint_action(c, mint_next)
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path
        uid = await _uid(service, "op")
        assert await service.store.get_totp_secret(uid) is None  # nothing staged


async def test_must_change_confinement_on_posts_and_reauth_continuation(engine: Engine) -> None:
    # Confinement covers POSTs and the /ui/reauth-driven continuation, not just GETs.
    service = await _service(engine)
    await create_local_user_chosen(
        service,
        username="fresh",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    async with _client(engine, service) as c:
        await _cookie_login(c, "fresh")
        # A state-changing POST is bounced, not executed.
        r = await c.post("/ui/account/mfa/enroll", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"
        uid = await _uid(service, "fresh")
        assert await service.store.get_totp_secret(uid) is None
        # Even the reauth continuation can't be used to slip past confinement.
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/account/mfa/enroll", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/account/password"


async def test_l4b_rate_limit_paths(engine: Engine) -> None:
    # The 429 contracts: change-password re-raises the JSON 429 (not a 400 HTML re-render); mfa/verify
    # raises _rate_limited. A throttle must never mutate state.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)

    def _deny(_actor: str) -> bool:
        return False

    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        # 7.5.1: mint the MFA_CONFIRM grant BEFORE denying (the mint itself consults the ceremony
        # limiter) so the throttled verify reaches its in-body rate-limit check instead of bouncing
        # to reauth.
        await _mint_action(c, "/ui/account/mfa/confirm")
        # These are POST-session ceremonies: they draw on the per-ACTOR budget, NOT the shared
        # unauthenticated sign-in budget (allow_login_attempt) they used to consume.
        service.allow_reauth_attempt = _deny  # type: ignore[method-assign]
        r = await c.post(
            "/ui/account/password",
            data={"current_password": PW, "new_password": NEW_PW, "new_password2": NEW_PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 429
        r = await c.post(
            "/ui/account/mfa/verify",
            data={"code": "123456"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 429
        uid = await _uid(service, "op")
        user = await service.store.get_user(uid)
        assert user is not None and not user.totp_enabled  # nothing activated


async def test_account_cookie_not_accepted_on_json_routes(engine: Engine) -> None:
    # The /ui cookie must never authorize the JSON self-service routes (bearer-header only).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (
            await c.post("/me/password", json={"current_password": PW, "new_password": NEW_PW})
        ).status_code == 401
        assert (await c.post("/me/mfa/enroll")).status_code == 401
        assert (await c.post("/me/mfa/confirm", json={"code": "123456"})).status_code == 401
        assert (await c.delete("/me/mfa")).status_code == 401
