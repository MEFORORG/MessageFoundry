# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The login-to-MFA floor on the console's two enrolment routes (BACKLOG #2389, #3194).

``POST /ui/account/mfa/verify`` confirms a TOTP enrolment and ``POST /ui/account/webauthn/verify``
finishes a passkey registration. Either can turn a session that still owes its factor into a
satisfied one, so the service floors both against the session's mint
(``[auth].mfa_verify_min_elapsed_seconds``). The console suites that drive a ceremony at machine
speed either turn that floor off or run with require_mfa off and no factor enrolled, where no session
owes a factor and the floor never applies. These tests keep it ON, at its shipped default, with require_mfa on, and
pin what each route answers inside it and past it.

No test sleeps. The wall clock the service and the store read is held, so no time passes between
the sign-in and the early attempt however slow the runner is, and the clock then moves only forward.
A clock that stepped behind a session's own stamps would end the session.

The last three tests pin what the same two routes say when the service refuses a directory account
the directory did not confirm (BACKLOG #3061) or one under a second-step lock (BACKLOG #3810
finding 4), neither of which is a floor refusal, and the passkey page's note on a stray passkey.

Each test names the mutation that must turn it RED.
"""

from __future__ import annotations

import json
import re
import time
import uuid

import pytest
from _ui_clients import (
    SAME_ORIGIN,
    PresentDirectory,
    cookie_login,
    held_totp_code,
    hold_auth_wall_clock,
    mint_bound_proof,
    provision,
    ui_client,
)

from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import TOO_EARLY, AuthService, Elevation
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

FLOOR = AuthSettings().mfa_verify_min_elapsed_seconds
assert FLOOR > 0, "the floor ships off, so these tests would test nothing"


async def _floored_service(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, *, ldap: object | None = None
) -> tuple[AuthService, list[float]]:
    """A service with the floor at its shipped default and require_mfa on, so a fresh sign-in owes
    its factor, and the held clock it reads. The admin-write pacing floor and the sign-in rate
    limit are off: neither is under test, and the ceremony posts several writes at once."""
    now = [time.time()]
    hold_auth_wall_clock(monkeypatch, now)
    service = AuthService(
        engine.store,
        AuthSettings(admin_write_min_interval_seconds=0, login_rate_limit_enabled=False),
        ldap=ldap,  # type: ignore[arg-type]
    )
    await service.initialize()
    return service, now


def _banner(page: str) -> str | None:
    """The error banner a console page renders, the one part a refusal varies, or None."""
    found = re.findall(r'<p class="banner">(.*?)</p>', page)
    assert len(found) <= 1, found
    return found[0] if found else None


async def _too_early_rows(engine: Engine, action: str) -> list[dict[str, object]]:
    rows = await engine.store.list_audit(action=action, limit=50)
    details = [json.loads(str(r["detail"])) for r in rows if r["detail"]]
    return [d for d in details if d.get("reason") == TOO_EARLY]


async def test_a_console_totp_confirm_inside_the_floor_is_an_ordinary_invalid_code(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``confirm_mfa_enrollment`` stops calling the enrolment floor.

    Inside the floor, a good code gets the status and message a wrong code gets past it,
    ``Invalid code.`` with a 400. Past it, after a fresh step-up, the SAME code activates TOTP, so
    the refusal spent no step."""
    service, now = await _floored_service(engine, monkeypatch)
    user_id = await provision(service, "op", ["operator"])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        token = c.cookies.get("mf_session")
        assert token
        assert not await service.mfa_satisfied(token), "the session must owe its factor"
        await mint_bound_proof(c, "/ui/account/mfa/enroll")
        r = await c.post("/ui/account/mfa/enroll", headers=SAME_ORIGIN)
        assert r.status_code == 200, r.text
        secret = await service.store.get_totp_secret(user_id)
        assert secret is not None
        with held_totp_code(secret) as code:
            await mint_bound_proof(c, "/ui/account/mfa/confirm")
            early = await c.post("/ui/account/mfa/verify", data={"code": code}, headers=SAME_ORIGIN)
            assert early.status_code == 400 and _banner(early.text) == "Invalid code."
            rows = await _too_early_rows(engine, "auth.mfa_failed")
            assert [r.get("phase") for r in rows] == ["enroll"]
            user = await service.store.get_user(user_id)
            assert user is not None and not user.totp_enabled

            # Past the floor, a genuinely wrong code gets the answer the early good code got.
            now[0] += FLOOR + 0.001
            await mint_bound_proof(c, "/ui/account/mfa/confirm")
            wrong = f"{(int(code) + 1) % 1_000_000:06d}"  # never the live code at skew 0
            refused = await c.post(
                "/ui/account/mfa/verify", data={"code": wrong}, headers=SAME_ORIGIN
            )
            assert (refused.status_code, _banner(refused.text)) == (400, "Invalid code.")

            # CONTROL: past the floor, the SAME good code activates TOTP and shows the codes.
            await mint_bound_proof(c, "/ui/account/mfa/confirm")
            served = await c.post(
                "/ui/account/mfa/verify", data={"code": code}, headers=SAME_ORIGIN
            )
        assert served.status_code == 200 and "shown once" in served.text, served.text
    user = await service.store.get_user(user_id)
    assert user is not None and user.totp_enabled


async def test_a_console_passkey_registration_inside_the_floor_is_a_failed_verification(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``finish_webauthn_registration`` stops calling the enrolment floor.

    The case the console can reach: a directory account is not covered in the ADR 0197 sense, so its
    Kerberos session, minted unstamped under require_mfa, may register a first passkey. Inside the
    floor the route answers ``400 passkey verification failed``, as for a response that fails
    verification. Past it, the SAME response binds the passkey, so the ceremony stayed in flight."""
    pytest.importorskip("webauthn")
    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    principal = AdPrincipal(
        username="adfloor",
        display_name=None,
        email=None,
        dn="CN=adfloor,DC=x",
        groups=frozenset(),
        directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "adfloor")),
    )
    service, now = await _floored_service(engine, monkeypatch, ldap=PresentDirectory(principal))
    out = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert out.ok and out.token is not None and out.identity is not None
    assert not await service.mfa_satisfied(out.token), "the session must owe its factor"
    # The ceremony is begun at the service. The begin route takes an action-bound password re-proof,
    # and a directory account proves its password at the directory, which this suite has none of.
    # The route under test is the finish, which needs only a recent re-proof, stamped here.
    options = json.loads(
        await service.begin_webauthn_registration(
            out.identity, token=out.token, rp_id="t", rp_name="MessageFoundry"
        )
    )
    await service.store.mark_session_reauthed(hash_token(out.token))
    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", out.token)
        key = SoftAuthenticator(rp_id="t", origin="http://t")
        response = json.loads(key.create_response(base64url_to_bytes(options["challenge"])))
        body = {"label": "key", "response": response}

        early = await c.post("/ui/account/webauthn/verify", json=body, headers=SAME_ORIGIN)
        assert (early.status_code, early.json()) == (
            400,
            {"ok": False, "error": "passkey verification failed"},
        )
        rows = await _too_early_rows(engine, "auth.webauthn_failed")
        assert [r.get("phase") for r in rows] == ["enroll"]
        assert await service.store.list_webauthn_credentials(out.identity.user_id) == []

        # CONTROL: past the floor, the SAME response binds the passkey and satisfies the session.
        now[0] += FLOOR + 0.001
        served = await c.post("/ui/account/webauthn/verify", json=body, headers=SAME_ORIGIN)
        assert served.status_code == 200 and served.json()["ok"] is True, served.text
    assert len(await service.store.list_webauthn_credentials(out.identity.user_id)) == 1


# --- what the two enrolment routes say for a directory refusal (BACKLOG #3061) -----------------

_DIRECTORY_UNCONFIRMED_TEXT = "The directory could not confirm your account."


_LOCKED_TEXT = "Account locked. Try again later."

#: The refusal each arm stubs, and the banner it must show. "wrong" is the control: an ordinary
#: wrong proof keeps the leg's own words.
_ENROL_REFUSALS = pytest.mark.parametrize(
    "refusal", ["directory", "locked", "wrong"], ids=["directory-refused", "locked", "wrong-proof"]
)


def _refusal(refusal: str) -> Elevation:
    return Elevation(directory_unconfirmed=refusal == "directory", locked=refusal == "locked")


@_ENROL_REFUSALS
async def test_the_console_totp_confirm_says_why_an_unchecked_code_was_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """``confirm_mfa_enrollment`` asks the directory before it checks a directory account's code,
    so a refusal never judged the code. The service answer is stubbed; the refusal itself is pinned
    in tests/test_enrolment_directory_recheck.py. A second-step lock found by the re-read after the
    lookup never judged the code either (BACKLOG #3810 finding 4).

    RED when: ``/ui/account/mfa/verify`` drops the directory_unconfirmed or the locked branch (the
    refused arm then reads "Invalid code."), or applies either to an ordinary wrong code (the
    control arm)."""
    service, _now = await _floored_service(engine, monkeypatch)
    await provision(service, "op", ["operator"])

    async def _refused(*_args: object, **_kwargs: object) -> Elevation:
        return _refusal(refusal)

    async with ui_client(engine, service) as c:
        await cookie_login(c, "op")
        await mint_bound_proof(c, "/ui/account/mfa/enroll")
        assert (await c.post("/ui/account/mfa/enroll", headers=SAME_ORIGIN)).status_code == 200
        await mint_bound_proof(c, "/ui/account/mfa/confirm")
        monkeypatch.setattr(service, "confirm_mfa_enrollment", _refused)
        r = await c.post("/ui/account/mfa/verify", data={"code": "123456"}, headers=SAME_ORIGIN)
    assert r.status_code == 400
    banner = _banner(r.text)
    assert banner is not None
    assert (_DIRECTORY_UNCONFIRMED_TEXT in banner) is (refusal == "directory")
    assert (banner == _LOCKED_TEXT) is (refusal == "locked")
    assert (banner == "Invalid code.") is (refusal == "wrong")


@_ENROL_REFUSALS
async def test_the_console_passkey_finish_says_why_an_unchecked_passkey_was_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    """As above, for ``finish_webauthn_registration``. The service answer is stubbed.

    RED when: ``/ui/account/webauthn/verify`` drops the directory_unconfirmed or the locked branch
    (the refused arm then reads "passkey verification failed"), or applies either to an ordinary
    failed attestation."""
    principal = AdPrincipal(
        username="adwords",
        display_name=None,
        email=None,
        dn="CN=adwords,DC=x",
        groups=frozenset(),
        directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "adwords")),
    )
    service, _now = await _floored_service(engine, monkeypatch, ldap=PresentDirectory(principal))
    out = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert out.ok and out.token is not None
    await service.store.mark_session_reauthed(hash_token(out.token))

    async def _refused(*_args: object, **_kwargs: object) -> Elevation:
        return _refusal(refusal)

    monkeypatch.setattr(service, "finish_webauthn_registration", _refused)
    async with ui_client(engine, service, webauthn_rp_from_request=True) as c:
        c.cookies.set("mf_session", out.token)
        r = await c.post(
            "/ui/account/webauthn/verify",
            json={"label": "key", "response": {}},
            headers=SAME_ORIGIN,
        )
    assert r.status_code == 400, r.text
    error = r.json()["error"]
    assert (_DIRECTORY_UNCONFIRMED_TEXT in error) is (refusal == "directory")
    assert (error == _LOCKED_TEXT) is (refusal == "locked")
    assert (error == "passkey verification failed") is (refusal == "wrong")


def test_the_passkey_page_says_a_stray_passkey_can_be_deleted() -> None:
    """BACKLOG #3810 finding 4: every refusal at the passkey finish comes after the authenticator
    made its credential, as it did before #3061, so a failed enrolment can leave one behind that
    the server never stored. RED when the page stops saying it can be deleted."""
    from messagefoundry_webconsole import pages

    page = str(pages.webauthn_enroll_page("{}"))
    assert "was not added to your account and cannot sign you in" in page
    assert "You can delete it from your browser" in page
