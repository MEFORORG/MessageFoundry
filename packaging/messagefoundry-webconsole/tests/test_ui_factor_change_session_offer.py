# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1147 (ASVS 7.4.3): an MFA settings change offers to end the caller's other sessions.

Four console lanes change a second factor: TOTP enrolment confirm, TOTP disable, passkey add and
passkey delete. Each success now offers, as part of the ceremony, to sign out every other session
while keeping this one. The offer posts to the existing revoke-others route, so accepting it runs a
fresh re-proof and then the auto-retry (ASVS 7.5.2). Nothing ends unless the caller asks.

These tests are the control on the offer. Remove it from any lane and that lane's test goes red.
They also pin that the offer is bound to the event: a ``?m=`` code alone, typed or replayed,
renders no offer, and neither does a failed attempt."""

from __future__ import annotations

import html
import json
import re

import httpx
import pytest
from _ui_clients import (
    PW,
    SAME_ORIGIN,
    cookie_login,
    held_totp_code,
    mint_bound_proof,
    provision,
    ui_client,
)

from messagefoundry.api.auth_models import CurrentUser, MfaStatusResponse
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import WebAuthnCredential
from messagefoundry_webconsole import pages

#: The offer's form. The account page carries no other form with this action: its sessions card is
#: a plain link to the sessions page, which is the furniture the offer must not be mistaken for.
REVOKE_OTHERS = "/ui/account/sessions/revoke-others"
OFFER = f'action="{REVOKE_OTHERS}"'


async def _service(engine: Engine) -> AuthService:
    # MFA off, so a fresh login is not diverted to enrolment, and the two human-timing floors off,
    # so the suite can drive a ceremony at machine speed (the test_webui.py shape, BACKLOG #2301).
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            require_mfa=False,
        ),
    )
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    return ui_client(engine, service, webauthn_rp_from_request=True)


def _cookie(c: httpx.AsyncClient) -> str:
    token = c.cookies.get("mf_session")
    assert token, "the client holds no session cookie"
    return token


async def _enroll_totp(c: httpx.AsyncClient, service: AuthService, user_id: str) -> httpx.Response:
    """Enrol and confirm TOTP over /ui; return the confirm POST's response (the recovery page)."""
    await mint_bound_proof(c, "/ui/account/mfa/enroll")
    r = await c.post("/ui/account/mfa/enroll", headers=SAME_ORIGIN)
    assert r.status_code == 200, r.text
    secret = await service.store.get_totp_secret(user_id)
    assert secret is not None
    await mint_bound_proof(c, "/ui/account/mfa/confirm")
    with held_totp_code(secret) as code:
        r = await c.post("/ui/account/mfa/verify", data={"code": code}, headers=SAME_ORIGIN)
    assert r.status_code == 200, r.text
    return r


async def _live_hashes(service: AuthService, user_id: str) -> set[str]:
    return {s.token_hash for s in await service.list_sessions(user_id)}


async def test_enroll_confirm_shows_the_codes_and_the_offer_for_the_new_session(
    engine: Engine,
) -> None:
    """Lane 2. The recovery page is the confirm POST's own response, so it carries the offer. The
    confirm re-keys the session, and the count is against the NEW token: counted against the old
    one it would read 2, since the new session would count as another."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        user_id = await provision(service, "op", ["operator"])
        assert (await service.login("op", PW)).ok
        await cookie_login(c, "op")
        before = _cookie(c)
        r = await _enroll_totp(c, service, user_id)
        assert "shown once" in r.text and "<code>" in r.text  # the codes still render
        assert OFFER in r.text
        assert "Sign out my other sessions (1)" in r.text
        assert "Save your recovery codes before" in r.text
        after = _cookie(c)
        assert after != before  # the confirm rotated the session
        # Accepting the offer keeps the NEW session and ends the other one.
        await mint_bound_proof(c, REVOKE_OTHERS)
        r = await c.post(REVOKE_OTHERS, headers=SAME_ORIGIN)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/account/sessions?m=signed_out_others"
        assert await _live_hashes(service, user_id) == {hash_token(_cookie(c))}


async def test_disable_offers_once_and_accepting_reproves_then_keeps_this_session(
    engine: Engine,
) -> None:
    """Lane 3, end to end. The disable success marks the session; the account page it lands on
    consumes the mark. Accepting bounces to /ui/reauth (the terminate grant is single-use and the
    disable did not mint one), and the re-auth auto-retries the revoke, which keeps this session."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        user_id = await provision(service, "op", ["operator"])
        assert (await service.login("op", PW)).ok
        await cookie_login(c, "op")
        await _enroll_totp(c, service, user_id)
        await mint_bound_proof(c, "/ui/account/mfa/disable")
        r = await c.post("/ui/account/mfa/disable", headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=mfa_off"
        page = await c.get(r.headers["location"])
        assert "MFA disabled." in page.text
        assert OFFER in page.text and "Sign out my other sessions (1)" in page.text
        # Single use: the same URL again is page furniture only.
        assert OFFER not in (await c.get("/ui/account?m=mfa_off")).text
        assert len(await _live_hashes(service, user_id)) == 2  # declining ended nothing

        # Accept: the form's POST, with no terminate grant yet.
        bounced = await c.post(REVOKE_OTHERS, headers=SAME_ORIGIN)
        assert bounced.status_code == 303
        assert bounced.headers["location"] == f"/ui/reauth?next={REVOKE_OTHERS}"
        assert len(await _live_hashes(service, user_id)) == 2  # nothing ended before the proof
        form = await c.get(bounced.headers["location"])
        assert form.status_code == 200 and "Sign out all your other sessions" in form.text
        proved = await c.post(
            "/ui/reauth", data={"next": REVOKE_OTHERS, "password": PW}, headers=SAME_ORIGIN
        )
        assert proved.status_code == 200
        assert "data-autosubmit" in proved.text and f'action="{REVOKE_OTHERS}"' in proved.text
        done = await c.post(REVOKE_OTHERS, headers=SAME_ORIGIN)
        assert done.status_code == 303
        assert done.headers["location"] == "/ui/account/sessions?m=signed_out_others"
        assert await _live_hashes(service, user_id) == {hash_token(_cookie(c))}
        assert (await c.get("/ui/account/sessions")).status_code == 200


async def test_passkey_add_offer_is_bound_to_the_event_not_the_redirect_url(
    engine: Engine,
) -> None:
    """Lane 4. Passkey add answers a fetch with JSON and the browser GETs the redirect. The offer
    rides a mark on the session's NEW token. A bare GET of the same URL, by this session before the
    ceremony or by another session of the same user after it, renders no offer."""
    pytest.importorskip("webauthn")
    from _soft_webauthn import SoftAuthenticator
    from webauthn.helpers import base64url_to_bytes

    service = await _service(engine)
    async with _client(engine, service) as c, _client(engine, service) as other:
        user_id = await provision(service, "op", ["operator"])
        await cookie_login(other, "op")
        await cookie_login(c, "op")
        assert OFFER not in (await c.get("/ui/account?m=passkey_added")).text  # forged, before
        before = _cookie(c)
        await mint_bound_proof(c, "/ui/account/webauthn/enroll")
        r = await c.post("/ui/account/webauthn/enroll", headers=SAME_ORIGIN)
        assert r.status_code == 200, r.text
        hook = re.search('data-mf-webauthn-create="([^"]*)"', r.text)
        assert hook is not None
        options = json.loads(html.unescape(hook.group(1)))
        auth = SoftAuthenticator(rp_id="t", origin="http://t")
        resp = json.loads(auth.create_response(base64url_to_bytes(options["challenge"])))
        r = await c.post(
            "/ui/account/webauthn/verify",
            json={"label": "key A", "response": resp},
            headers=SAME_ORIGIN,
        )
        assert r.status_code == 200 and r.json() == {
            "ok": True,
            "redirect": "/ui/account?m=passkey_added",
        }
        assert _cookie(c) != before  # the ceremony rotated the session
        # Another session of the same user, at the same URL: no offer.
        assert OFFER not in (await other.get("/ui/account?m=passkey_added")).text
        page = await c.get("/ui/account?m=passkey_added")
        assert "Passkey added." in page.text
        assert OFFER in page.text and "Sign out my other sessions (1)" in page.text
        assert OFFER not in (await c.get("/ui/account?m=passkey_added")).text  # single use
        assert len(await _live_hashes(service, user_id)) == 2


async def test_passkey_delete_offers_without_the_webauthn_extra(engine: Engine) -> None:
    """Lane 5, with a credential written straight to the store, so the offer is pinned on an
    install without the ``[webauthn]`` extra too."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        user_id = await provision(service, "op", ["operator"])
        assert (await service.login("op", PW)).ok
        await cookie_login(c, "op")
        await service.store.add_webauthn_credential(
            WebAuthnCredential(
                credential_id_hash="synthetic-hash-1147",
                credential_id="c3ludGhldGlj",
                user_id=user_id,
                rp_id="t",
                public_key="c3ludGhldGlj",
                sign_count=0,
                transports=None,
                device_type="single_device",
                backed_up=False,
                label="synthetic key",
                aaguid=None,
                created_at=1.0,
            )
        )
        creds = await service.store.list_webauthn_credentials(user_id)
        path = f"/ui/account/webauthn/{creds[0].credential_id_hash}/delete"
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == "/ui/account?m=passkey_removed"
        page = await c.get(r.headers["location"])
        assert OFFER in page.text and "Sign out my other sessions (1)" in page.text


async def test_a_forged_notice_code_renders_no_offer(engine: Engine) -> None:
    """The scorecard's forged-GET case: every lane's landing URL, typed with no factor change
    behind it, shows the notice and no offer, while another session is live."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        await provision(service, "op", ["operator"])
        assert (await service.login("op", PW)).ok
        await cookie_login(c, "op")
        for code in ("mfa_off", "passkey_added", "passkey_removed"):
            r = await c.get(f"/ui/account?m={code}")
            assert r.status_code == 200
            assert OFFER not in r.text, code


async def test_a_failed_factor_change_offers_nothing(engine: Engine) -> None:
    """A wrong confirm code and a delete of an unknown passkey change nothing, so neither the
    response nor the next account page offers to end the other sessions."""
    service = await _service(engine)
    async with _client(engine, service) as c:
        await provision(service, "op", ["operator"])
        assert (await service.login("op", PW)).ok
        await cookie_login(c, "op")
        await mint_bound_proof(c, "/ui/account/mfa/enroll")
        assert (await c.post("/ui/account/mfa/enroll", headers=SAME_ORIGIN)).status_code == 200
        await mint_bound_proof(c, "/ui/account/mfa/confirm")
        r = await c.post("/ui/account/mfa/verify", data={"code": "000000"}, headers=SAME_ORIGIN)
        assert r.status_code == 400 and OFFER not in r.text
        path = "/ui/account/webauthn/no-such-passkey/delete"
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
        assert r.status_code == 404 and OFFER not in r.text
        assert OFFER not in (await c.get("/ui/account")).text


def test_the_offer_with_no_other_session_has_no_button() -> None:
    """With nothing to end, the card says so and renders no form."""
    me = CurrentUser(user_id="u1", username="op", auth_provider="local", roles=[], permissions=[])
    mfa = MfaStatusResponse(enabled=False, required=False, recovery_codes_remaining=0)
    page = pages.account_page(me, mfa, session_offer=0)
    assert "You have no other active sessions" in page and OFFER not in page
    assert OFFER in pages.account_page(me, mfa, session_offer=2)
    assert OFFER not in pages.account_page(me, mfa)
    assert OFFER not in pages.mfa_recovery_page(["a", "b"], other_sessions=0)
