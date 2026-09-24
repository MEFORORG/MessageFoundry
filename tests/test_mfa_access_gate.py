# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.3.3 / 6.3.4 — MFA as an ACCESS gate, and per-mechanism directory strength.

6.3.3 moved the second factor from the step-up boundary to the front door: an MFA-pending session is
refused on every authorized route, not merely on sensitive ones. 6.3.4 stopped minting every directory
session MFA-verified regardless of what the directory actually enforced. 6.8.4 finished that: the
Kerberos leg asserts nothing the engine can read, so it grants nothing, and a directory account enrols
an engine factor like any other (BACKLOG #1144).

Each test names the mutation that must turn it RED, because several of these would pass either way if
written carelessly — a session's ``mfa_verified_at`` column can be correct while nothing gates on it.
"""

from __future__ import annotations

import ast
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _mfa_grant import mfa_grant_values
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import STEP_UP_ACTION_SESSION_TERMINATE, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import WebAuthnCredential

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "mfa_gate.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    service = AuthService(engine.store, settings or AuthSettings(login_rate_limit_enabled=False))
    await service.initialize()
    return service


#: httpx's own ASGITransport default, named rather than left implicit. ``_client`` in
#: tests/test_api_auth.py carries the reasoning; this is the same constant for the same reason.
_DEFAULT_PEER = ("127.0.0.1", 123)


def _client(
    engine: Engine, service: AuthService, *, peer: tuple[str, int] | None = None
) -> httpx.AsyncClient:
    """``peer`` pins the ASGI scope's client address; omitted, ``_DEFAULT_PEER`` stands.

    Either way ``request.client`` is a real address and never None, so an assertion on the audited
    ``client`` cannot degenerate to ``None == None`` and pass against unfixed code. Pass ``peer``
    wherever the address is the subject.

    The full rationale -- including when modelling an absent peer IS the right thing to do, and why
    the loopback default is not neutral for the network allowlist -- is on ``_client`` in
    tests/test_api_auth.py, stated once there rather than restated here (BACKLOG #1644)."""
    transport = httpx.ASGITransport(
        app=create_app(engine, auth=service), client=_DEFAULT_PEER if peer is None else peer
    )
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    # Admin-created accounts force first-login rotation; clear it so must_change does not mask the
    # MFA refusal under test (must_change is enforced FIRST by design).
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return user_id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200
    return str(r.json()["token"])


def _principal(username: str = "aduser") -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name="AD User",
        email=None,
        dn=f"CN={username},DC=x",
        groups=frozenset(),
    )


# --- 6.3.3: the access gate -------------------------------------------------


async def test_pending_session_is_refused_on_an_ordinary_authorized_route(
    engine: Engine,
) -> None:
    """RED when: the MFA block in api/security.py:require() is deleted.

    The route chosen is a plain read on require(), NOT a step-up route — a step-up route would 403
    from the pre-existing WP-14 check and pass either way, proving nothing about 6.3.3.
    """
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        tok = await _login(c, "vw")
        r = await c.get("/messages", headers=_auth(tok))
        assert r.status_code == 403
        assert r.headers.get("X-MFA-Required") == "1"


async def test_the_refusal_is_audited_so_probing_is_not_silent(engine: Engine) -> None:
    """RED when: the ``audit_mfa_denied`` call is removed from require().

    The gate sits ABOVE the permission loop, so ``auth.permission_denied`` never fires for a pending
    session. Without its own row a stolen password-only token could sweep the whole surface and leave
    the audit log completely empty.
    """
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    # RFC 5737 TEST-NET-1, so it cannot resolve to a real host. See ``_client`` for why the address
    # has to be set here at all.
    async with _client(engine, service, peer=("192.0.2.77", 51234)) as c:
        tok = await _login(c, "vw")
        assert (await c.get("/messages", headers=_auth(tok))).status_code == 403
    denied = [a for a in await engine.store.list_audit() if a["action"] == "auth.mfa_denied"]
    assert denied, "an MFA refusal must leave an audit row; otherwise probing is invisible"
    assert denied[-1]["actor"] == "vw"
    assert "/messages" in (denied[-1]["detail"] or "")
    # The row must never carry the bearer token or a code — only the path.
    assert "Bearer" not in (denied[-1]["detail"] or "")
    # BACKLOG #1644 (ADR 0150): and it records WHERE FROM. This row is the ONLY evidence a stolen
    # password-only token was used at all — the paragraph above says the trail would otherwise be
    # empty — so the address is the half an incident responder acts on. RED when ``client=`` is
    # dropped from require()'s ``audit_mfa_denied`` call.
    assert denied[-1]["client"] == "192.0.2.77"


async def test_exempt_routes_stay_reachable_while_pending(engine: Engine) -> None:
    """RED when: an entry is dropped from _MFA_EXEMPT_ROUTES.

    These are the self-service routes a pending session must keep, or the account is bricked.
    """
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        tok = await _login(c, "vw")
        h = _auth(tok)
        assert (await c.get("/auth/me", headers=h)).status_code == 200
        assert (await c.get("/me/mfa", headers=h)).status_code == 200
        assert (await c.post("/me/reauth", json={"password": PW}, headers=h)).status_code == 200


def test_the_exempt_set_is_keyed_on_method_and_path() -> None:
    """RED when: _MFA_EXEMPT_ROUTES is flattened to bare paths.

    STRUCTURAL on purpose. The behavioural version of this test does NOT work, and finding that out
    was the point of running the mutation: flattening the set to paths leaves ``DELETE /me/mfa``
    refused anyway, because ``require_step_up_action`` applies its own ``mfa_satisfied`` check. A
    behavioural assertion therefore passes under both spellings and proves nothing.

    So the keying is asserted directly. ``GET /me/mfa`` (read your factor status) and ``DELETE
    /me/mfa`` (turn your factor OFF) are the same path string; keying on the path alone would exempt
    the disable route the moment that second control is ever refactored away — a latent hole rather
    than a live one, which is precisely what a structural guard is for.
    """
    from messagefoundry.api.security import _MFA_EXEMPT_ROUTES

    assert all(isinstance(entry, tuple) and len(entry) == 2 for entry in _MFA_EXEMPT_ROUTES), (
        "_MFA_EXEMPT_ROUTES must stay keyed on (METHOD, path) — a path-only set exempts every verb"
    )
    assert ("GET", "/me/mfa") in _MFA_EXEMPT_ROUTES
    assert ("DELETE", "/me/mfa") not in _MFA_EXEMPT_ROUTES
    assert not any(path == "/me/sessions" for _, path in _MFA_EXEMPT_ROUTES)


async def test_disabling_your_second_factor_is_refused_while_pending(engine: Engine) -> None:
    """RED when: BOTH the base gate and require_step_up_action's mfa_satisfied check are removed.

    Two independent controls hold this line. The step-up check is defence-in-depth **that is
    currently load-bearing for this route** under a path-keyed exempt set — do not delete it as
    "redundant" (see the structural test above for why that is not a safe simplification).
    """
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        h = _auth(await _login(c, "vw"))
        assert (await c.get("/me/mfa", headers=h)).status_code == 200
        assert (await c.delete("/me/mfa", headers=h)).status_code == 403


async def test_session_inventory_is_not_readable_while_pending(engine: Engine) -> None:
    """RED when: /me/sessions or /me/security-events is added back to _MFA_EXEMPT_ROUTES.

    A pending session has proven ONE factor — the attacker-holds-the-password case. Its session list
    and client-IP history are reconnaissance, and neither route is on the escape path.
    """
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    async with _client(engine, service) as c:
        tok = await _login(c, "vw")
        h = _auth(tok)
        assert (await c.get("/me/sessions", headers=h)).status_code == 403
        assert (await c.get("/me/security-events", headers=h)).status_code == 403


async def test_scope_administrators_restores_the_pre_633_posture(engine: Engine) -> None:
    """RED when: require_mfa_scope stops being consulted in _mfa_required_for.

    Both arms are asserted from one settings dial, so a change that hard-wires either answer reds.
    """
    narrowed = await _service(
        engine,
        AuthSettings(login_rate_limit_enabled=False, require_mfa_scope="administrators"),
    )
    await _add(narrowed, "vw", Role.VIEWER)
    await _add(narrowed, "adm", Role.ADMINISTRATOR)
    async with _client(engine, narrowed) as c:
        assert (await c.get("/messages", headers=_auth(await _login(c, "vw")))).status_code == 200
        r = await c.get("/messages", headers=_auth(await _login(c, "adm")))
        assert r.status_code == 403 and r.headers.get("X-MFA-Required") == "1"


async def test_an_enrolled_account_cannot_self_promote_by_binding_a_second_factor(
    engine: Engine,
) -> None:
    """RED when: the factor-binding guard is removed from AuthService.reauth.

    The bypass an adversarial pass found in this very change, reproduced as its exploit chain. The
    gate's carve-out lets an MFA-pending session reach the ENROLLMENT routes, which is correct while
    the account has no factor — but ``confirm_mfa_enrollment`` marks the session MFA-satisfied on
    success. For an account that ALREADY has a factor that turns enrollment into a promotion path:
    an attacker holding only the password re-auths (password-only, MFA-exempt), enrols a NEW
    authenticator it controls, and is promoted — defeating the second factor outright and leaving a
    durable attacker-bound authenticator behind.

    Note the chain uses nothing but the password. That precondition is precisely what MFA exists to
    survive, which is why this is the whole cell rather than a hardening nicety.
    """
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)

    # The victim already holds a factor, so the deadlock carve-out does NOT apply to them.
    victim = await service.store.get_user_by_username("vic")
    assert victim is not None
    identity = await service.identity_for_user_id(victim.id)
    assert identity is not None
    setup = await service.login("vic", PW)
    assert setup.ok and setup.token is not None
    enrollment = await service.begin_mfa_enrollment(identity)
    assert (
        await service.confirm_mfa_enrollment(
            identity, totp.totp(enrollment.secret), token=setup.token
        )
    ).ok

    async with _client(engine, service) as c:
        # The attacker knows the password and nothing else.
        tok = await _login(c, "vic")
        h = _auth(tok)
        assert (await c.get("/messages", headers=h)).status_code == 403  # gate holds, for now

        # Step 1 of the chain: password-only re-auth naming a factor-binding purpose. It still
        # succeeds as a re-auth (the session window legitimately refreshes)...
        r = await c.post("/me/reauth", json={"password": PW, "purpose": "mfa_enroll"}, headers=h)
        assert r.status_code == 200
        # The re-auth re-keyed the session (ASVS 7.2.4), so the rest of the chain has to be driven
        # with the ROTATED bearer -- otherwise the enroll below would 401 on a dead token and the
        # test would "pass" without ever reaching the guard it exists to prove.
        tok = str(r.json()["token"])
        h = _auth(tok)

        # ...but it must NOT have minted the action grant, so the enrollment route stays shut.
        enroll = await c.post("/me/mfa/enroll", headers=h)
        assert enroll.status_code == 403, (
            "an MFA-pending session with an EXISTING factor bound a new one using the password "
            "alone — the 6.3.3 gate is bypassable by anyone who knows the password"
        )
        # And the gate still holds afterwards: no promotion happened.
        assert await service.mfa_satisfied(tok) is False
        assert (await c.get("/messages", headers=h)).status_code == 403


async def test_bootstrap_enrollment_from_a_pending_session_still_works(engine: Engine) -> None:
    """RED when: the factor-binding guard over-reaches and blocks the un-enrolled case too.

    The other side of the same coin. An account with NO factor MUST be able to enrol from a
    password-only pending session — that is the deadlock carve-out, and blocking it bricks every
    account on the day require_mfa_scope widens. Pinned beside the bypass test so a fix for one
    cannot silently break the other.
    """
    service = await _service(engine)
    await _add(service, "fresh", Role.VIEWER)
    async with _client(engine, service) as c:
        tok = await _login(c, "fresh")
        h = _auth(tok)
        assert (await c.get("/messages", headers=h)).status_code == 403
        elevated = await c.post(
            "/me/reauth", json={"password": PW, "purpose": "mfa_enroll"}, headers=h
        )
        assert elevated.status_code == 200
        h = _auth(str(elevated.json()["token"]))  # re-keyed by the re-auth
        assert (await c.post("/me/mfa/enroll", headers=h)).status_code == 200


@pytest.mark.parametrize("action_step_up", (True, False), ids=("enforced", "opted-out"))
async def test_the_existing_factor_is_required_whatever_the_step_up_knob_says(
    engine: Engine, action_step_up: bool
) -> None:
    """RED when: the ``factor_binding_is_blocked`` refusal leaves ``_action_step_up_ok``.

    The ``opted-out`` arm is the one that matters. The guard in ``AuthService.reauth`` is keyed on
    the re-auth's ``purpose``, so a purpose-LESS re-auth walks past it while still refreshing the
    session window — and under ``[auth].require_action_step_up = false`` that window is the whole
    gate. A password holder would therefore be able to enrol a NEW factor on an account that already
    holds one, then be promoted by the confirm ceremony, which is an account takeover reachable by
    flipping a config knob. A control a knob can switch off is not a control, so the refusal sits
    above the fork and the ``enforced`` arm pins that the same refusal covers both branches.

    THE VICTIM HOLDS A PASSKEY, NOT A TOTP SECRET, AND THAT IS DELIBERATE. Against a TOTP holder
    ``begin_mfa_enrollment`` refuses on its own ("MFA is already enabled") with a 400, so the route
    answers 400 whether the gate opened or not and a 403 assertion would grade a gate that is wide
    open. A passkey holder has ``totp_enabled`` False, so the TOTP lane is a real second-factor
    bind: measured against the unfixed code, the opted-out arm enrolls and returns **200**.
    """
    service = await _service(
        engine,
        AuthSettings(login_rate_limit_enabled=False, require_action_step_up=action_step_up),
    )
    await _add(service, "vic", Role.VIEWER)

    # The victim really holds a factor, so the enrollment deadlock carve-out does not cover them.
    victim = await service.store.get_user_by_username("vic")
    assert victim is not None
    await engine.store.add_webauthn_credential(
        WebAuthnCredential(
            credential_id_hash="vic-passkey-hash",
            credential_id="vic-passkey-id-b64url",
            user_id=victim.id,
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
    assert await service.store.has_webauthn_credentials(victim.id) is True

    async with _client(engine, service) as c:
        tok = await _login(c, "vic")  # the attacker knows the password and nothing else
        h = _auth(tok)
        # A purpose-LESS re-auth. Nothing refuses it: it is a genuine password proof, and the
        # factor-binding guard on the mint never runs because there is no purpose to bind.
        r = await c.post("/me/reauth", json={"password": PW}, headers=h)
        assert r.status_code == 200
        tok = str(r.json()["token"])  # the re-auth re-keys the session (ASVS 7.2.4)
        h = _auth(tok)
        # The positive control. Without it a refusal for some OTHER reason (a stale window) would
        # read as this guard working, and the opted-out arm would pass while the hole stood open.
        assert await service.has_recent_step_up(tok) is True

        enroll = await c.post("/me/mfa/enroll", headers=h)
        assert enroll.status_code == 403, (
            "an MFA-pending session on an ALREADY-ENROLLED account bound a new factor with the "
            "password alone — the existing passkey is what should have been required"
        )
        # The confirm lane is refused on its own, not merely starved of a staged secret.
        confirm = await c.post("/me/mfa/confirm", json={"code": "000000"}, headers=h)
        assert confirm.status_code == 403
        # Nothing was staged, so the takeover has no second step to take.
        assert await service.store.get_totp_secret(victim.id) is None
        # No promotion happened: the session is still behind the 6.3.3 gate.
        assert await service.mfa_satisfied(tok) is False
        assert (await c.get("/messages", headers=h)).status_code == 403


# --- 6.3.3 / 7.5.2: ending sessions from a pending session (BACKLOG #1951) -------------------


async def _enroll_totp_out_of_band(
    service: AuthService, username: str, *, now: float | None = None
) -> tuple[str, str]:
    """Activate TOTP on a service-level session; return ``(secret, that session's token)``.

    The ceremony runs on its OWN session, which ``confirm_mfa_enrollment`` marks MFA-satisfied and
    re-keys. That session stands in for the real user's signed-in device, so a terminate that
    reaches it shows up as a dead token. A caller that later verifies a code pins the TOTP clock and
    passes that instant as ``now``: enrollment consumes the activating step (BACKLOG #1021)."""
    user = await service.store.get_user_by_username(username)
    assert user is not None
    identity = await service.identity_for_user_id(user.id)
    assert identity is not None
    setup = await service.login(username, PW)
    assert setup.ok and setup.token is not None
    enrollment = await service.begin_mfa_enrollment(identity)
    code = (
        totp.totp(enrollment.secret, now=now) if now is not None else fresh_totp(enrollment.secret)
    )
    confirmed = await service.confirm_mfa_enrollment(identity, code, token=setup.token)
    assert confirmed.ok and confirmed.token is not None
    return enrollment.secret, confirmed.token


async def _reauth_to_terminate(c: httpx.AsyncClient, tok: str) -> str:
    """Re-prove the password for ``session_terminate``; assert it succeeds, return the new token.

    It succeeds even where the grant is refused: it is still a genuine password proof, and the
    session is re-keyed either way (ASVS 7.2.4)."""
    r = await c.post(
        "/me/reauth",
        json={"password": PW, "purpose": STEP_UP_ACTION_SESSION_TERMINATE},
        headers=_auth(tok),
    )
    assert r.status_code == 200
    return str(r.json()["token"])


@pytest.mark.parametrize("action_step_up", (True, False), ids=("enforced", "opted-out"))
async def test_a_pending_session_cannot_end_an_enrolled_accounts_sessions(
    engine: Engine, action_step_up: bool
) -> None:
    """RED when: ``session_terminate`` leaves the set ``_factor_binding_is_blocked`` refuses.

    The chain BACKLOG #1951 records. ``POST /me/reauth`` is MFA-exempt, and both terminate routes
    ride ``require_reauth_only_action`` (``mfa_gate=False``). So a caller holding only the password
    could re-prove it from a pending session and sign an enrolled user out of every other session.
    The exemption exists for an account with NO factor, which cannot satisfy a gate. This account
    has one, so it must prove it first.

    The ``opted-out`` arm is the one the route-side refusal carries alone. Under
    ``require_action_step_up = false`` a re-auth refreshes the session window, and the window is the
    whole gate. The ``enforced`` arm also pins the MINT-side refusal: the re-auth must leave no
    ``session_terminate`` grant behind for a later request to spend.
    """
    service = await _service(
        engine,
        AuthSettings(login_rate_limit_enabled=False, require_action_step_up=action_step_up),
    )
    await _add(service, "vic", Role.VIEWER)
    _secret, victim_token = await _enroll_totp_out_of_band(service, "vic")
    assert await service.mfa_satisfied(victim_token) is True  # the real user's signed-in device

    async with _client(engine, service) as c:
        tok = await _login(c, "vic")  # the attacker knows the password and nothing else
        assert await service.mfa_satisfied(tok) is False

        for path in (f"/me/sessions/{hash_token(victim_token)}", "/me/sessions"):
            tok = await _reauth_to_terminate(c, tok)
            # The positive control. Without it a refusal for some OTHER reason (a stale window)
            # would read as this guard working, and the opted-out arm would pass with the hole open.
            assert await service.has_recent_step_up(tok) is True

            ended = await c.delete(path, headers=_auth(tok))
            assert ended.status_code == 403, (
                f"DELETE {path} from an MFA-pending session on an ENROLLED account succeeded "
                "with the password alone"
            )
            # MFA-required, not step-up: a step-up header would send the client back to
            # POST /me/reauth, which mints nothing here, in a loop.
            assert ended.headers.get("X-MFA-Required") == "1"
            assert "X-Step-Up-Required" not in ended.headers
            if action_step_up:
                # The route refuses BEFORE it pops a grant, so a minted one would still be here.
                assert (
                    await service.has_action_step_up(tok, STEP_UP_ACTION_SESSION_TERMINATE) is False
                ), "the re-auth minted a session_terminate grant for a pending session"

        # The real user's device was not signed out, and nothing promoted the attacker.
        assert await service.identity_for_token(victim_token) is not None
        assert await service.mfa_satisfied(tok) is False

    # The trail tells a refused re-proof from a granted one, and records each refused terminate.
    audit = await engine.store.list_audit()
    reauths = [json.loads(a["detail"]) for a in audit if a["action"] == "auth.reauth"]
    assert [r["grant_refused"] for r in reauths] == [True, True]
    denied = [a["detail"] or "" for a in audit if a["action"] == "auth.mfa_denied"]
    assert any("/me/sessions" in d for d in denied)


async def test_a_session_that_proved_its_second_factor_can_end_sessions(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal ignores ``mfa_satisfied`` and blocks every enrolled account.

    The other side of the test above. Proving the existing factor at ``POST /auth/mfa-verify`` is
    the way through, so a session that did it ends other sessions exactly as before.
    """
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    secret, other_token = await _enroll_totp_out_of_band(service, "vic", now=t0)

    async with _client(engine, service) as c:
        tok = await _login(c, "vic")
        t1 = t0 + totp.DEFAULT_PERIOD  # a strictly later step: enrollment consumed its own
        pin_totp_clock(monkeypatch, t1)
        r = await c.post(
            "/auth/mfa-verify", json={"code": totp.totp(secret, now=t1)}, headers=_auth(tok)
        )
        assert r.status_code == 200
        tok = await _reauth_to_terminate(c, str(r.json()["token"]))
        r = await c.delete("/me/sessions", headers=_auth(tok))
        assert r.status_code == 200
        assert await service.identity_for_token(other_token) is None
        assert await service.identity_for_token(tok) is not None


async def test_an_account_with_no_factor_still_ends_sessions_from_a_pending_session(
    engine: Engine,
) -> None:
    """RED when: the refusal over-reaches and blocks the un-enrolled case too.

    This is the path the comment on ``_MFA_EXEMPT_ROUTES`` keeps on purpose. An account with no
    factor is pending under the default ``require_mfa``, and it has nothing to prove at
    ``/auth/mfa-verify``. A password re-proof is the only way it can end a session it does not
    recognise. Pinned beside the refusal so a fix for one cannot silently break the other.
    """
    service = await _service(engine)
    await _add(service, "fresh", Role.VIEWER)
    other = await service.login("fresh", PW)
    assert other.ok and other.token is not None

    async with _client(engine, service) as c:
        tok = await _login(c, "fresh")
        assert (await c.get("/messages", headers=_auth(tok))).status_code == 403  # pending
        tok = await _reauth_to_terminate(c, tok)
        r = await c.delete("/me/sessions", headers=_auth(tok))
        assert r.status_code == 200
        assert await service.identity_for_token(other.token) is None


def test_every_reauth_only_gate_action_is_refused_to_a_pending_enrolled_session() -> None:
    """RED when: a route takes a ``*_reauth_only_action`` gate for an action that is not in
    ``AuthService._PENDING_REFUSED_ACTIONS``.

    Those gates skip the MFA access gate so an account with no factor is not locked out. That skip
    is safe for an account WITH a factor only because the refusal set names the action. #1951 was
    exactly this omission: ``session_terminate`` was wired onto the gate and never added to the set.
    So every action either gate is called with must be in it. The scan covers every module of the
    engine and console packages, as a bare name or an attribute call. It does not reach the
    action-less ``require_ui_reauth_only``, which never consults the set.
    """
    import messagefoundry
    import messagefoundry.auth.service as service_module
    import messagefoundry_webconsole

    gates = {"require_reauth_only_action", "require_ui_reauth_only_action"}
    roots = [Path(messagefoundry.__file__).parent, Path(messagefoundry_webconsole.__file__).parent]
    wired: set[str] = set()
    for source in (f for root in roots for f in root.rglob("*.py")):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name not in gates:
                continue
            kw = [k.value for k in node.keywords if k.arg == "action"]
            arg = node.args[0] if node.args else kw[0]
            assert isinstance(arg, (ast.Name, ast.Attribute)), f"{source}: {ast.dump(arg)}"
            const = arg.id if isinstance(arg, ast.Name) else arg.attr
            wired.add(getattr(service_module, const))
    # The positive control: an empty or narrowed scan would make the subset check pass vacuously.
    assert {STEP_UP_ACTION_SESSION_TERMINATE, "mfa_enroll", "webauthn_enroll"} <= wired
    missing = wired - AuthService._PENDING_REFUSED_ACTIONS
    assert not missing, f"reauth-only gate actions a pending enrolled session could use: {missing}"


# --- 6.3.3 / 7.5.1: changing the password from a pending session (BACKLOG #1954) -------------

PW2 = "another-strong-test-passphrase"  # the rotated password; satisfies the same policy


async def _change_password(
    c: httpx.AsyncClient, tok: str, *, current: str = PW, new: str = PW2
) -> httpx.Response:
    return await c.post(
        "/me/password",
        json={"current_password": current, "new_password": new},
        headers=_auth(tok),
    )


async def test_a_pending_session_cannot_change_an_enrolled_accounts_password(
    engine: Engine,
) -> None:
    """RED when: ``POST /me/password`` stops refusing a pending session on an account with a factor.

    The chain BACKLOG #1954 records. The route is MFA-exempt so an account with NO factor can
    rotate, and changing the password revokes every session. So a caller holding only the password
    could, from a pending session, lock the real user out and sign them out everywhere. This account
    has a factor, so it must prove it first.
    """
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    _secret, victim_token = await _enroll_totp_out_of_band(service, "vic")

    async with _client(engine, service, peer=("192.0.2.54", 40000)) as c:
        tok = await _login(c, "vic")  # the attacker knows the password and nothing else
        r = await _change_password(c, tok)
        assert r.status_code == 403, "a pending session changed an enrolled account's password"
        assert r.headers.get("X-MFA-Required") == "1"
        assert "X-Step-Up-Required" not in r.headers

    # Nothing changed: the real user's device is still signed in, and the old password still works.
    assert await service.identity_for_token(victim_token) is not None
    assert (await service.login("vic", PW)).ok
    denied = [a for a in await engine.store.list_audit() if a["action"] == "auth.mfa_denied"]
    assert any("/me/password" in (a["detail"] or "") for a in denied)
    assert denied[-1]["client"] == "192.0.2.54"


async def test_a_reset_account_with_a_factor_proves_it_and_then_rotates(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``/auth/mfa-verify`` leaves ``_MUST_CHANGE_EXEMPT_PATHS``.

    The flow the refusal above must not strand. ``admin_reset_password`` sets must-change and keeps
    the account's factors, so the next session is both must-change and pending. The password route
    now wants the factor first, so the factor step has to be reachable under the must-change
    confinement. Without it this account could neither rotate nor verify: the brick.
    """
    service = await _service(engine)
    user_id = await _add(service, "vic", Role.VIEWER)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    secret, _ = await _enroll_totp_out_of_band(service, "vic", now=t0)
    temp = (await service.admin_reset_password(user_id, actor="test")).password

    async with _client(engine, service) as c:
        r = await c.post("/auth/login", json={"username": "vic", "password": temp})
        assert r.status_code == 200 and r.json()["must_change_password"] is True
        tok = str(r.json()["token"])
        # must_change still outranks the second factor on an ordinary route.
        refused = await c.get("/messages", headers=_auth(tok))
        assert refused.status_code == 403 and "X-MFA-Required" not in refused.headers
        # The rotation route names the missing factor instead of refusing blind.
        r = await _change_password(c, tok, current=temp)
        assert r.status_code == 403 and r.headers.get("X-MFA-Required") == "1"

        t1 = t0 + totp.DEFAULT_PERIOD  # a strictly later step: enrollment consumed its own
        pin_totp_clock(monkeypatch, t1)
        r = await c.post(
            "/auth/mfa-verify", json={"code": totp.totp(secret, now=t1)}, headers=_auth(tok)
        )
        assert r.status_code == 200, r.text
        r = await _change_password(c, str(r.json()["token"]), current=temp)
        assert r.status_code == 200, r.text
    assert (await service.login("vic", PW2)).ok


async def test_a_must_change_account_with_no_factor_still_rotates_from_a_pending_session(
    engine: Engine,
) -> None:
    """RED when: the refusal over-reaches and blocks an account with no factor.

    Both shipped producers of a must-change account with no factor: an administrator-created user
    and the bootstrap administrator. Each is pending under the default ``require_mfa`` and has
    nothing to prove at ``/auth/mfa-verify``, so rotating first is the only way forward. This is
    also why must-change stays ahead of the MFA gate in ``require()``.
    """
    service = AuthService(engine.store, AuthSettings(login_rate_limit_enabled=False))
    boot = await service.initialize()  # the FIRST initialize mints the bootstrap admin
    assert boot is not None
    await service.create_local_user(
        username="newbie",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    async with _client(engine, service) as c:
        for username, password in ((boot.username, boot.password), ("newbie", PW)):
            r = await c.post("/auth/login", json={"username": username, "password": password})
            assert r.status_code == 200 and r.json()["must_change_password"] is True
            tok = str(r.json()["token"])
            assert await service.mfa_satisfied(tok) is False  # pending, with nothing to prove
            r = await _change_password(c, tok, current=password)
            assert r.status_code == 200, f"{username}: {r.text}"


async def test_a_satisfied_session_changes_the_password_as_before(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the refusal ignores ``mfa_satisfied`` and blocks every enrolled account."""
    service = await _service(engine)
    await _add(service, "vic", Role.VIEWER)
    t0 = 1_000_000.0
    pin_totp_clock(monkeypatch, t0)
    secret, other_token = await _enroll_totp_out_of_band(service, "vic", now=t0)
    async with _client(engine, service) as c:
        tok = await _login(c, "vic")
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        r = await c.post(
            "/auth/mfa-verify", json={"code": totp.totp(secret, now=t1)}, headers=_auth(tok)
        )
        assert r.status_code == 200
        r = await _change_password(c, str(r.json()["token"]))
        assert r.status_code == 200, r.text
    # A real change still signs the account out everywhere.
    assert await service.identity_for_token(other_token) is None


@pytest.mark.parametrize(
    ("mfa_verified", "enrolled"),
    ((False, False), (True, False), (False, True)),
    ids=("pending", "verified", "pending-with-a-factor"),
)
async def test_a_directory_account_is_still_told_its_password_lives_in_the_directory(
    engine: Engine, mfa_verified: bool, enrolled: bool
) -> None:
    """RED when: the refusal pre-empts the directory 400.

    A directory session with no engine factor is pending under the default ``require_mfa`` (the
    directory floor in ``mfa_satisfied``), and it has nothing to prove. One WITH an engine factor
    (BACKLOG #1144) is left to the handler too: its 400 changes nothing, so a 403 asking for the
    factor would only spend a code to learn the same answer.
    """
    service = await _service(engine)
    if enrolled:
        setup = await service._complete_ad_login(_principal("aduser9"), None, mfa_verified=False)
        assert setup.identity is not None and setup.token is not None
        enrollment = await service.begin_mfa_enrollment(setup.identity)
        code = fresh_totp(enrollment.secret)
        assert (await service.confirm_mfa_enrollment(setup.identity, code, token=setup.token)).ok
    out = await service._complete_ad_login(_principal("aduser9"), None, mfa_verified=mfa_verified)
    assert out.ok and out.token is not None
    assert await service.mfa_satisfied(out.token) is mfa_verified
    async with _client(engine, service) as c:
        r = await _change_password(c, out.token)
        assert r.status_code == 400
        assert "Active Directory" in r.json()["detail"]


# --- 6.3.4: per-mechanism directory strength --------------------------------


async def test_a_federated_session_minted_unverified_is_not_mfa_satisfied(
    engine: Engine,
) -> None:
    """RED when: the AD branch in ``mfa_satisfied`` is removed (the pre-6.3.4 behaviour).

    THIS is the cell. Before the fix, ``_mfa_required_for`` short-circuited on every non-LOCAL
    provider, so ``mfa_satisfied`` returned True for a directory session no matter what
    ``mfa_verified`` was at issuance — making the conditional OIDC mint a timestamp with no
    consequence. Asserting on the sessions column alone would pass either way, so this asserts on
    ``mfa_satisfied``, which is what the gates actually call.
    """
    service = await _service(engine)
    out = await service._complete_ad_login(_principal(), None, mfa_verified=False)
    assert out.ok and out.token is not None
    assert await service.mfa_satisfied(out.token) is False


async def test_a_directory_session_minted_verified_is_satisfied(engine: Engine) -> None:
    """RED when: the directory floor starts refusing unconditionally.

    A verified mint has to keep working: it is what the federated leg produces once the claim gate has
    checked the token's ``amr``/``acr``, and refusing it would strand every directory operator whose
    IdP did assert a factor. This is the guard against over-correcting into a mass lockout.
    """
    service = await _service(engine)
    out = await service._complete_ad_login(_principal("aduser2"), None, mfa_verified=True)
    assert out.ok and out.token is not None
    assert await service.mfa_satisfied(out.token) is True


async def test_require_mfa_off_is_still_a_global_escape_for_the_directory_leg(
    engine: Engine,
) -> None:
    """RED when: the directory floor stops honouring require_mfa.

    An operator who deliberately turned the claim gate off must not be left without an off-switch.
    With the knob off and no factor enrolled, the floor falls through to the shared per-user rule,
    which also says not required — so an un-enrolled directory session is satisfied.
    """
    service = await _service(
        engine, AuthSettings(login_rate_limit_enabled=False, require_mfa=False)
    )
    out = await service._complete_ad_login(_principal("aduser3"), None, mfa_verified=False)
    assert out.ok and out.token is not None
    assert await service.mfa_satisfied(out.token) is True


def test_the_per_user_rule_reads_no_provider_at_all(engine: Engine) -> None:
    """RED when: ``_mfa_required_for`` re-adds ANY provider branch, allow-list or deny-list.

    Two failures the shape guards against at once. A ``!= LOCAL`` denylist would exempt an
    unrecognized provider, which ``_identity_for_user`` maps back to LOCAL when it builds the
    Identity — so such a row would present as local everywhere else while silently skipping the second
    factor here. An ``== AD`` allow-list was the shipped code until BACKLOG #1144 and exempted every
    directory account on a delegation the directory never asserted. Reading no provider closes both.
    """
    from types import SimpleNamespace

    service = AuthService.__new__(AuthService)
    service._settings = AuthSettings()  # type: ignore[attr-defined]
    for provider in ("saml-from-the-future", "ad", "local"):
        rogue = SimpleNamespace(auth_provider=provider)
        assert (
            service._mfa_required_for(  # type: ignore[arg-type]
                rogue, frozenset({Role.VIEWER}), second_factor_enrolled=False
            )
            is True
        ), f"provider {provider!r} must not change the answer"


# --- 6.8.4: the directory legs assert nothing, so the engine assumes nothing --


def test_the_kerberos_leg_mints_at_the_minimum() -> None:
    """RED when: ``_authenticate_kerberos`` goes back to passing ``mfa_verified=True``.

    A Kerberos service ticket carries no factor-strength assertion ``pyspnego`` surfaces, so the leg
    must grant nothing. The source read lives in ``tests/_mfa_grant.py``, shared with the doc-drift
    guard that pins ``docs/SECURITY.md``'s Kerberos rows against this same fact. The paired
    behavioural test is
    ``test_a_directory_session_minted_at_the_minimum_is_confined_until_it_enrolls``.
    """
    grants = mfa_grant_values(AuthService._authenticate_kerberos)
    assert grants, "the Kerberos leg passes no mfa_verified at all — the seam moved"
    assert all(isinstance(v, ast.Constant) and v.value is False for v in grants), (
        "the Kerberos leg mints MFA-satisfied again; docs/SECURITY.md's Kerberos rows say it does "
        "not, and every engine MFA gate would clear on evidence the engine never received."
    )


async def test_a_directory_session_minted_at_the_minimum_is_confined_until_it_enrolls(
    engine: Engine,
) -> None:
    """RED when: minting at the minimum ships WITHOUT directory-account factor enrollment.

    This is the co-landing invariant as one test. A minimum-minted directory session must be refused
    on an ordinary authorized route (otherwise the mint gates nothing) AND must be able to reach the
    enrollment ceremony and satisfy the gate (otherwise the mint is a lockout, not a control). Either
    half alone passes trivially; asserting both is what pins them together.
    """
    service = await _service(engine)
    out = await service._complete_ad_login(_principal("aduser4"), None, mfa_verified=False)
    assert out.ok and out.token is not None and out.identity is not None
    async with _client(engine, service) as c:
        headers = {"Authorization": f"Bearer {out.token}"}
        refused = await c.get("/connections", headers=headers)
        assert refused.status_code == 403
        assert refused.headers.get("X-MFA-Required") == "1"

    # The confinement is survivable: the ceremony accepts the directory account.
    enroll = await service.begin_mfa_enrollment(out.identity)
    confirmed = await service.confirm_mfa_enrollment(
        out.identity, totp.totp(enroll.secret), token=out.token
    )
    assert confirmed.recovery_codes
    # Confirming ROTATES the session (ASVS 7.2.4, BACKLOG #1146): the gate lifts on the NEW token,
    # and the one that walked into the ceremony has stopped authenticating by design.
    assert isinstance(confirmed.token, str)
    assert await service.mfa_satisfied(confirmed.token) is True


async def test_the_directory_login_outcome_reports_the_debt_it_created(engine: Engine) -> None:
    """RED when: the directory tail returns ``mfa_required=False`` for a session the gate will refuse.

    A JSON client (``POST /auth/negotiate``) is told whether it still owes a factor. Before BACKLOG
    #1144 a directory session was minted satisfied and the answer was always False, so the tail
    hardcoded it. Minting at the minimum without moving this would tell a client no factor is needed
    and then refuse its very next call with ``X-MFA-Required: 1`` and no earlier signal.

    The second half pins the flag to the GATE rather than to the grant: with ``require_mfa`` off, an
    un-enrolled directory session grants nothing yet owes nothing, and reporting True there would
    prompt for a factor the caller does not need.
    """
    service = await _service(engine)
    owes = await service._complete_ad_login(_principal("aduser5"), None, mfa_verified=False)
    assert owes.ok and owes.mfa_required is True

    granted = await service._complete_ad_login(_principal("aduser6"), None, mfa_verified=True)
    assert granted.ok and granted.mfa_required is False

    lax = await _service(engine, AuthSettings(login_rate_limit_enabled=False, require_mfa=False))
    off = await lax._complete_ad_login(_principal("aduser7"), None, mfa_verified=False)
    assert off.ok and off.mfa_required is False
