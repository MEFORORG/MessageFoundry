# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _mfa_grant import mfa_grant_values

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

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


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
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
    async with _client(engine, service) as c:
        tok = await _login(c, "vw")
        assert (await c.get("/messages", headers=_auth(tok))).status_code == 403
    denied = [a for a in await engine.store.list_audit() if a["action"] == "auth.mfa_denied"]
    assert denied, "an MFA refusal must leave an audit row; otherwise probing is invisible"
    assert denied[-1]["actor"] == "vw"
    assert "/messages" in (denied[-1]["detail"] or "")
    # The row must never carry the bearer token or a code — only the path.
    assert "Bearer" not in (denied[-1]["detail"] or "")


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
    assert await service.confirm_mfa_enrollment(
        identity, totp.totp(enrollment.secret), token=setup.token
    )

    async with _client(engine, service) as c:
        # The attacker knows the password and nothing else.
        tok = await _login(c, "vic")
        h = _auth(tok)
        assert (await c.get("/messages", headers=h)).status_code == 403  # gate holds, for now

        # Step 1 of the chain: password-only re-auth naming a factor-binding purpose. It still
        # succeeds as a re-auth (the session window legitimately refreshes)...
        r = await c.post("/me/reauth", json={"password": PW, "purpose": "mfa_enroll"}, headers=h)
        assert r.status_code == 200

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
        assert (
            await c.post("/me/reauth", json={"password": PW, "purpose": "mfa_enroll"}, headers=h)
        ).status_code == 200
        assert (await c.post("/me/mfa/enroll", headers=h)).status_code == 200


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
    """RED when: ``authenticate_kerberos`` goes back to passing ``mfa_verified=True``.

    A Kerberos service ticket carries no factor-strength assertion ``pyspnego`` surfaces, so the leg
    must grant nothing. The source read lives in ``tests/_mfa_grant.py``, shared with the doc-drift
    guard that pins ``docs/SECURITY.md``'s Kerberos rows against this same fact. The paired
    behavioural test is
    ``test_a_directory_session_minted_at_the_minimum_is_confined_until_it_enrolls``.
    """
    grants = mfa_grant_values(AuthService.authenticate_kerberos)
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
    codes = await service.confirm_mfa_enrollment(
        out.identity, totp.totp(enroll.secret), token=out.token
    )
    assert codes is not None
    assert await service.mfa_satisfied(out.token) is True


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
