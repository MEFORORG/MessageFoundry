# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A generator that cannot issue a credential changes nothing (ADR 0197 Amendment A, Manager decision
2026-09-29, prompted by PR 1761 / BACKLOG #1132).

Since #1132 the temporary-password generator screens a site's own context words, and after
``_RESET_GENERATION_ATTEMPTS`` misses it raises :class:`TemporaryPasswordUnavailable`. Amendment A made
three paths issue a generated credential: account creation (AC-A2), the administrator's password reset,
and the factor reset (AC-A4). Each must fail HARMLESSLY: no row written, no factor cleared, no session
revoked, and the single-use step-up grant the administrator spent to reach the route still usable.

**The pathological list is CONSTRUCTED, not guessed.** The generator's candidates are cut from
``secrets.token_urlsafe``, whose alphabet is ``[A-Za-z0-9_-]``; the screen lower-cases, leaving 38
symbols. The site-term floor is 3 characters (``EXTRA_CONTEXT_WORD_MIN_LENGTH``), so the 1- and
2-character lists the brief suggested are refused at load. So the list is EVERY 3-character string over
those 38 symbols, 54,872 terms: every candidate of 32 or more characters contains one, so every
candidate fails, deterministically. It is applied with ``model_copy`` because the settings validator
takes about 11 s over it; ``PasswordPolicy.__post_init__`` re-checks every term, so nothing unchecked
reaches the screen.

The route arms use a narrower tool, a faked token source, because they must also show the SAME grant
succeeds once the generator can issue again, which a permanent failure cannot.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import string
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import AuthService, TemporaryPasswordUnavailable
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore, WebAuthnCredential
from tests._admin_account import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    create_admin,
    create_local_user_chosen,
)

PW = "a-strong-test-passphrase"

#: Every 3-character string over the lower-cased ``token_urlsafe`` alphabet: see the module docstring.
_EVERY_TRIGRAM = [
    "".join(t) for t in itertools.product(string.ascii_lowercase + string.digits + "-_", repeat=3)
]


def _unissuable() -> AuthSettings:
    """Settings under which no generated candidate can clear the policy."""
    base = AuthSettings(password_check_breached=False, require_mfa=False)
    return base.model_copy(update={"password_extra_context_words": _EVERY_TRIGRAM})


def test_the_constructed_list_defeats_every_candidate() -> None:
    """The premise, measured rather than assumed: the generator itself refuses under the list."""
    from messagefoundry.auth.policy import PasswordPolicy

    policy = PasswordPolicy.from_settings(_unissuable())
    with pytest.raises(TemporaryPasswordUnavailable):
        service_module.generate_policy_password(policy, username="someone")


# --- the service: nothing is written ------------------------------------------------------------


async def _state(store: Any, user_id: str) -> tuple[object, ...]:
    user = await store.get_user(user_id)
    assert user is not None
    return (
        user.password_hash,
        user.password_generated,
        user.must_change_password,
        user.totp_enabled,
        await store.get_totp_secret(user_id),
        tuple(c.credential_id_hash for c in await store.list_webauthn_credentials(user_id)),
    )


async def test_create_reset_and_factor_reset_write_nothing_when_no_credential_can_be_issued() -> (
    None
):
    store = await MessageStore.open(":memory:")
    try:
        # Seeded under ordinary settings, then run under the unissuable list.
        seeding = AuthService(store, AuthSettings(require_mfa=False))
        await create_admin(seeding)
        target = await create_local_user_chosen(
            seeding,
            username="holder",
            password=PW,
            display_name=None,
            email="holder@example.org",
            roles=["viewer"],
            actor="test",
        )
        await store.set_totp_secret(target, secret="JBSWY3DPEHPK3PXP")
        await store.enable_totp(target, recovery_code_hashes=["h"])
        await store.add_webauthn_credential(
            WebAuthnCredential(
                credential_id_hash="kept-hash",
                credential_id="kept-id",
                user_id=target,
                rp_id="t",
                public_key="cose-public-key-b64url",
                sign_count=0,
                transports=None,
                device_type="multi_device",
                backed_up=True,
                label="kept",
                aaguid=None,
                created_at=1.0,
            )
        )
        session = await seeding.login("holder", PW)
        assert session.ok and session.token is not None
        before = await _state(store, target)
        users_before = await store.count_users()

        service = AuthService(store, _unissuable())
        with pytest.raises(TemporaryPasswordUnavailable):
            await service.create_local_user(
                username="newbie",
                display_name=None,
                email="newbie@example.org",
                roles=["viewer"],
                actor=ADMIN_USERNAME,
            )
        assert await store.count_users() == users_before
        assert await store.get_user_by_username("newbie") is None
        with pytest.raises(TemporaryPasswordUnavailable):
            await service.admin_reset_password(target, actor=ADMIN_USERNAME)
        with pytest.raises(TemporaryPasswordUnavailable):
            await service.admin_reset_mfa(target, actor=ADMIN_USERNAME)
        assert await _state(store, target) == before, "a refused issue changed the account"
        assert await seeding.identity_for_token(session.token) is not None, "a session was revoked"
        audit = [r["action"] for r in await store.list_audit(limit=50)]
        assert "auth.password_reset" not in audit and "auth.mfa_reset" not in audit
    finally:
        await store.close()


# --- the routes: the refusal is a 503 and the grant survives -------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "unissuable.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _signed_in_admin(service: AuthService, c: httpx.AsyncClient) -> str:
    admin = await create_admin(service)
    row = await service.store.get_user(admin.user_id)
    assert row is not None and row.password_hash is not None
    await service.store.set_password(
        admin.user_id,
        password_hash=row.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    r = await c.post("/auth/login", json={"username": admin.username, "password": admin.password})
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _grant(c: httpx.AsyncClient, token: str, purpose: str) -> str:
    r = await c.post(
        "/me/reauth", json={"password": ADMIN_PASSWORD, "purpose": purpose}, headers=_auth(token)
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


#: A token source whose every token carries the one site term, so the generator cannot issue.
_NO_ISSUE = SimpleNamespace(token_urlsafe=lambda n=None: "zq-globex-" + "v" * 40)


def _one_term_settings() -> AuthSettings:
    return AuthSettings(
        require_mfa=False,
        login_rate_limit_enabled=False,
        # The refusal and the retry are one machine-speed pair; PR 1781's human-timing floor on
        # admin writes (BACKLOG #2301) would answer the retry 429.
        admin_write_min_interval_seconds=0,
        password_extra_context_words=["globex"],
    )


@pytest.mark.parametrize(
    ("path", "purpose"),
    [
        pytest.param("reset-password", "admin_reset_password", id="password-reset"),
        pytest.param("reset-mfa", "admin_reset_mfa", id="factor-reset"),
    ],
)
async def test_a_refused_reset_keeps_the_account_and_the_grant(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, path: str, purpose: str
) -> None:
    service = AuthService(engine.store, _one_term_settings())
    await service.initialize()
    target = await create_local_user_chosen(
        service,
        username="carol",
        password=PW,
        display_name=None,
        email="carol@example.org",
        roles=["viewer"],
        actor="test",
    )
    carol = await service.login("carol", PW)
    assert carol.ok and carol.token is not None
    async with _client(engine, service) as c:
        token = await _signed_in_admin(service, c)
        token = await _grant(c, token, purpose)
        before = await _state(engine.store, target)
        with monkeypatch.context() as m:
            m.setattr(service_module, "secrets", _NO_ISSUE)
            refused = await c.post(f"/users/{target}/{path}", headers=_auth(token))
        assert refused.status_code == 503, refused.text
        assert "password_extra_context_words" in refused.json()["detail"]
        assert await _state(engine.store, target) == before
        assert await service.identity_for_token(carol.token) is not None
        # The SAME grant still opens the route, with no second re-authentication.
        again = await c.post(f"/users/{target}/{path}", headers=_auth(token))
        assert again.status_code == 200, again.text
        assert again.json()["temp_password"]
        # ...and it was spent by that success, so single-use still holds.
        third = await c.post(f"/users/{target}/{path}", headers=_auth(token))
        assert third.status_code == 403 and third.headers.get("X-Step-Up-Action") == purpose


async def test_a_refused_create_writes_no_row(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = AuthService(engine.store, _one_term_settings())
    await service.initialize()
    async with _client(engine, service) as c:
        token = await _signed_in_admin(service, c)
        body = {"username": "newbie", "roles": ["viewer"], "email": "n@x.org"}
        with monkeypatch.context() as m:
            m.setattr(service_module, "secrets", _NO_ISSUE)
            refused = await c.post("/users", headers=_auth(token), json=body)
        assert refused.status_code == 503, refused.text
        assert await service.store.get_user_by_username("newbie") is None
        created = await c.post("/users", headers=_auth(token), json=body)
        assert created.status_code == 201, created.text


# --- the startup probe ---------------------------------------------------------------------------


async def test_the_startup_probe_logs_an_error_and_does_not_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        bad = AuthService(store, _unissuable())
        with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
            assert bad.probe_credential_generation() is False
        text = " ".join(r.getMessage() for r in caplog.records)
        assert "password_extra_context_words" in text and "startup" in text
        good = AuthService(store, AuthSettings())
        assert good.probe_credential_generation() is True
    finally:
        await store.close()


def test_the_verify_probe_fails_on_an_unissuable_policy_and_passes_otherwise() -> None:
    from messagefoundry.verify import checks
    from messagefoundry.verify.model import Status

    bad = checks.check_credential_generation(_unissuable())
    assert bad.status is Status.FAIL, bad.detail
    assert "password_extra_context_words" in bad.detail
    good = checks.check_credential_generation(AuthSettings())
    assert good.status is Status.PASS, good.detail


# --- the refund: only what this process spent, only for the two issuing routes -------------------


async def test_a_refund_restores_only_the_grant_this_request_spent() -> None:
    """RED when: a refund can mint, re-arm, extend, cross actions, or overwrite a fresher grant.

    Each block runs in its own ``contextvars`` context, as each request does: the gate's spend and
    the handler's refund share one, and nothing else does."""
    import contextvars

    from messagefoundry.auth.service import (
        STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY,
        STEP_UP_ACTION_ADMIN_RESET_MFA,
    )
    from messagefoundry.auth.tokens import hash_token

    mfa, fed = STEP_UP_ACTION_ADMIN_RESET_MFA, STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        token = "a-synthetic-session-token"
        key = hash_token(token)

        async def request(body: Callable[[], Awaitable[None]]) -> None:
            await asyncio.create_task(body(), context=contextvars.copy_context())

        async def never_granted() -> None:
            assert service.refund_action_step_up(mfa) is False  # nothing spent: cannot mint

        async def spend_then_refund_another_action() -> None:
            service._grant_action_step_up(key, mfa)
            assert await service.has_action_step_up(token, mfa) is True
            assert service.refund_action_step_up(fed) is False  # another action: nothing
            assert await service.has_action_step_up(token, mfa) is False  # spent, single-use

        async def spend_then_refund() -> None:
            service._grant_action_step_up(key, mfa)
            assert await service.has_action_step_up(token, mfa) is True
            assert service.refund_action_step_up(mfa) is True
            assert service.refund_action_step_up(mfa) is False  # a second refund finds nothing

        async def not_refundable() -> None:
            service._grant_action_step_up(key, fed)
            assert await service.has_action_step_up(token, fed) is True
            assert service.refund_action_step_up(fed) is False  # never recorded

        async def spend_only() -> None:
            service._grant_action_step_up(key, mfa)
            assert await service.has_action_step_up(token, mfa) is True

        async def a_fresher_grant_is_kept() -> None:
            service._grant_action_step_up(key, mfa)
            assert await service.has_action_step_up(token, mfa) is True
            # The session re-proved since: a grant with a later deadline is live again.
            service._action_step_up_grants[(key, mfa)] = time.monotonic() + 10_000
            assert service.refund_action_step_up(mfa) is False
            assert service._action_step_up_grants[(key, mfa)] > time.monotonic() + 9_000

        async def the_restored_grant_opens_once() -> None:
            assert await service.has_action_step_up(token, mfa) is True
            assert await service.has_action_step_up(token, mfa) is False

        async def refund_without_spending() -> None:
            assert service.refund_action_step_up(mfa) is False

        await request(never_granted)
        await request(spend_then_refund_another_action)
        await request(spend_then_refund)
        await request(the_restored_grant_opens_once)
        await request(not_refundable)
        # A different request cannot refund what another one spent.
        await request(spend_only)
        await request(refund_without_spending)
        await request(a_fresher_grant_is_kept)
    finally:
        await store.close()
