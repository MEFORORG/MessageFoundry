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
import json
import logging
import string
import threading
import time
from collections.abc import AsyncIterator, Callable, Coroutine
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import (
    CREDENTIAL_ISSUE_REFUSED_ACTION,
    AuthService,
    TemporaryPasswordUnavailable,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings
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
        assert await store.enable_totp(target, recovery_code_hashes=["h"])
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
        issue_rows_before = [
            r["action"]
            for r in await store.list_audit(limit=200)
            if r["action"] in ("user.created", "auth.password_reset")
        ]

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
        rows = await store.list_audit(limit=200)
        audit = [r["action"] for r in rows]
        assert "auth.password_reset" not in audit and "auth.mfa_reset" not in audit
        # BACKLOG #2359: each refusal leaves ONE row of its own, naming the operation and the actor,
        # and no row the credential-issuer lookup would read as an issue (`_ISSUE_ROW_KEYS`).
        refused = [
            (r["actor"], json.loads(r["detail"]))
            for r in rows
            if r["action"] == CREDENTIAL_ISSUE_REFUSED_ACTION
        ]
        assert sorted(refused, key=lambda row: row[1]["op"]) == [
            (ADMIN_USERNAME, {"op": "create", "username": "newbie", "roles": ["viewer"]}),
            (ADMIN_USERNAME, {"op": "mfa_reset", "username": "holder", "user_id": target}),
            (ADMIN_USERNAME, {"op": "password_reset", "username": "holder", "user_id": target}),
        ]
        issue_rows_after = [
            r["action"] for r in rows if r["action"] in ("user.created", "auth.password_reset")
        ]
        assert issue_rows_after == issue_rows_before
    finally:
        await store.close()


async def test_the_generator_runs_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #2359, finding 4. A refusing site list costs up to 128 policy screens, so all three
    issuing paths run the generator in a worker thread. RED when any caller calls it inline."""
    loop_thread = threading.get_ident()
    seen: list[int] = []
    real = service_module.generate_policy_password

    def recording(*args: Any, **kwargs: Any) -> str:
        seen.append(threading.get_ident())
        return real(*args, **kwargs)

    monkeypatch.setattr(service_module, "generate_policy_password", recording)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(require_mfa=False))
        await service.initialize()
        created = await service.create_local_user(
            username="threaded",
            display_name=None,
            email="threaded@example.org",
            roles=["viewer"],
            actor="test",
        )
        await service.admin_reset_password(created.user_id, actor="test")
        await service.admin_reset_mfa(created.user_id, actor="test")
        assert len(seen) == 3, "each issuing path generates exactly one credential"
        assert loop_thread not in seen, "the generator ran on the event loop's thread"
    finally:
        await store.close()


# --- the restart advice (BACKLOG #2359, finding 9) -------------------------------------------------

#: What the advice must name. The environment variable overrides the TOML key, and every engine
#: process builds its policy once at start, so a fix needs a restart of each one.
_ADVICE_TERMS = (
    "password_extra_context_words",
    "MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS",
    "restart every engine process",
    "engine shard",
    "cluster node",
    "/config/reload",
)


def test_the_error_log_and_the_refusal_carry_the_same_restart_advice(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from messagefoundry.auth.policy import PasswordPolicy

    policy = PasswordPolicy.from_settings(_unissuable())
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"),
        pytest.raises(TemporaryPasswordUnavailable) as raised,
    ):
        service_module.generate_policy_password(policy, username="someone")
    logged = " ".join(r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)
    for text in (logged, str(raised.value)):
        assert service_module.SITE_TERMS_FIX_ADVICE in text
    for term in _ADVICE_TERMS:
        assert term in service_module.SITE_TERMS_FIX_ADVICE, term


def test_the_docs_carry_the_restart_advice() -> None:
    """The operator reads the advice in SECURITY.md's reset section and the CONFIGURATION.md row too.
    Each must name the environment variable, every engine shard and every cluster node."""
    root = Path(__file__).resolve().parents[1]
    security = (root / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    start = security.index("### Admin password reset")
    section = security[start : security.index("\n### ", start + 1)]
    config = (root / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    row = next(
        line for line in config.splitlines() if line.startswith("| `password_extra_context_words`")
    )
    for text in (section, row):
        for term in (
            "MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS",
            "engine shard",
            "cluster node",
            "/config/reload",
        ):
            assert term in text, term
    assert "auth.credential_issue_refused" in section


async def test_a_failed_refusal_audit_still_answers_with_the_refusal(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The refusal row is a record, not the answer. A store that cannot write it must not turn the
    refusal into a different exception, or the route answers 500 and keeps the spent grant."""
    import sqlite3

    store = await MessageStore.open(":memory:")
    try:
        seeding = AuthService(store, AuthSettings(require_mfa=False))
        await seeding.initialize()
        target = await create_local_user_chosen(
            seeding,
            username="holder",
            password=PW,
            display_name=None,
            email="holder@example.org",
            roles=["viewer"],
            actor="test",
        )

        service = AuthService(store, _unissuable())

        async def failing_audit(*_a: object, **_k: object) -> None:
            raise sqlite3.OperationalError("synthetic store fault")

        monkeypatch.setattr(service, "_audit", failing_audit)
        with (
            caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"),
            pytest.raises(TemporaryPasswordUnavailable),
        ):
            await service.admin_reset_password(target, actor=ADMIN_USERNAME)
        logged = [
            r
            for r in caplog.records
            if r.levelno >= logging.ERROR and CREDENTIAL_ISSUE_REFUSED_ACTION in r.getMessage()
        ]
        assert len(logged) == 1
        assert logged[0].exc_info is not None and logged[0].exc_info[0] is sqlite3.OperationalError
    finally:
        await store.close()


# --- the routes: the refusal is a 503 and the grant survives -------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "unissuable.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
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


async def _refusal_ops(service: AuthService) -> list[str]:
    """The ``op`` of every refused-issue audit row, oldest first."""
    rows = await service.store.list_audit(action=CREDENTIAL_ISSUE_REFUSED_ACTION, limit=50)
    return [json.loads(r["detail"])["op"] for r in reversed(rows)]


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
    ("path", "purpose", "op"),
    [
        pytest.param(
            "reset-password", "admin_reset_password", "password_reset", id="password-reset"
        ),
        pytest.param("reset-mfa", "admin_reset_mfa", "mfa_reset", id="factor-reset"),
    ],
)
async def test_a_refused_reset_keeps_the_account_and_the_grant(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, path: str, purpose: str, op: str
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
        # One refusal row, written by the service, not a second one by the route (BACKLOG #2359).
        assert await _refusal_ops(service) == [op]
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
        assert await _refusal_ops(service) == ["create"]
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
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(errors) == 1, "one failure, one ERROR record"
        text = " ".join(r.getMessage() for r in errors)
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


def test_a_probe_reports_any_generator_failure_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A generator that raises something other than TemporaryPasswordUnavailable (a later policy
    clause, a data file) is reported by the shared probe, so neither `serve` nor `verify` dies."""
    from messagefoundry.auth.policy import PasswordPolicy
    from messagefoundry.verify import checks
    from messagefoundry.verify.model import Status

    def broken(*_a: object, **_k: object) -> str:
        raise RuntimeError("synthetic generator fault")

    monkeypatch.setattr(service_module, "generate_policy_password", broken)
    problem = service_module.credential_generation_problem(
        PasswordPolicy.from_settings(AuthSettings())
    )
    assert problem is not None and "RuntimeError" in problem
    assert "synthetic generator fault" not in problem  # the type only, never the message
    assert checks.check_credential_generation(AuthSettings()).status is Status.FAIL


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

        async def request(body: Callable[[], Coroutine[Any, Any, None]]) -> None:
            await asyncio.create_task(body(), context=contextvars.copy_context())

        async def never_granted() -> None:
            assert service.refund_action_step_up(mfa) is False  # nothing spent: cannot mint

        async def spend_then_refund_another_action() -> None:
            service._grant_action_step_up(key, mfa)
            assert await service.has_action_step_up(token, mfa) is True
            assert service.refund_action_step_up(fed) is False  # another action: nothing...
            assert service.refund_action_step_up(mfa) is True  # ...and the right one still stands
            assert await service.has_action_step_up(token, mfa) is True  # restored, spent again
            assert await service.has_action_step_up(token, mfa) is False  # single-use

        async def another_instance_cannot_take_it() -> None:
            other = AuthService(store, AuthSettings())
            service._grant_action_step_up(key, mfa)
            assert await service.has_action_step_up(token, mfa) is True
            assert other.refund_action_step_up(mfa) is False  # not the instance that spent it
            assert (key, mfa) not in other._action_step_up_grants

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
        await request(another_instance_cannot_take_it)
        await request(spend_then_refund)
        await request(the_restored_grant_opens_once)
        await request(not_refundable)
        # A different request cannot refund what another one spent.
        await request(spend_only)
        await request(refund_without_spending)
        await request(a_fresher_grant_is_kept)
    finally:
        await store.close()
