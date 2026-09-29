# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``verify_mfa`` asks the directory before it renews a directory account's step-up window.

BACKLOG #2023. A good second factor renews the step-up window. ``verify_mfa`` used to refuse only
when the ENGINE row was disabled, and the reconciliation pass is what updates that row. So an account
disabled in the directory could keep renewing its window until the next pass revoked it.

The refusals are the subject here, and each one asserts three things: nothing was renewed, the code
was never checked (the same code verifies once the directory answers), and nothing was charged to the
lockout. A local account is the control that must never reach the directory. All directory data here
is synthetic.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.api import create_app
from messagefoundry.auth import reconcile, totp
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe, LdapError
from messagefoundry.auth.service import DIRECTORY_UNCONFIRMED, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.store import MessageStore
from tests._admin_account import login_admin

_T0 = 1_700_000_000.0
_T1 = _T0 + totp.DEFAULT_PERIOD

_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="jdoe@test.invalid",
    dn="CN=jdoe,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="6f1d3c52-0e0b-4a57-9d52-1c2a3b4c5d6e",
)


class _Directory:
    """A directory whose answer the test sets. ``unreachable`` raises the connectivity signal."""

    def __init__(self, principal: AdPrincipal) -> None:
        self.principal = principal
        self.answer = DirectoryAnswer.FOUND
        self.unreachable = False
        self.probes: list[tuple[str, str | None]] = []

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        self.probes.append((username, object_id))
        if self.unreachable:
            raise LdapError("synthetic: LDAP socket closed")
        if self.answer is DirectoryAnswer.FOUND:
            return DirectoryProbe(DirectoryAnswer.FOUND, self.principal)
        return DirectoryProbe(self.answer)


@dataclass
class _Enrolled:
    service: AuthService
    store: Store
    directory: _Directory
    secret: str
    token: str  # a fresh directory session that still owes its second factor
    user_id: str


def _settings(**overrides: object) -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
        **overrides,  # type: ignore[arg-type]
    )


async def _enrolled_directory_session(
    store: Store,
    monkeypatch: pytest.MonkeyPatch,
    principal: AdPrincipal = _PRINCIPAL,
    settings: AuthSettings | None = None,
) -> _Enrolled:
    """A directory account with an enrolled TOTP factor, and a new session owing that factor.

    Mints through ``_complete_ad_login``, the shared tail Kerberos and OIDC both reach, because the
    subject is the second-factor leg and not the login mechanism.
    """
    directory = _Directory(principal)
    service = AuthService(store, settings or _settings(), ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    first = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert first.token is not None and first.identity is not None
    pin_totp_clock(monkeypatch, _T0)
    enroll = await service.begin_mfa_enrollment(first.identity)
    confirmed = await service.confirm_mfa_enrollment(
        first.identity, totp.totp(enroll.secret, now=_T0), token=first.token
    )
    assert confirmed.ok
    second = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert second.token is not None and second.identity is not None
    pin_totp_clock(monkeypatch, _T1)  # enrollment consumed _T0's step (BACKLOG #1021)
    directory.probes.clear()
    return _Enrolled(
        service, store, directory, enroll.secret, second.token, second.identity.user_id
    )


async def _audited_mfa_failures(store: Store) -> list[dict[str, object]]:
    rows = await store.list_audit(action="auth.mfa_failed")
    return [json.loads(r["detail"]) for r in rows if r["detail"]]


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


@pytest.mark.parametrize(
    ("answer", "unreachable", "outcome"),
    [
        (DirectoryAnswer.DISABLED, False, "disabled"),
        (DirectoryAnswer.NOT_FOUND, False, "absent"),
        (DirectoryAnswer.UNDETERMINED, False, "undetermined"),
        (DirectoryAnswer.FOUND, True, "unavailable"),
    ],
    ids=["disabled", "absent", "undetermined", "unavailable"],
)
async def test_a_directory_the_account_is_not_confirmed_in_refuses_the_renewal(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    answer: DirectoryAnswer,
    unreachable: bool,
    outcome: str,
) -> None:
    """RED when: ``verify_mfa`` renews a directory account's window without asking the directory,
    or asks only after the code is checked (which would spend it), or fails open on an outage."""
    e = await _enrolled_directory_session(store, monkeypatch)
    e.directory.answer = answer
    e.directory.unreachable = unreachable
    code = totp.totp(e.secret, now=_T1)

    refused = await e.service.verify_mfa(e.token, code)

    assert refused.ok is False
    assert refused.directory_unconfirmed is True
    assert refused.session_lost is False
    assert e.directory.probes == [("jdoe", _PRINCIPAL.directory_object_id)]  # by the immutable id
    session = await store.get_session(hash_token(e.token))
    assert session is not None and session.revoked_at is None  # the token still authenticates
    assert session.reauth_at is None  # no window was opened or renewed
    assert session.mfa_verified_at is None
    user = await store.get_user(e.user_id)
    # Nothing charged to either lockout counter (ADR 0197 splits them).
    assert user is not None and user.failed_attempts == 0
    assert user.second_step_failed_attempts == 0
    assert {"reason": DIRECTORY_UNCONFIRMED, "outcome": outcome} in await _audited_mfa_failures(
        store
    )

    # The code was never checked, so its step was not spent: the same code verifies once the
    # directory confirms the account.
    e.directory.answer = DirectoryAnswer.FOUND
    e.directory.unreachable = False
    assert (await e.service.verify_mfa(e.token, code)).ok is True


async def test_a_present_enabled_directory_account_still_renews(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the re-check must not refuse the account it exists to let through."""
    e = await _enrolled_directory_session(store, monkeypatch)

    verified = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert verified.ok is True and verified.token is not None
    assert e.directory.probes == [("jdoe", _PRINCIPAL.directory_object_id)]
    assert await e.service.has_recent_step_up(verified.token) is True


async def test_a_bound_row_with_no_directory_id_is_refused_unasked(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0184 AC-5: a row carrying a federated binding and no ``directory_object_id`` may not be
    asked about by its name, and it has no other key. So the directory cannot confirm it."""
    e = await _enrolled_directory_session(store, monkeypatch)
    # No sign-in mints an id-less row since BACKLOG #2027, which refuses a principal with no id. So
    # the legacy row is planted: the keyed row's column is cleared under its live session.
    await store._db.execute(
        "UPDATE users SET directory_object_id = NULL WHERE id = ?", (e.user_id,)
    )
    await store._db.commit()
    await store.set_user_federated_subject(e.user_id, "https://idp.test.invalid", "synthetic-sub")

    refused = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.ok is False and refused.directory_unconfirmed is True
    assert e.directory.probes == []  # never a name-only probe of a bound row
    assert {
        "reason": DIRECTORY_UNCONFIRMED,
        "outcome": "directory_object_id_missing",
    } in await _audited_mfa_failures(store)


async def test_a_confirmed_directory_accounts_wrong_code_still_feeds_the_lockout(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pathway rows say a directory account's TOTP leg feeds the lockout. The directory check
    must add a refusal and exempt nothing, so a confirmed account's wrong code still counts. ADR
    0197: it counts on the SECOND-STEP counter, because the caller holds a session."""
    e = await _enrolled_directory_session(store, monkeypatch)

    wrong = await e.service.verify_mfa(e.token, "000000")

    assert wrong.ok is False and wrong.directory_unconfirmed is False
    user = await store.get_user(e.user_id)
    assert user is not None and user.second_step_failed_attempts == 1
    assert user.failed_attempts == 0


async def _lock_second_step(store: MessageStore, user_id: str) -> None:
    """A live SECOND-STEP lock, the one ``verify_mfa`` is refused by (ADR 0197)."""
    await store.increment_login_failure(
        user_id,
        counter="second_step",
        threshold=1,
        lockout_seconds=900.0,
        max_lockout_seconds=86_400.0,
    )


async def test_a_locked_directory_account_is_refused_as_locked_before_any_lookup(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock is the cheap local check, so it runs first and costs no directory round trip. It
    also keeps its own answer, even when the directory would have refused the account too."""
    e = await _enrolled_directory_session(store, monkeypatch)
    await _lock_second_step(store, e.user_id)
    e.directory.answer = DirectoryAnswer.DISABLED

    refused = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.locked is True and refused.directory_unconfirmed is False
    assert e.directory.probes == []


async def test_a_directory_accounts_sign_in_lock_alone_does_not_refuse_the_second_step(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0197: ``verify_mfa`` is refused by the SECOND-STEP lock only, on the directory branch too.
    A sign-in lock is the one a caller who knows only the username can set, and this session has
    already passed the step it guards. Covers both lock checks, before and after the lookup."""
    e = await _enrolled_directory_session(store, monkeypatch)
    # Wall clock, not the pinned TOTP clock: the service reads the lock against time.time().
    await store.record_login_failure(e.user_id, failed_attempts=5, locked_until=time.time() + 900.0)
    user = await store.get_user(e.user_id)
    assert user is not None and user.sign_in_locked(time.time())  # the sign-in lock is live

    verified = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert verified.ok is True and verified.locked is False
    assert e.directory.probes == [("jdoe", _PRINCIPAL.directory_object_id)]


async def test_a_lock_set_during_the_lookup_is_honoured(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lookup is a network round trip, so the row is read again after it. Without the re-read, a
    lock set meanwhile by a concurrent guess would not stop this attempt."""
    e = await _enrolled_directory_session(store, monkeypatch)

    async def _probe_while_a_guess_locks(user: object) -> reconcile.Probe:
        await _lock_second_step(store, e.user_id)
        return reconcile.Probe(e.user_id, "jdoe", reconcile.ProbeOutcome.PRESENT)

    monkeypatch.setattr(e.service, "_probe_principal", _probe_while_a_guess_locks)

    refused = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.locked is True and refused.ok is False
    session = await store.get_session(hash_token(e.token))
    assert session is not None and session.reauth_at is None


async def _more_sessions(e: _Enrolled, count: int) -> list[str]:
    """``count`` further sessions on the enrolled directory account, each still owing its factor."""
    tokens = []
    for _ in range(count):
        minted = await e.service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
        assert minted.token is not None
        tokens.append(minted.token)
    return tokens


def _wrong_code(e: _Enrolled) -> str:
    live = totp.totp(e.secret, now=_T1)
    return f"{(int(live[0]) + 1) % 10}{live[1:]}"


async def test_a_slow_lookup_does_not_hold_the_accounts_credential_queue(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``verify_mfa`` takes the per-account queue (BACKLOG #1943) before the directory
    lookup, so one slow lookup stalls every other attempt on that account.

    The first attempt's lookup blocks until the test releases it. While it is blocked the queue
    must be empty, and a second attempt on the same account must get through its own lookup, its
    code check and its failure count. Only then is the first lookup released."""
    e = await _enrolled_directory_session(
        store, monkeypatch, settings=_settings(max_sessions_per_user=0)
    )
    (second,) = await _more_sessions(e, 1)
    first_in_lookup = asyncio.Event()
    release_first = asyncio.Event()
    lookups = 0

    async def _probe(user: object) -> reconcile.Probe:
        nonlocal lookups
        lookups += 1
        if lookups == 1:
            first_in_lookup.set()
            await release_first.wait()
        return reconcile.Probe(e.user_id, "jdoe", reconcile.ProbeOutcome.PRESENT)

    monkeypatch.setattr(e.service, "_probe_principal", _probe)
    wrong = _wrong_code(e)
    first = asyncio.ensure_future(e.service.verify_mfa(e.token, wrong))
    try:
        await asyncio.wait_for(first_in_lookup.wait(), timeout=5)
        assert e.service._credential_locks == {}, "the queue is held across the directory lookup"

        # The queue is free, so the second attempt runs to the end while the first is still asking.
        other = await asyncio.wait_for(e.service.verify_mfa(second, wrong), timeout=5)

        assert not first.done()
        assert other.ok is False and other.locked is False
        user = await store.get_user(e.user_id)
        assert user is not None and user.second_step_failed_attempts == 1
    finally:
        release_first.set()
        result = await asyncio.wait_for(first, timeout=5)
    assert result.ok is False
    user = await store.get_user(e.user_id)
    assert user is not None and user.second_step_failed_attempts == 2
    assert e.service._credential_locks == {}


async def test_a_burst_on_a_directory_account_gets_exactly_threshold_code_checks(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the lock check after the lookup and the count after the code check are not one
    step per account (BACKLOG #1943), so a burst gets one code check per attempt.

    Every attempt passes the first lock check and then waits in its lookup until all of them are
    there, so all of them read the account unlocked before any code is checked. Only the check
    inside the per-account queue can then stop the attempts after the locking one. The same
    barrier proves the lookups run side by side: held inside the queue, they could not all meet."""
    threshold, burst = 3, 5
    settings = _settings(lockout_threshold=threshold, lockout_minutes=15, max_sessions_per_user=0)
    e = await _enrolled_directory_session(store, monkeypatch, settings=settings)
    tokens = [e.token, *await _more_sessions(e, burst - 1)]
    in_lookup = 0
    all_in_lookup = asyncio.Event()

    async def _probe(user: object) -> reconcile.Probe:
        nonlocal in_lookup
        in_lookup += 1
        if in_lookup == burst:
            all_in_lookup.set()
        await all_in_lookup.wait()
        return reconcile.Probe(e.user_id, "jdoe", reconcile.ProbeOutcome.PRESENT)

    checks = 0
    real_check = e.service._verify_second_factor

    async def _counted(user: object, code: str, **kwargs: Any) -> bool:
        nonlocal checks
        checks += 1
        return await real_check(user, code, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(e.service, "_probe_principal", _probe)
    monkeypatch.setattr(e.service, "_verify_second_factor", _counted)
    wrong = _wrong_code(e)

    results = await asyncio.wait_for(
        asyncio.gather(*(e.service.verify_mfa(t, wrong) for t in tokens)), timeout=10
    )

    assert in_lookup == burst
    assert not any(r.ok for r in results)
    assert checks == threshold, "codes past the lock check were still checked"
    assert sum(1 for r in results if r.locked) == burst - threshold
    user = await store.get_user(e.user_id)
    assert user is not None and user.second_step_failed_attempts == threshold
    assert user.second_step_locked_until is not None
    assert user.failed_attempts == 0
    assert e.service._credential_locks == {}


async def test_a_directory_account_with_no_directory_configured_is_refused(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An AD row left behind after the directory is unwired has nothing to confirm it, so it fails
    closed rather than renewing on the engine row alone."""
    e = await _enrolled_directory_session(store, monkeypatch)
    unwired = AuthService(store, AuthSettings())

    refused = await unwired.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.ok is False and refused.directory_unconfirmed is True
    assert {"reason": DIRECTORY_UNCONFIRMED, "outcome": "not_configured"} in (
        await _audited_mfa_failures(store)
    )


async def test_a_local_account_is_never_probed(store: MessageStore) -> None:
    """A local account's second factor is unchanged, and it costs no directory round trip."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    identity, token, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    confirmed = await service.confirm_mfa_enrollment(
        identity, fresh_totp(enroll.secret), token=token
    )
    assert confirmed.ok and confirmed.recovery_codes

    verified = await service.verify_mfa(confirmed.token, confirmed.recovery_codes[0])

    assert verified.ok is True
    assert directory.probes == []


async def test_the_route_says_the_directory_could_not_confirm_the_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The API answers 403, not the wrong-code 401, and names the directory as the reason."""
    engine = await Engine.create(tmp_path / "mfa_directory.db", poll_interval=0.02)
    try:
        e = await _enrolled_directory_session(engine.store, monkeypatch)
        e.directory.answer = DirectoryAnswer.DISABLED
        transport = httpx.ASGITransport(
            app=create_app(engine, auth=e.service), client=("127.0.0.1", 123)
        )
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                "/auth/mfa-verify",
                json={"code": totp.totp(e.secret, now=_T1)},
                headers={"Authorization": f"Bearer {e.token}"},
            )
        assert r.status_code == 403
        assert "directory could not confirm this account" in r.json()["detail"]
    finally:
        await engine.stop()
