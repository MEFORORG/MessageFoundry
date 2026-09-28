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

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

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


def _settings() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
    )


async def _enrolled_directory_session(
    store: Store, monkeypatch: pytest.MonkeyPatch, principal: AdPrincipal = _PRINCIPAL
) -> _Enrolled:
    """A directory account with an enrolled TOTP factor, and a new session owing that factor.

    Mints through ``_complete_ad_login``, the shared tail Kerberos and OIDC both reach, because the
    subject is the second-factor leg and not the login mechanism.
    """
    directory = _Directory(principal)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
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
    assert user is not None and user.failed_attempts == 0  # nothing charged to the lockout
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
    unkeyed = AdPrincipal(
        username=_PRINCIPAL.username,
        display_name=_PRINCIPAL.display_name,
        email=_PRINCIPAL.email,
        dn=_PRINCIPAL.dn,
        groups=_PRINCIPAL.groups,
        directory_object_id=None,
    )
    e = await _enrolled_directory_session(store, monkeypatch, unkeyed)
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
    must add a refusal and exempt nothing, so a confirmed account's wrong code still counts."""
    e = await _enrolled_directory_session(store, monkeypatch)

    wrong = await e.service.verify_mfa(e.token, "000000")

    assert wrong.ok is False and wrong.directory_unconfirmed is False
    user = await store.get_user(e.user_id)
    assert user is not None and user.failed_attempts == 1


async def test_a_locked_directory_account_is_refused_as_locked_before_any_lookup(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock is the cheap local check, so it runs first and costs no directory round trip. It
    also keeps its own answer, even when the directory would have refused the account too."""
    e = await _enrolled_directory_session(store, monkeypatch)
    await store.increment_login_failure(e.user_id, threshold=1, lockout_seconds=900.0)
    e.directory.answer = DirectoryAnswer.DISABLED

    refused = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.locked is True and refused.directory_unconfirmed is False
    assert e.directory.probes == []


async def test_a_lock_set_during_the_lookup_is_honoured(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lookup is a network round trip, so the row is read again after it. Without the re-read, a
    lock set meanwhile by a concurrent guess would not stop this attempt."""
    e = await _enrolled_directory_session(store, monkeypatch)

    async def _probe_while_a_guess_locks(user: object) -> reconcile.Probe:
        await store.increment_login_failure(e.user_id, threshold=1, lockout_seconds=900.0)
        return reconcile.Probe(e.user_id, "jdoe", reconcile.ProbeOutcome.PRESENT)

    monkeypatch.setattr(e.service, "_probe_principal", _probe_while_a_guess_locks)

    refused = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.locked is True and refused.ok is False
    session = await store.get_session(hash_token(e.token))
    assert session is not None and session.reauth_at is None


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
