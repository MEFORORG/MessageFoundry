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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.api import create_app
from messagefoundry.auth import reconcile, totp
from messagefoundry.auth.identity import SessionMechanism
from messagefoundry.auth.ldap import (
    AdPrincipal,
    DirectoryAnswer,
    LdapReferralError,
    LdapUnansweredError,
)
from messagefoundry.auth.service import DIRECTORY_UNCONFIRMED, AuthService, DirectoryRefusal
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.base import Store
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.store import MessageStore
from tests._admin_account import login_admin
from tests._fake_directory import FakeDirectory as _Directory

_T0 = 1_700_000_000.0
_T1 = _T0 + totp.DEFAULT_PERIOD
# Synthetic base32, a second secret for a factor enrolled again during a code check.
_REPLACING_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="jdoe@test.invalid",
    dn="CN=jdoe,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="6f1d3c52-0e0b-4a57-9d52-1c2a3b4c5d6e",
)


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
        mfa_verify_min_elapsed_seconds=0,
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
    assert refused.directory_refusal is DirectoryRefusal.UNCONFIRMED
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


@pytest.mark.parametrize(
    ("raised", "outcome"),
    [
        (LdapReferralError("synthetic: AD answered the user search with a referral"), "referred"),
        # BACKLOG #3100: a fault, not an outage, so the audit row says which.
        (KeyError("userAccountControl"), "probe_fault"),
        (ValueError("synthetic: malformed objectGUID"), "probe_fault"),
        # A network-class error that escaped the directory layer is still unreachable.
        (TimeoutError("synthetic: read timed out"), "unavailable"),
        # BACKLOG #3010: a code that points at the configuration, and one that does not.
        (
            LdapUnansweredError("synthetic: noSuchObject", code=32, code_name="noSuchObject"),
            "misconfigured",
        ),
        (LdapUnansweredError("synthetic: busy", code=51, code_name="busy"), "unavailable"),
    ],
    ids=["referral", "key-error", "value-error", "timeout", "no-such-object", "busy"],
)
async def test_a_lookup_that_raises_refuses_the_renewal_rather_than_failing(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    raised: Exception,
    outcome: str,
) -> None:
    """BACKLOG #2241 and #2538. A referral, or a fault that is not an LdapError, still refuses as
    an audited directory_unconfirmed, spending no code and charging no lockout.

    RED when: the non-LdapError escapes verify_mfa (a 500 at the route), or the referral is read
    as anything that lets the renewal through."""
    e = await _enrolled_directory_session(store, monkeypatch)
    e.directory.raises = raised
    code = totp.totp(e.secret, now=_T1)

    refused = await e.service.verify_mfa(e.token, code)

    assert refused.ok is False and refused.directory_refusal is DirectoryRefusal.UNCONFIRMED
    session = await store.get_session(hash_token(e.token))
    assert session is not None and session.revoked_at is None and session.reauth_at is None
    user = await store.get_user(e.user_id)
    assert user is not None and user.failed_attempts == 0
    assert user.second_step_failed_attempts == 0
    assert {"reason": DIRECTORY_UNCONFIRMED, "outcome": outcome} in await _audited_mfa_failures(
        store
    )

    e.directory.raises = None
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


@pytest.mark.parametrize("bound", [True, False], ids=["bound", "unbound"])
async def test_a_row_with_no_directory_id_is_refused_unasked(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, bound: bool
) -> None:
    """ADR 0184 AC-5, BACKLOG #2027: a row with no ``directory_object_id`` has only its name to be
    asked by, and a directory may reissue a name. So it is refused without a lookup, bound or not.

    RED when: the unbound arm probes the directory by name, as this leg did before #2027's
    remainder, or a refusal spends the code or charges the lockout."""
    e = await _enrolled_directory_session(store, monkeypatch)
    # No sign-in mints an id-less row since BACKLOG #2027, which refuses a principal with no id. So
    # the legacy row is planted: the keyed row's column is cleared under its live session.
    await store._db.execute(
        "UPDATE users SET directory_object_id = NULL WHERE id = ?", (e.user_id,)
    )
    if bound:
        # Straight to the columns, like the id above. The store's bind ends the account's sessions
        # (vault BACKLOG #2609), and this leg needs the session that owes the factor.
        await store._db.execute(
            "UPDATE users SET oidc_issuer = ?, oidc_subject = ? WHERE id = ?",
            ("https://idp.test.invalid", "synthetic-sub", e.user_id),
        )
    await store._db.commit()
    code = totp.totp(e.secret, now=_T1)

    refused = await e.service.verify_mfa(e.token, code)

    assert refused.ok is False and refused.directory_refusal is DirectoryRefusal.UNCONFIRMED
    assert refused.session_lost is False
    assert e.directory.probes == []  # never a name-only probe
    assert {
        "reason": DIRECTORY_UNCONFIRMED,
        "outcome": "directory_object_id_missing",
    } in await _audited_mfa_failures(store)
    user = await store.get_user(e.user_id)
    assert user is not None and user.failed_attempts == 0
    assert user.second_step_failed_attempts == 0

    # The code was never checked, so its step was not spent: it verifies once the row has an id.
    await store._db.execute(
        "UPDATE users SET directory_object_id = ? WHERE id = ?",
        (_PRINCIPAL.directory_object_id, e.user_id),
    )
    await store._db.commit()
    assert (await e.service.verify_mfa(e.token, code)).ok is True


async def test_a_confirmed_directory_accounts_wrong_code_still_feeds_the_lockout(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pathway rows say a directory account's TOTP leg feeds the lockout. The directory check
    must add a refusal and exempt nothing, so a confirmed account's wrong code still counts. ADR
    0197: it counts on the SECOND-STEP counter, because the caller holds a session."""
    e = await _enrolled_directory_session(store, monkeypatch)

    wrong = await e.service.verify_mfa(e.token, "000000")

    assert wrong.ok is False and wrong.directory_refusal is None
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

    assert refused.locked is True and refused.directory_refusal is None
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


# BACKLOG #2240: a present account's stored roles must all be among the roles its current groups
# map to. Synthetic groups; the map gives each one role.
_OPERATORS = "CN=MF-Operators,OU=Groups,DC=test,DC=invalid"
_VIEWERS = "CN=MF-Viewers,OU=Groups,DC=test,DC=invalid"


async def _mapped_session(store: Store, monkeypatch: pytest.MonkeyPatch, *groups: str) -> _Enrolled:
    """A directory session whose roles the sign-in wrote from ``groups``, under the synthetic map."""
    await AuthService(store, _settings()).initialize()  # the map's role ids need the seeded roles
    await store.set_ad_group_role_map([(_OPERATORS, "operator"), (_VIEWERS, "viewer")])
    return await _enrolled_directory_session(
        store, monkeypatch, replace(_PRINCIPAL, groups=frozenset(groups))
    )


@pytest.mark.parametrize("now_in", [(_VIEWERS,), ()], ids=["one-role-lost", "every-role-lost"])
async def test_a_directory_account_demoted_since_sign_in_is_refused_the_renewal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, now_in: tuple[str, ...]
) -> None:
    """RED when: ``verify_mfa`` renews the window of an account the directory has since demoted, so
    it steps up with roles it no longer holds until the reconciler's role pass. The refusal must
    spend no code, charge nothing, and leave the stored roles for the reconciler to re-sync."""
    e = await _mapped_session(store, monkeypatch, _OPERATORS, _VIEWERS)
    assert set(await store.get_user_role_ids(e.user_id)) == {"operator", "viewer"}
    e.directory.principal = replace(_PRINCIPAL, groups=frozenset(now_in))
    code = totp.totp(e.secret, now=_T1)

    refused = await e.service.verify_mfa(e.token, code)

    assert refused.ok is False and refused.directory_refusal is DirectoryRefusal.DEMOTED
    assert refused.session_lost is False
    session = await store.get_session(hash_token(e.token))
    assert session is not None and session.revoked_at is None
    assert session.reauth_at is None and session.mfa_verified_at is None
    user = await store.get_user(e.user_id)
    assert user is not None and user.failed_attempts == 0
    assert user.second_step_failed_attempts == 0
    assert {
        "reason": DIRECTORY_UNCONFIRMED,
        "outcome": "directory_roles_demoted",
    } in await _audited_mfa_failures(store)
    assert set(await store.get_user_role_ids(e.user_id)) == {"operator", "viewer"}  # wrote nothing

    # The code was never checked: once the directory gives the groups back, the same code verifies.
    e.directory.principal = replace(_PRINCIPAL, groups=frozenset({_OPERATORS, _VIEWERS}))
    assert (await e.service.verify_mfa(e.token, code)).ok is True


async def test_a_role_map_that_fails_its_seal_is_not_called_a_demotion(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3082: a role map that fails its seal grants nothing, so every stored role would read
    as lost. That is no demotion: nothing changed in the directory, and a new sign-in takes its
    roles from the same failing map. So the refusal is UNCONFIRMED, whose text never says to sign
    out, and the audit row names the map.

    RED when the seal failure is refused as DEMOTED, which tells the operator to sign out."""
    e = await _mapped_session(store, monkeypatch, _OPERATORS, _VIEWERS)
    # The map fails its seal check (BACKLOG #2592). This store holds no sealing key, so the check is
    # failed directly, as tests/test_role_seal.py does.
    from messagefoundry.auth import service as service_module

    monkeypatch.setattr(service_module, "ad_map_seal_ok", lambda _sealer, _current: False)
    assert await e.service._ad_roles_for_groups([_OPERATORS]) == set(), "control: it fails"

    refused = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.ok is False
    assert refused.directory_refusal is DirectoryRefusal.UNCONFIRMED
    assert {
        "reason": DIRECTORY_UNCONFIRMED,
        "outcome": "directory_role_map_unsealed",
    } in await _audited_mfa_failures(store)


@pytest.mark.parametrize(
    "now_in", [(_VIEWERS,), (_OPERATORS, _VIEWERS)], ids=["unchanged", "promoted"]
)
async def test_a_directory_account_not_demoted_still_renews(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, now_in: tuple[str, ...]
) -> None:
    """The control: an unchanged account renews, and so does a promoted one, whose token holds fewer
    roles than the directory grants rather than more."""
    e = await _mapped_session(store, monkeypatch, _VIEWERS)
    e.directory.principal = replace(_PRINCIPAL, groups=frozenset(now_in))

    verified = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert verified.ok is True and verified.token is not None
    assert await e.service.has_recent_step_up(verified.token) is True


async def test_the_role_test_judges_the_roles_read_after_the_lookup(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3081 item 8: the role test judges the roles of the row read AFTER the lookup. Pinned
    by a bare role write during the lookup, with no session revocation. That is an instrument, not
    a production interleaving: every production role writer also revokes the account's sessions.
    RED when the test compares the roles read before the lookup, which still hold the role the
    directory took away."""
    e = await _mapped_session(store, monkeypatch, _OPERATORS, _VIEWERS)
    e.directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))
    original = e.service._directory_presence

    async def lookup_then_resync(user: Any) -> reconcile.Probe | str:
        answer = await original(user)
        await store.set_user_roles(e.user_id, ["viewer"], assigned_by="ad-sync")
        return answer

    monkeypatch.setattr(e.service, "_directory_presence", lookup_then_resync)

    verified = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert verified.ok is True and verified.token is not None


async def test_a_local_account_is_never_role_checked(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local account reads no group map: its roles are never compared with a directory's."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    identity, token, _ = await login_admin(service)
    await store.set_ad_group_role_map([(_OPERATORS, "operator")])
    enroll = await service.begin_mfa_enrollment(identity)
    confirmed = await service.confirm_mfa_enrollment(
        identity, fresh_totp(enroll.secret), token=token
    )
    assert confirmed.ok and confirmed.recovery_codes

    async def _never(name: str) -> object:
        raise AssertionError(f"a local account was compared with the directory map {name}")

    # The service reads the AD directory maps only through this reader (BACKLOG #2592).
    monkeypatch.setattr(store, "get_ad_map", _never)

    verified = await service.verify_mfa(confirmed.token, confirmed.recovery_codes[0])

    assert verified.ok is True
    assert directory.probes == []


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


@pytest.mark.parametrize(
    "change",
    [
        "lock",
        "revoke",
        "disable",
        "factor-off",
        "factor-replaced",
        "factor-replaced-same-stamp",
        "factor-restamped",
        "secret-unopenable",
    ],
)
@pytest.mark.parametrize("account", ["directory", "local"])
async def test_what_lands_during_the_code_check_stops_the_factor_write(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, change: str, account: str
) -> None:
    """BACKLOG #3068, item 2. A revocation, a disable or a factor reset needs no account queue to
    land, and the code check awaits, so the session, the account and its lock are read again right
    before the factor is written, for every account. RED when: a change that lands during a good
    code's check does not stop the write, which would then mark the factor, stamp the window and
    clear the lockout counters. ``factor-replaced`` turns TOTP off and enrols it again with a new
    secret, so the row holds a factor again but not the one the code proved; it is audited
    ``factor_replaced``, apart from a plain disable. ``factor-restamped`` enrols the SAME secret
    again under a new stamp, so only the stamp tells the enrolments apart. ``secret-unopenable``
    makes the fresh row's secret fail to open once the code is spent: refused and audited
    ``factor_unverified``, never raised."""
    if account == "directory":
        e = await _enrolled_directory_session(store, monkeypatch)
        service, token, user_id, code = e.service, e.token, e.user_id, totp.totp(e.secret, now=_T1)
        secret = e.secret
    else:
        service = AuthService(store, _settings())
        identity, first, _ = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        confirmed = await service.confirm_mfa_enrollment(
            identity, fresh_totp(enroll.secret), token=first
        )
        assert confirmed.ok and confirmed.token is not None and confirmed.recovery_codes
        # A fresh session that still owes its factor, proved by a single-use recovery code.
        token = await service._issue_session(
            identity.user_id,
            None,
            mfa_verified=False,
            seed_reauth=False,
            mechanism=SessionMechanism.PASSWORD,
            idp_auth_time=None,
        )
        user_id, code = identity.user_id, confirmed.recovery_codes[0]
        secret = enroll.secret
    real_verify = service._verify_second_factor

    async def _verify_while_something_lands(*args: Any, **kwargs: Any) -> bool:
        good = await real_verify(*args, **kwargs)
        if change == "lock":
            await _lock_second_step(store, user_id)
        elif change == "revoke":
            await store.revoke_session(hash_token(token))
        elif change == "disable":
            await store.set_user_disabled(user_id, disabled=True)
        elif change == "secret-unopenable":

            def _refuse(*_args: object) -> str | None:
                raise CipherError("synthetic: the cell does not open")

            monkeypatch.setattr(store, "open_totp_secret", _refuse)
        elif change == "factor-restamped":
            before = await store.get_user(user_id)
            assert before is not None and before.totp_enrolled_at is not None
            await store.disable_totp(user_id)
            cell = await store.set_totp_secret(user_id, secret=secret)
            assert cell is not None
            assert await store.enable_totp(
                user_id,
                recovery_code_hashes=[],
                expected_secret_cell=cell,
                now=before.totp_enrolled_at + 1.0,
            )
        else:
            before = await store.get_user(user_id)
            assert before is not None
            await store.disable_totp(user_id)
            if change.startswith("factor-replaced"):
                cell = await store.set_totp_secret(user_id, secret=_REPLACING_SECRET)
                assert cell is not None
                # ``-same-stamp`` gives the new enrolment the old one's stamp, so only the secret
                # tells them apart; the other passes an explicit, different stamp.
                stamp = before.totp_enrolled_at if change.endswith("same-stamp") else _T1
                assert stamp is not None
                assert await store.enable_totp(
                    user_id, recovery_code_hashes=[], expected_secret_cell=cell, now=stamp
                )
        return good

    monkeypatch.setattr(service, "_verify_second_factor", _verify_while_something_lands)

    refused = await service.verify_mfa(token, code)

    assert refused.ok is False
    assert refused.session_lost is (change in ("revoke", "disable"))
    assert refused.locked is (change == "lock")
    reason = {
        "lock": "locked",
        "factor-off": "factor_removed",
        "factor-replaced": "factor_replaced",
        "factor-replaced-same-stamp": "factor_replaced",
        "factor-restamped": "factor_replaced",
        "secret-unopenable": "factor_unverified",
    }.get(change, "session_lost")
    assert {"reason": reason} in await _audited_mfa_failures(store)
    session = await store.get_session(hash_token(token))
    assert session is not None
    assert session.mfa_verified_at is None and session.reauth_at is None
    if change == "lock":
        user = await store.get_user(user_id)
        assert user is not None and user.second_step_locked_until is not None  # not cleared


#: Each case: the change landing during the check, whether the code sent is the correct one, and the
#: reason it is refused with (``None``: charged as a wrong code).
_CHANGED_FACTOR_CASES: dict[str, tuple[str, bool, str | None]] = {
    "factor-off": ("factor-off", True, "factor_removed"),
    "factor-replaced": ("factor-replaced", True, "factor_replaced"),
    "factor-replaced-same-stamp": ("factor-replaced-same-stamp", True, "factor_replaced"),
    "wrong-code-meets-a-change": ("factor-off", False, None),
    "wrong-code": ("none", False, None),
}


@pytest.mark.parametrize("case", list(_CHANGED_FACTOR_CASES))
async def test_a_factor_changed_during_the_check_charges_no_lockout(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """BACKLOG #3780 item 1. A self-service disable or re-enrolment takes no queue and clears the
    recovery codes the check spends, so a CORRECT recovery code whose factor is turned off, or
    turned off and enrolled again, while the code is checked fails its spend. RED when: that code
    falls through to the wrong-code branch, which charges the second-step lockout, rather than
    being refused with its own reason. ``-same-stamp`` gives the new enrolment the old stamp, so
    only the secret tells them apart. The controls: a WRONG code is charged whether or not a change
    lands during its check, since it matched nothing."""
    change, correct, reason = _CHANGED_FACTOR_CASES[case]
    service = AuthService(store, _settings())
    identity, first, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    confirmed = await service.confirm_mfa_enrollment(
        identity, fresh_totp(enroll.secret), token=first
    )
    assert confirmed.ok and confirmed.token is not None and confirmed.recovery_codes
    user_id = identity.user_id
    real_verify = service._verify_second_factor

    async def _verify_while_the_factor_changes(*args: Any, **kwargs: Any) -> bool:
        # The check holds the row it loaded, so a change landing now is one it cannot see.
        before = await store.get_user(user_id)
        assert before is not None
        if change != "none":
            await store.disable_totp(user_id)
        if change.startswith("factor-replaced"):
            cell = await store.set_totp_secret(user_id, secret=_REPLACING_SECRET)
            assert cell is not None
            stamp = before.totp_enrolled_at if change.endswith("same-stamp") else _T1
            assert stamp is not None
            assert await store.enable_totp(
                user_id, recovery_code_hashes=[], expected_secret_cell=cell, now=stamp
            )
        return await real_verify(*args, **kwargs)

    monkeypatch.setattr(service, "_verify_second_factor", _verify_while_the_factor_changes)
    code = confirmed.recovery_codes[0] if correct else "ZZZZ-ZZZZ-ZZZZ"

    refused = await service.verify_mfa(confirmed.token, code)

    assert refused.ok is False and refused.locked is False and refused.session_lost is False
    user = await store.get_user(user_id)
    assert user is not None
    if reason is None:
        assert user.second_step_failed_attempts == 1
        return
    assert {"reason": reason} in await _audited_mfa_failures(store)
    assert user.second_step_failed_attempts == 0
    # No plain wrong-code row: the refusal is audited once, with its reason.
    rows = await store.list_audit(action="auth.mfa_failed")
    assert all(r["detail"] for r in rows)


@pytest.mark.parametrize("change", ["reset", "admin-replace"])
async def test_a_factor_changed_with_the_sessions_revoked_answers_a_lost_session(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """BACKLOG #3780 item 1, the review of PR 2392 at 5d8901d8. An MFA reset, or an administrator's
    replace, turns the factor off (and enrols a new one) and revokes the sessions, so a CORRECT
    recovery code checked meanwhile fails its spend on a session that no longer authenticates. RED
    when: the failed-spend branch answers ``factor_removed`` or ``factor_replaced`` with
    ``session_lost`` unset, because it skipped the holder re-read the proved branch runs. The code
    matched, so it is still charged nothing."""
    service = AuthService(store, _settings())
    identity, first, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    confirmed = await service.confirm_mfa_enrollment(
        identity, fresh_totp(enroll.secret), token=first
    )
    assert confirmed.ok and confirmed.token is not None and confirmed.recovery_codes
    token = confirmed.token
    user_id = identity.user_id
    real_verify = service._verify_second_factor

    async def _verify_while_an_admin_changes_the_factor(*args: Any, **kwargs: Any) -> bool:
        # The check holds the row it loaded, so a change landing now is one it cannot see.
        await store.disable_totp(user_id)
        if change == "admin-replace":
            cell = await store.set_totp_secret(user_id, secret=_REPLACING_SECRET)
            assert cell is not None
            assert await store.enable_totp(
                user_id, recovery_code_hashes=[], expected_secret_cell=cell, now=_T1
            )
        await store.revoke_session(hash_token(token))
        return await real_verify(*args, **kwargs)

    monkeypatch.setattr(service, "_verify_second_factor", _verify_while_an_admin_changes_the_factor)

    refused = await service.verify_mfa(token, confirmed.recovery_codes[0])

    assert refused.ok is False and refused.session_lost is True and refused.locked is False
    failures = await _audited_mfa_failures(store)
    assert {"reason": "session_lost"} in failures
    assert {"reason": "factor_removed"} not in failures
    assert {"reason": "factor_replaced"} not in failures
    user = await store.get_user(user_id)
    assert user is not None and user.second_step_failed_attempts == 0


#: Each case: what lands with the factor turned off during the check, and what the refusal is:
#: ``session_lost``, ``locked``, or ``charged`` (the re-read raised, which proves no change).
_FAILED_SPEND_REREAD_CASES = {
    "disable": "session_lost",
    "lock": "locked",
    "reread-raises": "charged",
}


@pytest.mark.parametrize("change", list(_FAILED_SPEND_REREAD_CASES))
async def test_the_failed_spend_reread_answers_the_holder_first(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """BACKLOG #3780 item 1, the review of PR 2392. A CORRECT recovery code whose factor is turned
    off during the check fails its spend, and the branch that then asks why reads the session, the
    account and its lock first. RED when: an account disabled meanwhile answers ``factor_removed``
    rather than a lost session, a lock landing meanwhile is not answered ``locked``, or either
    charges the matched code; or when a re-read that raises is not charged (fail closed)."""
    outcome = _FAILED_SPEND_REREAD_CASES[change]
    service = AuthService(store, _settings())
    identity, first, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    confirmed = await service.confirm_mfa_enrollment(
        identity, fresh_totp(enroll.secret), token=first
    )
    assert confirmed.ok and confirmed.token is not None and confirmed.recovery_codes
    user_id = identity.user_id
    real_verify = service._verify_second_factor

    async def _verify_while_something_lands(*args: Any, **kwargs: Any) -> bool:
        await store.disable_totp(user_id)
        if change == "disable":
            await store.set_user_disabled(user_id, disabled=True)
        elif change == "lock":
            await _lock_second_step(store, user_id)
        return await real_verify(*args, **kwargs)

    async def _reread_fails(*_args: Any, **_kwargs: Any) -> object:
        raise RuntimeError("synthetic: the holder re-read failed")

    monkeypatch.setattr(service, "_verify_second_factor", _verify_while_something_lands)
    if change == "reread-raises":
        monkeypatch.setattr(service, "_factor_holder_current", _reread_fails)

    refused = await service.verify_mfa(confirmed.token, confirmed.recovery_codes[0])

    assert refused.ok is False
    assert refused.session_lost is (outcome == "session_lost")
    assert refused.locked is (outcome == "locked")
    failures = await _audited_mfa_failures(store)
    assert {"reason": "factor_removed"} not in failures
    if outcome == "session_lost":
        assert {"reason": "session_lost"} in failures
    user = await store.get_user(user_id)
    assert user is not None
    # The lock case's one failure is the lock itself; the code adds none.
    assert user.second_step_failed_attempts == (0 if outcome == "session_lost" else 1)


async def test_a_rename_during_the_code_check_is_audited_under_the_new_name(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3068 (the #2291 class). A directory rename needs no account queue to land, so the
    success is filed under the name the row holds when the factor is written. RED when: the
    ``auth.mfa_verified`` row names the account as it was before the rename."""
    e = await _enrolled_directory_session(store, monkeypatch)
    real_verify = e.service._verify_second_factor

    async def _verify_while_renamed(*args: Any, **kwargs: Any) -> bool:
        good = await real_verify(*args, **kwargs)
        assert await store.set_user_username(e.user_id, "jdoe-renamed", expected_username="jdoe")
        return good

    monkeypatch.setattr(e.service, "_verify_second_factor", _verify_while_renamed)

    verified = await e.service.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert verified.ok
    rows = await store.list_audit(action="auth.mfa_verified")
    assert [r["actor"] for r in rows] == ["jdoe-renamed"]


async def test_a_replayed_code_checked_across_a_rename_is_charged_under_the_new_name(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3780 item 1, the review of PR 2392 at fcac75a5. A replayed code MATCHES but fails its
    spend with the factor unchanged, so it is charged as a wrong code, and against the row the
    holder re-read returned: a rename landing during the check must not leave the wrong-code row
    and the lockout naming the account as it was. RED when: the ``auth.mfa_failed`` row names the
    old username, or the replay is not charged."""
    e = await _enrolled_directory_session(store, monkeypatch)
    (second,) = await _more_sessions(e, 1)
    code = totp.totp(e.secret, now=_T1)
    assert (await e.service.verify_mfa(e.token, code)).ok
    real_verify = e.service._verify_second_factor

    async def _verify_while_renamed(*args: Any, **kwargs: Any) -> bool:
        good = await real_verify(*args, **kwargs)
        assert await store.set_user_username(e.user_id, "jdoe-renamed", expected_username="jdoe")
        return good

    monkeypatch.setattr(e.service, "_verify_second_factor", _verify_while_renamed)

    refused = await e.service.verify_mfa(second, code)

    assert refused.ok is False and refused.session_lost is False and refused.locked is False
    rows = await store.list_audit(action="auth.mfa_failed")
    assert [r["actor"] for r in rows] == ["jdoe-renamed"]
    user = await store.get_user(e.user_id)
    assert user is not None and user.second_step_failed_attempts == 1


async def test_a_secret_that_does_not_open_for_the_check_is_refused_and_spends_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3068, review of the merged head. A TOTP cell that does not open before the code is
    checked is refused ``factor_unverified``, never raised, and the check stops at its TOTP
    decrypt, so a recovery code sent with it is not spent. RED when: verify_mfa raises
    ``CipherError``, or the refused recovery code no longer verifies once the cell opens again."""
    service = AuthService(store, _settings())
    identity, first, _ = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    confirmed = await service.confirm_mfa_enrollment(
        identity, fresh_totp(enroll.secret), token=first
    )
    assert confirmed.ok and confirmed.recovery_codes
    token = await service._issue_session(
        identity.user_id,
        None,
        mfa_verified=False,
        seed_reauth=False,
        mechanism=SessionMechanism.PASSWORD,
        idp_auth_time=None,
    )
    real_open = store.open_totp_secret
    state = {"broken": True}

    def _sometimes_refuses(*args: Any) -> str | None:
        if state["broken"]:
            raise CipherError("synthetic: the cell does not open")
        return real_open(*args)

    monkeypatch.setattr(store, "open_totp_secret", _sometimes_refuses)

    refused = await service.verify_mfa(token, confirmed.recovery_codes[0])

    assert refused.ok is False and not refused.session_lost and not refused.locked
    assert {"reason": "factor_unverified"} in await _audited_mfa_failures(store)
    state["broken"] = False  # the control: the same recovery code still verifies
    assert (await service.verify_mfa(token, confirmed.recovery_codes[0])).ok


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
    unwired = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))

    refused = await unwired.verify_mfa(e.token, totp.totp(e.secret, now=_T1))

    assert refused.ok is False and refused.directory_refusal is DirectoryRefusal.UNCONFIRMED
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


@pytest.mark.parametrize(
    ("cause", "outcome", "refusal"),
    [
        ("disabled", "disabled", DirectoryRefusal.UNCONFIRMED),
        ("outage", "unavailable", DirectoryRefusal.UNCONFIRMED),
        ("demotion", "directory_roles_demoted", DirectoryRefusal.DEMOTED),
    ],
)
async def test_the_route_says_which_fix_clears_the_directory_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cause: str,
    outcome: str,
    refusal: DirectoryRefusal,
) -> None:
    """The API answers 403, not the wrong-code 401, with the text for the fix that clears the cause
    (BACKLOG #3082; docs/SECURITY.md states which). A demotion is told to sign in again, which takes
    the roles the groups grant now. A disabled account or an outage is told to try later or ask an
    administrator, and never to sign out: a new sign-in fails the same way, and the working session
    would be gone. RED when the outage text tells the operator to sign out, or the demotion text
    only to wait. Neither names a group or a role."""
    engine = await Engine.create(
        tmp_path / "mfa_directory.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        if cause == "demotion":
            e = await _mapped_session(engine.store, monkeypatch, _OPERATORS, _VIEWERS)
            e.directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))
        else:
            e = await _enrolled_directory_session(engine.store, monkeypatch)
            e.directory.answer = DirectoryAnswer.DISABLED
            e.directory.unreachable = cause == "outage"
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
        detail = r.json()["detail"]
        if refusal is DirectoryRefusal.DEMOTED:
            assert "access changed in the directory" in detail
            assert "sign out and sign in again" in detail
            assert "try again later" not in detail
        else:
            assert "directory could not confirm this account" in detail
            assert "try again later" in detail and "ask an administrator" in detail
            assert "sign out" not in detail and "sign in" not in detail
        for internal in (
            "MF-Operators",
            "MF-Viewers",
            "operator",
            "viewer",
            "demoted",
            "group",
            "role",
        ):
            assert internal not in detail
        # The cause the test set is the one the engine met: the precise reason is on the audit row.
        audited = [row["outcome"] for row in await _audited_mfa_failures(engine.store)]
        assert audited == [outcome]
    finally:
        await engine.stop()


async def test_the_route_refuses_and_does_not_500_when_the_lookup_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2241, where the operator meets it: a lookup fault that is not an LdapError used to
    reach the route as a 500. It is the same 403 refusal as any other unconfirmed account."""
    engine = await Engine.create(
        tmp_path / "mfa_directory_raises.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        e = await _enrolled_directory_session(engine.store, monkeypatch)
        e.directory.raises = KeyError("userAccountControl")
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
