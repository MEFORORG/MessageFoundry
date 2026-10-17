# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The two enrolment legs ask the directory before a directory account's new factor marks the
session met.

BACKLOG #3061. ``verify_mfa`` (#2023) and ``finish_webauthn_assertion`` (#2239) ask through
``_directory_vouches_for_factor``. ``confirm_mfa_enrollment`` and ``finish_webauthn_registration``
did not, so on a first deployment an account disabled or demoted in the directory could still
finish an enrolment and clear the MFA gate until the reconciler revoked it.

Each refusal asserts what it must not spend. On the TOTP leg: no TOTP step (the same code confirms
once the directory answers), no recovery codes minted, MFA left off. On the passkey leg: no
challenge popped (the same response registers once the directory answers) and no credential
stored. A local account is the control that must never reach the directory. All directory data
here is synthetic.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace

import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.auth import reconcile, totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer
from messagefoundry.auth.service import (
    DIRECTORY_OBJECT_ID_MISSING,
    DIRECTORY_ROLES_DEMOTED,
    DIRECTORY_UNCONFIRMED,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore, UserRecord
from tests._admin_account import login_admin
from tests._fake_directory import FakeDirectory as _Directory

_T0 = 1_700_000_000.0
_RP, _ORIGIN = "t", "http://t"

_PRINCIPAL = AdPrincipal(
    username="mrivera",
    display_name="M Rivera",
    email="mrivera@test.invalid",
    dn="CN=mrivera,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="9a4c2e71-3b8d-4f60-b1a2-7c5d9e0f1a23",
)

# BACKLOG #2240's role pair, which the helper brings with it (#3081 item 3). Synthetic groups.
_OPERATORS = "CN=MF-Operators,OU=Groups,DC=test,DC=invalid"
_VIEWERS = "CN=MF-Viewers,OU=Groups,DC=test,DC=invalid"

# The refusals the directory can answer with, each with the outcome its audit row names.
_REFUSALS = pytest.mark.parametrize(
    ("answer", "unreachable", "outcome"),
    [
        (DirectoryAnswer.DISABLED, False, "disabled"),
        (DirectoryAnswer.NOT_FOUND, False, "absent"),
        (DirectoryAnswer.UNDETERMINED, False, "undetermined"),
        (DirectoryAnswer.FOUND, True, "unavailable"),
    ],
    ids=["disabled", "absent", "undetermined", "unavailable"],
)


def _settings(**overrides: object) -> AuthSettings:
    # require_mfa off so a passkey may be a first factor (ADR 0197 Amendment A keeps a covered
    # account's first factor TOTP). The floor is off: it is not the subject, and its order against
    # the lookup has its own test below.
    return AuthSettings(
        **{  # type: ignore[arg-type]
            "require_mfa": False,
            "mfa_verify_min_elapsed_seconds": 0,
            "ad_enabled": True,
            "ad_server": "ldaps://dc.test.invalid",
            "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
            "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
            "ad_bind_password": "synthetic",
            **overrides,
        }
    )


@dataclass
class _Signed:
    service: AuthService
    store: MessageStore
    directory: _Directory
    identity: Identity
    token: str


async def _directory_sign_in(
    store: MessageStore,
    principal: AdPrincipal = _PRINCIPAL,
    settings: AuthSettings | None = None,
) -> _Signed:
    """A directory account signed in with no factor yet, through ``_complete_ad_login``, the shared
    tail Kerberos and OIDC both reach."""
    directory = _Directory(principal)
    service = AuthService(store, settings or _settings(), ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    out = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert out.token is not None and out.identity is not None
    return _Signed(service, store, directory, out.identity, out.token)


async def _mapped_sign_in(store: MessageStore, *groups: str) -> _Signed:
    """A directory sign-in whose roles were written from ``groups``."""
    await AuthService(store, _settings()).initialize()  # the map's role ids need the seeded roles
    await store.set_ad_group_role_map([(_OPERATORS, "operator"), (_VIEWERS, "viewer")])
    return await _directory_sign_in(store, replace(_PRINCIPAL, groups=frozenset(groups)))


async def _audited(store: MessageStore, action: str) -> list[dict[str, object]]:
    rows = await store.list_audit(action=action)
    return [json.loads(r["detail"]) for r in rows if r["detail"]]


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


# --- the TOTP leg: confirm_mfa_enrollment ------------------------------------------------------


@dataclass
class _TotpStaged:
    signed: _Signed
    code: str  # the live code for the staged secret
    minted: list[int]  # one entry per recovery-code mint


async def _totp_staged(
    s: _Signed, monkeypatch: pytest.MonkeyPatch, *, clear_probes: bool = True
) -> _TotpStaged:
    pin_totp_clock(monkeypatch, _T0)
    enroll = await s.service.begin_mfa_enrollment(s.identity)
    minted: list[int] = []
    real_mint: Callable[[int], list[str]] = totp.generate_recovery_codes

    def _counting_mint(count: int) -> list[str]:
        minted.append(count)
        return real_mint(count)

    monkeypatch.setattr(totp, "generate_recovery_codes", _counting_mint)
    if clear_probes:
        s.directory.probes.clear()
    return _TotpStaged(s, totp.totp(enroll.secret, now=_T0), minted)


async def _assert_totp_refused_and_unspent(t: _TotpStaged, outcome: str) -> None:
    s = t.signed
    refused = await s.service.confirm_mfa_enrollment(s.identity, t.code, token=s.token)
    assert refused.ok is False
    assert refused.directory_unconfirmed is True
    assert refused.session_lost is False
    assert refused.recovery_codes == ()
    assert t.minted == []  # no recovery codes were minted
    session = await s.store.get_session(hash_token(s.token))
    assert session is not None and session.revoked_at is None  # the token still authenticates
    assert session.mfa_verified_at is None  # the factor was not marked
    user = await s.store.get_user(s.identity.user_id)
    assert user is not None and not user.totp_enabled
    assert await s.store.get_recovery_code_hashes(s.identity.user_id) == []
    assert user.second_step_failed_attempts == 0  # nothing charged
    assert {"reason": DIRECTORY_UNCONFIRMED, "outcome": outcome, "phase": "enroll"} in (
        await _audited(s.store, "auth.mfa_failed")
    )


@_REFUSALS
async def test_a_directory_the_account_is_not_confirmed_in_refuses_the_totp_enrolment(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    answer: DirectoryAnswer,
    unreachable: bool,
    outcome: str,
) -> None:
    """RED when: ``confirm_mfa_enrollment`` marks a directory account's factor without asking the
    directory, or asks only after it consumed the TOTP step or minted the recovery codes."""
    t = await _totp_staged(await _directory_sign_in(store), monkeypatch)
    t.signed.directory.answer = answer
    t.signed.directory.unreachable = unreachable

    await _assert_totp_refused_and_unspent(t, outcome)
    assert t.signed.directory.probes == [("mrivera", _PRINCIPAL.directory_object_id)]

    # The step was not consumed, so the SAME code confirms once the directory answers.
    t.signed.directory.answer = DirectoryAnswer.FOUND
    t.signed.directory.unreachable = False
    served = await t.signed.service.confirm_mfa_enrollment(
        t.signed.identity, t.code, token=t.signed.token
    )
    assert served.ok is True and len(served.recovery_codes) > 0
    assert served.token is not None and await t.signed.service.mfa_satisfied(served.token)


async def test_a_row_with_no_directory_id_is_refused_the_totp_enrolment_unasked(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0184 AC-5, BACKLOG #2027: a row with no immutable id is refused without a lookup."""
    t = await _totp_staged(await _directory_sign_in(store), monkeypatch)
    await store._db.execute(
        "UPDATE users SET directory_object_id = NULL WHERE id = ?", (t.signed.identity.user_id,)
    )
    await store._db.commit()

    await _assert_totp_refused_and_unspent(t, DIRECTORY_OBJECT_ID_MISSING)
    assert t.signed.directory.probes == []


async def test_a_directory_account_demoted_since_sign_in_is_refused_the_totp_enrolment(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3081 item 3: the helper brings #2240's role check to this leg. RED when a demoted
    account still enrols and clears the gate with roles it no longer holds."""
    t = await _totp_staged(await _mapped_sign_in(store, _OPERATORS, _VIEWERS), monkeypatch)
    t.signed.directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))

    await _assert_totp_refused_and_unspent(t, DIRECTORY_ROLES_DEMOTED)
    assert set(await store.get_user_role_ids(t.signed.identity.user_id)) == {"operator", "viewer"}


async def test_a_present_enabled_directory_account_still_enrols_totp(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the check must not refuse the account it exists to let through."""
    t = await _totp_staged(await _directory_sign_in(store), monkeypatch)

    served = await t.signed.service.confirm_mfa_enrollment(
        t.signed.identity, t.code, token=t.signed.token
    )

    assert served.ok is True and t.minted != []
    assert t.signed.directory.probes == [("mrivera", _PRINCIPAL.directory_object_id)]


async def test_a_session_revoked_during_the_lookup_is_a_lost_totp_enrolment(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lookup is a network round trip; the re-read after it ends a revoked session's confirm as
    ``session_lost``, before the step is consumed. RED when the confirm goes on to spend the step."""
    t = await _totp_staged(await _directory_sign_in(store), monkeypatch)
    real_probe = t.signed.service._probe_principal

    async def _probe_while_revoked(user: UserRecord) -> reconcile.Probe:
        await store.revoke_session(hash_token(t.signed.token))
        return await real_probe(user)

    monkeypatch.setattr(t.signed.service, "_probe_principal", _probe_while_revoked)

    lost = await t.signed.service.confirm_mfa_enrollment(
        t.signed.identity, t.code, token=t.signed.token
    )

    assert lost.ok is False and lost.session_lost is True and lost.directory_unconfirmed is False
    assert t.minted == []
    assert {"reason": "session_lost", "phase": "enroll"} in await _audited(store, "auth.mfa_failed")
    # The step is unspent: a new session confirms with the same code.
    again = await t.signed.service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
    assert again.token is not None and again.identity is not None
    monkeypatch.setattr(t.signed.service, "_probe_principal", real_probe)
    served = await t.signed.service.confirm_mfa_enrollment(
        again.identity, t.code, token=again.token
    )
    assert served.ok is True


async def test_the_totp_enrolment_lookup_comes_after_the_floor(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A floored confirm costs no lookup. RED when the lookup moves ahead of the floor."""
    s = await _directory_sign_in(store, settings=_settings(require_mfa=True))
    s.service._settings = _settings(require_mfa=True, mfa_verify_min_elapsed_seconds=60)
    t = await _totp_staged(s, monkeypatch)
    s.directory.answer = DirectoryAnswer.DISABLED  # a lookup ahead of the floor would refuse

    floored = await s.service.confirm_mfa_enrollment(s.identity, t.code, token=s.token)

    assert floored.ok is False and floored.directory_unconfirmed is False
    assert s.directory.probes == []


async def test_a_local_account_is_never_probed_on_totp_enrolment(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local account's enrolment is unchanged, and costs no directory round trip."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    identity, token, _password = await login_admin(service)
    pin_totp_clock(monkeypatch, _T0)
    enroll = await service.begin_mfa_enrollment(identity)

    served = await service.confirm_mfa_enrollment(
        identity, totp.totp(enroll.secret, now=_T0), token=token
    )

    assert served.ok is True
    assert directory.probes == []


# --- the passkey leg: finish_webauthn_registration ---------------------------------------------


@dataclass
class _PasskeyStaged:
    signed: _Signed
    response: str  # an attestation answering the staged registration challenge


async def _passkey_staged(s: _Signed) -> _PasskeyStaged:
    pytest.importorskip("webauthn")
    from webauthn.helpers import base64url_to_bytes

    from tests._soft_webauthn import SoftAuthenticator

    options = json.loads(
        await s.service.begin_webauthn_registration(
            s.identity, token=s.token, rp_id=_RP, rp_name="MessageFoundry"
        )
    )
    key = SoftAuthenticator(rp_id=_RP, origin=_ORIGIN)
    s.directory.probes.clear()
    return _PasskeyStaged(s, key.create_response(base64url_to_bytes(options["challenge"])))


async def _register(p: _PasskeyStaged, token: str | None = None) -> object:
    return await p.signed.service.finish_webauthn_registration(
        p.signed.identity,
        p.response,
        label="key",
        token=token or p.signed.token,
        rp_id=_RP,
        origin=_ORIGIN,
    )


async def _assert_passkey_refused_and_unspent(p: _PasskeyStaged, outcome: str) -> None:
    s = p.signed
    refused = await s.service.finish_webauthn_registration(
        s.identity, p.response, label="key", token=s.token, rp_id=_RP, origin=_ORIGIN
    )
    assert refused.ok is False
    assert refused.directory_unconfirmed is True
    assert refused.session_lost is False
    assert await s.store.list_webauthn_credentials(s.identity.user_id) == []  # nothing stored
    session = await s.store.get_session(hash_token(s.token))
    assert session is not None and session.revoked_at is None
    assert session.mfa_verified_at is None
    # The challenge is still staged for this session: the refusal did not pop it.
    assert s.service._webauthn_challenges.peek((hash_token(s.token), "register")) is not None
    assert {"reason": DIRECTORY_UNCONFIRMED, "outcome": outcome, "phase": "enroll"} in (
        await _audited(s.store, "auth.webauthn_failed")
    )


@_REFUSALS
async def test_a_directory_the_account_is_not_confirmed_in_refuses_the_passkey_registration(
    store: MessageStore, answer: DirectoryAnswer, unreachable: bool, outcome: str
) -> None:
    """RED when: ``finish_webauthn_registration`` marks a directory account's factor without asking
    the directory, or asks only after it popped the challenge or stored the passkey."""
    p = await _passkey_staged(await _directory_sign_in(store))
    p.signed.directory.answer = answer
    p.signed.directory.unreachable = unreachable

    await _assert_passkey_refused_and_unspent(p, outcome)
    assert p.signed.directory.probes == [("mrivera", _PRINCIPAL.directory_object_id)]

    # The ceremony stayed in flight, so the SAME response registers once the directory answers.
    p.signed.directory.answer = DirectoryAnswer.FOUND
    p.signed.directory.unreachable = False
    served = await p.signed.service.finish_webauthn_registration(
        p.signed.identity, p.response, label="key", token=p.signed.token, rp_id=_RP, origin=_ORIGIN
    )
    assert served.ok is True
    assert len(await store.list_webauthn_credentials(p.signed.identity.user_id)) == 1


async def test_a_directory_account_demoted_since_sign_in_is_refused_the_passkey_registration(
    store: MessageStore,
) -> None:
    """BACKLOG #3081 item 3, on the passkey enrolment leg."""
    p = await _passkey_staged(await _mapped_sign_in(store, _OPERATORS, _VIEWERS))
    p.signed.directory.principal = replace(_PRINCIPAL, groups=frozenset())

    await _assert_passkey_refused_and_unspent(p, DIRECTORY_ROLES_DEMOTED)


async def test_a_directory_account_with_no_directory_configured_is_refused_the_passkey(
    store: MessageStore,
) -> None:
    """An AD row left behind after the directory is unwired has nothing to confirm it."""
    p = await _passkey_staged(await _directory_sign_in(store))
    unwired = AuthService(store, AuthSettings(require_mfa=False, mfa_verify_min_elapsed_seconds=0))
    unwired._webauthn_challenges = p.signed.service._webauthn_challenges
    p.signed.service = unwired

    await _assert_passkey_refused_and_unspent(p, "not_configured")


async def test_a_disable_during_the_lookup_is_a_lost_passkey_registration(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The re-read after the lookup ends the registration when the account was disabled meanwhile,
    before the challenge is popped or the passkey stored."""
    p = await _passkey_staged(await _directory_sign_in(store))
    real_probe = p.signed.service._probe_principal

    async def _probe_while_disabled(user: UserRecord) -> reconcile.Probe:
        await store.set_user_disabled(p.signed.identity.user_id, disabled=True)
        return await real_probe(user)

    monkeypatch.setattr(p.signed.service, "_probe_principal", _probe_while_disabled)

    lost = await p.signed.service.finish_webauthn_registration(
        p.signed.identity, p.response, label="key", token=p.signed.token, rp_id=_RP, origin=_ORIGIN
    )

    assert lost.ok is False and lost.session_lost is True
    assert await store.list_webauthn_credentials(p.signed.identity.user_id) == []
    assert {"reason": "session_lost", "phase": "enroll"} in await _audited(
        store, "auth.webauthn_failed"
    )


async def test_a_local_account_is_never_probed_on_passkey_registration(
    store: MessageStore,
) -> None:
    """A local account's passkey registration is unchanged, and costs no directory round trip."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    identity, token, _password = await login_admin(service)
    p = await _passkey_staged(_Signed(service, store, directory, identity, token))

    served = await _register(p)

    assert getattr(served, "ok", False) is True
    assert directory.probes == []
