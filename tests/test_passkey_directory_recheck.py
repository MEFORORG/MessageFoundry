# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``finish_webauthn_assertion`` asks the directory before a directory account's passkey marks the
factor met.

BACKLOG #2239. ``verify_mfa`` has asked since #2023 (``tests/test_mfa_directory_recheck.py``). The
passkey leg did not, so an account disabled in the directory could clear the MFA gate with its
passkey until the reconciliation pass revoked it.

Each refusal asserts four things: the factor was not marked, the challenge was not taken (the same
assertion verifies once the directory answers), the sign count did not move, and nothing was charged
to the lockout. A local account is the control that must never reach the directory. All directory
data here is synthetic.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from typing import Any

import pytest

pytest.importorskip("webauthn")

from webauthn.helpers import base64url_to_bytes  # noqa: E402

from messagefoundry.auth import reconcile  # noqa: E402
from messagefoundry.auth.identity import SessionMechanism  # noqa: E402
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer  # noqa: E402
from messagefoundry.auth.service import (  # noqa: E402
    DIRECTORY_OBJECT_ID_MISSING,
    DIRECTORY_ROLES_DEMOTED,
    DIRECTORY_UNCONFIRMED,
    AuthService,
    Elevation,
)
from messagefoundry.auth.tokens import hash_token  # noqa: E402
from messagefoundry.config.settings import AuthSettings  # noqa: E402
from messagefoundry.store.store import MessageStore, UserRecord  # noqa: E402
from tests._admin_account import ADMIN_USERNAME, login_admin  # noqa: E402
from tests._fake_directory import FakeDirectory as _Directory  # noqa: E402
from tests._soft_webauthn import SoftAuthenticator  # noqa: E402

_RP, _ORIGIN = "t", "http://t"

_PRINCIPAL = AdPrincipal(
    username="kpark",
    display_name="K Park",
    email="kpark@test.invalid",
    dn="CN=kpark,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="3b9e7a10-5c2d-4f8e-a1b6-0d4c8e2f7a91",
)


def _settings() -> AuthSettings:
    # require_mfa off so a passkey may be the account's first factor (ADR 0197 Amendment A keeps a
    # covered account's first factor TOTP). The factor is still owed once the account holds one.
    return AuthSettings(
        require_mfa=False,
        mfa_verify_min_elapsed_seconds=0,
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
    )


@dataclass
class _Pending:
    service: AuthService
    store: MessageStore
    directory: _Directory
    token: str  # a session that still owes its passkey
    user_id: str
    response: str  # an assertion answering the session's staged challenge
    key: SoftAuthenticator  # the account's one passkey


async def _register_passkey(
    service: AuthService, identity: object, token: str, key: SoftAuthenticator
) -> None:
    options = json.loads(
        await service.begin_webauthn_registration(
            identity,  # type: ignore[arg-type]
            token=token,
            rp_id=_RP,
            rp_name="MessageFoundry",
        )
    )
    enrolled = await service.finish_webauthn_registration(
        identity,  # type: ignore[arg-type]
        key.create_response(base64url_to_bytes(options["challenge"])),
        label="key",
        token=token,
        rp_id=_RP,
        origin=_ORIGIN,
    )
    assert enrolled.ok


async def _staged_assertion(service: AuthService, token: str, key: SoftAuthenticator) -> str:
    challenge = await service.begin_webauthn_assertion(token, rp_id=_RP)
    assert challenge is not None
    return key.get_response(base64url_to_bytes(json.loads(challenge)["challenge"]))


async def _directory_session_owing_a_passkey(
    store: MessageStore, principal: AdPrincipal = _PRINCIPAL
) -> _Pending:
    """A directory account holding a passkey, a new session owing it, and a staged assertion.

    Mints through ``_complete_ad_login``, the shared tail Kerberos and OIDC both reach, because the
    subject is the second-factor leg and not the sign-in mechanism. The authenticator's counter
    starts above zero, so a counter that moved is visible.
    """
    directory = _Directory(principal)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    first = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert first.token is not None and first.identity is not None
    key = SoftAuthenticator(rp_id=_RP, origin=_ORIGIN, sign_count=5)
    await _register_passkey(service, first.identity, first.token, key)
    second = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert second.token is not None and second.identity is not None
    assert await service.mfa_satisfied(second.token) is False
    response = await _staged_assertion(service, second.token, key)
    directory.probes.clear()
    return _Pending(service, store, directory, second.token, second.identity.user_id, response, key)


async def _finish(p: _Pending) -> Elevation:
    return await p.service.finish_webauthn_assertion(p.token, p.response, rp_id=_RP, origin=_ORIGIN)


async def _sign_count(store: MessageStore, user_id: str) -> int:
    (cred,) = await store.list_webauthn_credentials(user_id)
    return cred.sign_count


async def _audited_assertion_failures(store: MessageStore) -> list[dict[str, object]]:
    rows = await store.list_audit(action="auth.webauthn_failed")
    return [json.loads(r["detail"]) for r in rows if r["detail"]]


async def _assert_refused_and_uncharged(p: _Pending, outcome: str, sign_count: int) -> None:
    refused = await p.service.finish_webauthn_assertion(
        p.token, p.response, rp_id=_RP, origin=_ORIGIN
    )
    assert refused.ok is False
    assert refused.directory_unconfirmed is True
    assert refused.session_lost is False
    session = await p.store.get_session(hash_token(p.token))
    assert session is not None and session.revoked_at is None  # the token still authenticates
    assert session.mfa_verified_at is None  # the factor was not marked
    assert session.reauth_at is None
    assert await _sign_count(p.store, p.user_id) == sign_count  # the counter did not move
    user = await p.store.get_user(p.user_id)
    # Nothing charged to either lockout counter (ADR 0197 splits them).
    assert user is not None and user.failed_attempts == 0
    assert user.second_step_failed_attempts == 0
    assert {"reason": DIRECTORY_UNCONFIRMED, "outcome": outcome} in (
        await _audited_assertion_failures(p.store)
    )


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
async def test_a_directory_the_account_is_not_confirmed_in_refuses_the_passkey(
    store: MessageStore, answer: DirectoryAnswer, unreachable: bool, outcome: str
) -> None:
    """RED when: ``finish_webauthn_assertion`` marks a directory account's factor without asking the
    directory, asks only after taking the challenge or moving the counter, or fails open on an
    outage."""
    p = await _directory_session_owing_a_passkey(store)
    before = await _sign_count(store, p.user_id)
    p.directory.answer = answer
    p.directory.unreachable = unreachable

    await _assert_refused_and_uncharged(p, outcome, before)
    assert p.directory.probes == [("kpark", _PRINCIPAL.directory_object_id)]  # by the immutable id

    # The challenge was not taken and the counter did not move, so the SAME assertion verifies once
    # the directory confirms the account.
    p.directory.answer = DirectoryAnswer.FOUND
    p.directory.unreachable = False
    served = await p.service.finish_webauthn_assertion(
        p.token, p.response, rp_id=_RP, origin=_ORIGIN
    )
    assert served.ok is True and served.token is not None
    assert await _sign_count(store, p.user_id) > before


async def test_a_row_with_no_directory_id_is_refused_unasked(store: MessageStore) -> None:
    """ADR 0184 AC-5, BACKLOG #2027: a row with no ``directory_object_id`` has only its name to be
    asked by, and a directory may reissue a name. The passkey leg refuses it without a lookup, as
    ``verify_mfa`` does."""
    p = await _directory_session_owing_a_passkey(store)
    before = await _sign_count(store, p.user_id)
    await store._db.execute(
        "UPDATE users SET directory_object_id = NULL WHERE id = ?", (p.user_id,)
    )
    await store._db.commit()

    await _assert_refused_and_uncharged(p, DIRECTORY_OBJECT_ID_MISSING, before)
    assert p.directory.probes == []  # never a name-only probe


async def test_a_directory_account_with_no_directory_configured_is_refused(
    store: MessageStore,
) -> None:
    """An AD row left behind after the directory is unwired has nothing to confirm it."""
    p = await _directory_session_owing_a_passkey(store)
    before = await _sign_count(store, p.user_id)
    unwired = AuthService(store, AuthSettings(require_mfa=False, mfa_verify_min_elapsed_seconds=0))
    # The challenge cache is per service, so stage the unwired service's own: the refusal must
    # still come before it is taken.
    unwired._webauthn_challenges = p.service._webauthn_challenges
    p.service = unwired

    await _assert_refused_and_uncharged(p, "not_configured", before)


async def test_a_present_enabled_directory_account_still_clears_the_gate(
    store: MessageStore,
) -> None:
    """The control: the check must not refuse the account it exists to let through."""
    p = await _directory_session_owing_a_passkey(store)

    verified = await _finish(p)

    assert verified.ok is True
    assert p.directory.probes == [("kpark", _PRINCIPAL.directory_object_id)]
    assert await p.service.mfa_satisfied(verified.token) is True


# BACKLOG #2240: a present account's stored roles must all be among the roles its current groups
# map to. Synthetic groups; the map gives each one role.
_OPERATORS = "CN=MF-Operators,OU=Groups,DC=test,DC=invalid"
_VIEWERS = "CN=MF-Viewers,OU=Groups,DC=test,DC=invalid"


async def _mapped_session(store: MessageStore, *groups: str) -> _Pending:
    """A directory session owing a passkey, whose roles the sign-in wrote from ``groups``."""
    await AuthService(store, _settings()).initialize()  # the map's role ids need the seeded roles
    await store.set_ad_group_role_map([(_OPERATORS, "operator"), (_VIEWERS, "viewer")])
    return await _directory_session_owing_a_passkey(
        store, replace(_PRINCIPAL, groups=frozenset(groups))
    )


@pytest.mark.parametrize("now_in", [(_VIEWERS,), ()], ids=["one-role-lost", "every-role-lost"])
async def test_a_directory_account_demoted_since_sign_in_is_refused_the_passkey(
    store: MessageStore, now_in: tuple[str, ...]
) -> None:
    """RED when: the passkey leg clears the MFA gate for an account the directory has since demoted,
    or the refusal takes the challenge, moves the counter, charges the lockout or writes roles."""
    p = await _mapped_session(store, _OPERATORS, _VIEWERS)
    before = await _sign_count(store, p.user_id)
    p.directory.principal = replace(_PRINCIPAL, groups=frozenset(now_in))

    await _assert_refused_and_uncharged(p, DIRECTORY_ROLES_DEMOTED, before)
    assert set(await store.get_user_role_ids(p.user_id)) == {"operator", "viewer"}

    # The challenge is still in flight, so the SAME assertion verifies once the groups are back.
    p.directory.principal = replace(_PRINCIPAL, groups=frozenset({_OPERATORS, _VIEWERS}))
    served = await _finish(p)
    assert served.ok is True and served.token is not None


@pytest.mark.parametrize(
    "now_in", [(_VIEWERS,), (_OPERATORS, _VIEWERS)], ids=["unchanged", "promoted"]
)
async def test_a_directory_account_not_demoted_still_clears_the_gate(
    store: MessageStore, now_in: tuple[str, ...]
) -> None:
    """The control: an unchanged or a promoted account clears the gate with its passkey."""
    p = await _mapped_session(store, _VIEWERS)
    p.directory.principal = replace(_PRINCIPAL, groups=frozenset(now_in))

    verified = await _finish(p)

    assert verified.ok is True
    assert await p.service.mfa_satisfied(verified.token) is True


async def test_a_locked_directory_account_is_refused_as_locked_before_any_lookup(
    store: MessageStore,
) -> None:
    """The lock is the cheap local check, so it runs first and costs no directory round trip."""
    p = await _directory_session_owing_a_passkey(store)
    await store.increment_login_failure(
        p.user_id,
        counter="second_step",
        threshold=1,
        lockout_seconds=900.0,
        max_lockout_seconds=86_400.0,
    )
    p.directory.answer = DirectoryAnswer.DISABLED

    refused = await _finish(p)

    assert refused.ok is False
    assert refused.directory_unconfirmed is False
    assert p.directory.probes == []


async def _lock_second_step(store: MessageStore, user_id: str) -> None:
    await store.increment_login_failure(
        user_id,
        counter="second_step",
        threshold=1,
        lockout_seconds=900.0,
        max_lockout_seconds=86_400.0,
    )


@pytest.mark.parametrize("change", ["lock", "revoke", "disable"])
async def test_what_lands_during_the_lookup_is_honoured(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """The lookup is a network round trip, so the session, the account and its lock are read again
    after it. RED when: a lock, a revocation or a disable that lands during the lookup does not stop
    the assertion, which would then mark the factor and clear both lockout counters."""
    p = await _directory_session_owing_a_passkey(store)
    before = await _sign_count(store, p.user_id)
    real_probe = p.service._probe_principal

    async def _probe_while_something_lands(user: UserRecord) -> reconcile.Probe:
        if change == "lock":
            await _lock_second_step(store, p.user_id)
        elif change == "revoke":
            await store.revoke_session(hash_token(p.token))
        else:
            await store.set_user_disabled(p.user_id, disabled=True)
        return await real_probe(user)

    monkeypatch.setattr(p.service, "_probe_principal", _probe_while_something_lands)

    refused = await _finish(p)

    assert refused.ok is False and refused.directory_unconfirmed is False
    # A lock leaves the token authenticating; a revocation or a disable does not.
    assert refused.session_lost is (change != "lock")
    session = await store.get_session(hash_token(p.token))
    assert session is not None and session.mfa_verified_at is None
    assert await _sign_count(store, p.user_id) == before
    if change == "lock":
        user = await store.get_user(p.user_id)
        assert user is not None and user.second_step_locked_until is not None
        # BACKLOG #3068, item 3: the re-check's refusal writes its own audit row. The lock landed
        # after the first check, so only the re-check can have written it.
        assert {"reason": "locked"} in await _audited_assertion_failures(store)


async def test_a_local_account_is_never_probed(store: MessageStore) -> None:
    """A local account's passkey leg is unchanged, and it costs no directory round trip."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    identity, token, password = await login_admin(service)
    key = SoftAuthenticator(rp_id=_RP, origin=_ORIGIN)
    await _register_passkey(service, identity, token, key)
    out = await service.login(ADMIN_USERNAME, password)
    assert out.ok and out.mfa_required and out.token is not None
    response = await _staged_assertion(service, out.token, key)

    verified = await service.finish_webauthn_assertion(
        out.token, response, rp_id=_RP, origin=_ORIGIN
    )

    assert verified.ok is True
    assert directory.probes == []


# --- BACKLOG #3068: the follow-ups from engine PR 2055's review ------------------------------------


async def _directory_session_with_no_passkey(store: MessageStore) -> _Pending:
    """A directory account that holds no passkey, signed in, so nothing can be staged for it."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    out = await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
    assert out.token is not None and out.identity is not None
    assert await service.begin_webauthn_assertion(out.token, rp_id=_RP) is None  # nothing staged
    key = SoftAuthenticator(rp_id=_RP, origin=_ORIGIN)
    return _Pending(service, store, directory, out.token, out.identity.user_id, "{}", key)


@pytest.mark.parametrize("caller", ["nothing-staged", "no-passkey"])
async def test_a_post_with_nothing_staged_costs_no_directory_lookup(
    store: MessageStore, caller: str
) -> None:
    """Item 1. A directory session with no ceremony staged has proved nothing, so its post must not
    reach the directory or learn its answer: it gets the plain ``expired`` refusal the pop gives.
    RED when: the lookup runs before the staged ceremony is checked (the directory, set to refuse,
    is then probed and the answer reads ``directory_unconfirmed``)."""
    if caller == "nothing-staged":
        p = await _directory_session_owing_a_passkey(store)
        assert p.service._webauthn_challenges.pop((hash_token(p.token), "assert")) is not None
    else:
        p = await _directory_session_with_no_passkey(store)
    p.directory.answer = DirectoryAnswer.DISABLED

    refused = await _finish(p)

    assert refused == Elevation()  # the plain failure, nothing about the directory
    assert p.directory.probes == []
    failures = await _audited_assertion_failures(store)
    assert {"reason": "expired"} in failures
    assert not any(d.get("reason") == DIRECTORY_UNCONFIRMED for d in failures)


async def test_a_staged_ceremony_is_peeked_not_taken_before_the_lookup(
    store: MessageStore,
) -> None:
    """Item 1, the other half. RED when: the check before the lookup pops the staged ceremony, so
    the assertion it refused cannot verify once the directory answers."""
    p = await _directory_session_owing_a_passkey(store)
    p.directory.answer = DirectoryAnswer.DISABLED
    assert (await _finish(p)).directory_unconfirmed is True
    assert p.service._webauthn_challenges.peek((hash_token(p.token), "assert")) is not None

    p.directory.answer = DirectoryAnswer.FOUND
    assert (await _finish(p)).ok is True


async def test_an_oidc_minted_session_is_checked_too(store: MessageStore) -> None:
    """Item 3. The check keys on the ACCOUNT's provider, not on how the session was minted, so a
    session the federated sign-in minted is asked as a Kerberos one is. RED when: the check is
    skipped for an ``oidc`` session."""
    p = await _directory_session_owing_a_passkey(store)
    oidc = await p.service._issue_session(
        p.user_id,
        None,
        mfa_verified=False,
        seed_reauth=False,
        mechanism=SessionMechanism.OIDC,
        idp_auth_time=time.time(),
    )
    response = await _staged_assertion(p.service, oidc, p.key)
    p.directory.answer = DirectoryAnswer.DISABLED

    refused = await p.service.finish_webauthn_assertion(oidc, response, rp_id=_RP, origin=_ORIGIN)

    assert refused.directory_unconfirmed is True
    assert p.directory.probes == [("kpark", _PRINCIPAL.directory_object_id)]
    session = await store.get_session(hash_token(oidc))
    assert session is not None and session.mfa_verified_at is None


async def test_the_lookup_comes_after_the_too_early_floor(store: MessageStore) -> None:
    """Item 3. The login-then-MFA floor (BACKLOG #2301) is a local check, so a passkey that arrives
    too soon is refused before the directory is asked. RED when: the lookup moves ahead of it."""
    p = await _directory_session_owing_a_passkey(store)
    p.service._settings = p.service._settings.model_copy(
        update={"mfa_verify_min_elapsed_seconds": 3600}
    )
    p.directory.answer = DirectoryAnswer.DISABLED

    refused = await _finish(p)

    assert refused == Elevation()
    assert p.directory.probes == []


@pytest.mark.parametrize("change", ["lock", "revoke", "disable", "passkey-deleted"])
@pytest.mark.parametrize("account", ["directory", "local"])
async def test_what_lands_before_the_factor_write_is_honoured(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, change: str, account: str
) -> None:
    """Item 2. The passkey read and the sign-count write await after the session, the account and
    its lock were last read. RED when: a lock, a revocation, a disable or a delete of the passkey
    that signed lands there and does not stop the factor write, which would then mark the factor
    and clear both lockout counters, or when the refusal of a spent proof writes no audit row."""
    if account == "directory":
        p = await _directory_session_owing_a_passkey(store)
        service, token, response, user_id = p.service, p.token, p.response, p.user_id
    else:
        service = AuthService(store, _settings())
        identity, first, password = await login_admin(service)
        key = SoftAuthenticator(rp_id=_RP, origin=_ORIGIN)
        await _register_passkey(service, identity, first, key)
        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.token is not None
        token, user_id = out.token, identity.user_id
        response = await _staged_assertion(service, token, key)
    real_update = store.update_webauthn_sign_count

    async def _update_while_something_lands(*args: Any, **kwargs: Any) -> bool:
        if change == "lock":
            await _lock_second_step(store, user_id)
        elif change == "revoke":
            await store.revoke_session(hash_token(token))
        elif change == "disable":
            await store.set_user_disabled(user_id, disabled=True)
        else:
            # After the write: a delete before it already fails the sign-count compare-and-set.
            moved = await real_update(*args, **kwargs)
            (held,) = await store.list_webauthn_credentials(user_id)
            assert await store.delete_webauthn_credential(user_id, held.credential_id_hash)
            return moved
        return await real_update(*args, **kwargs)

    monkeypatch.setattr(store, "update_webauthn_sign_count", _update_while_something_lands)

    refused = await service.finish_webauthn_assertion(token, response, rp_id=_RP, origin=_ORIGIN)

    assert refused.ok is False
    assert refused.session_lost is (change in ("revoke", "disable"))
    session = await store.get_session(hash_token(token))
    assert session is not None and session.mfa_verified_at is None
    reason = {"lock": "locked", "passkey-deleted": "factor_removed"}.get(change, "session_lost")
    assert {"reason": reason} in await _audited_assertion_failures(store)
    if change == "lock":
        user = await store.get_user(user_id)
        assert user is not None and user.second_step_locked_until is not None  # not cleared
