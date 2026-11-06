# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0207: a directory account's first engine factor is bound only with a single-use enrolment
code an Administrator issued. The acceptance criteria AC-1 to AC-19 are named on each test.

Synthetic accounts and codes only. The store contract is shared with the Postgres and SQL Server
suites (``tests/_enrolment_code_store_contract.py``); this file runs it on SQLite, keyed and keyless.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import pytest
from _totp_clock import fresh_totp, pin_totp_clock

from messagefoundry.auth import totp
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import (
    ENROLMENT_CODE_ISSUED,
    ENROLMENT_CODE_SPENT,
    SecurityEvent,
)
from messagefoundry.auth.service import (
    ENROLMENT_CODE_LIFETIME_SECONDS,
    ENROLMENT_CODE_REFUSED,
    AuthService,
    EnrolmentCodeIssueRefused,
    EnrolmentCodeRefused,
)
from messagefoundry.auth.tokens import hash_token, mint_enrolment_code, normalise_enrolment_code
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    USER_SEAL_WHEN_SET,
    MessageStore,
    UserAuthzRecord,
    UserRecord,
    UserRow,
)
from tests._fake_directory import DirectoryOf

_T0 = 1_700_000_000.0


def _row(**overrides: object) -> UserRow:
    base: dict[str, object] = {}
    for f in fields(UserRow):
        text = str(f.type)
        if f.name in USER_SEAL_WHEN_SET:
            base[f.name] = None
        elif "bool" in text:
            base[f.name] = False
        elif "int" in text:
            base[f.name] = 0
        elif "float" in text:
            base[f.name] = 0.0
        else:
            base[f.name] = "x"
    base.update(overrides)
    return UserRow(**base)  # type: ignore[arg-type]


async def test_the_store_contract_holds_on_a_keyless_sqlite_store(tmp_path: Path) -> None:
    """AC-8, AC-9, AC-10, AC-15, AC-19 at the store: issue, revoke, spend, the TOTP fold and the
    disable's clear, each conditional, and two spends of one code where exactly one wins."""
    from tests._enrolment_code_store_contract import assert_enrolment_code_store_contract

    store = await MessageStore.open(tmp_path / "codes.db")
    try:
        await assert_enrolment_code_store_contract(store)
    finally:
        await store.close()


async def test_the_store_contract_holds_on_a_keyed_sqlite_store(tmp_path: Path) -> None:
    from tests._enrolment_code_store_contract import assert_enrolment_code_store_contract

    store = await MessageStore.open(
        tmp_path / "sealed.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    try:
        await assert_enrolment_code_store_contract(store)
    finally:
        await store.close()


def test_a_null_code_column_leaves_the_seal_as_it_was() -> None:
    """Amendment A: an account that never held a code keeps the seal it was sealed under, because
    a NULL code column is left out of the sealed fields."""
    names = [n for n, _ in UserAuthzRecord(row=_row()).seal_fields()]
    assert not USER_SEAL_WHEN_SET & set(names)


def test_a_non_null_value_of_each_code_column_changes_the_seal() -> None:
    """Amendment A's pin: each code column, once set, enters the sealed fields, so a value planted
    outside the store fails the seal."""
    plain = UserAuthzRecord(row=_row()).seal_fields()
    for column, value in (
        ("enrolment_code_digest", "0" * 64),
        ("enrolment_code_expires_at", 1.0),
        ("enrolment_code_issuer", "admin"),
    ):
        changed = UserAuthzRecord(row=_row(**{column: value})).seal_fields()
        assert changed != plain, column
        assert (column, value) in changed, column


# --- the service: issue, the binding steps, the reset (layer 2) ------------------------------------

_PRINCIPAL = AdPrincipal(
    username="mlane",
    display_name="M Lane",
    email="mlane@test.invalid",
    dn="CN=mlane,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="9c1e2d3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f",
)
_OTHER = AdPrincipal(
    username="rkent",
    display_name="R Kent",
    email="rkent@test.invalid",
    dn="CN=rkent,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
)
_RP, _ORIGIN = "t", "http://t"


class _Notices:
    def __init__(self) -> None:
        self.sent: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> bool:
        self.sent.append(event)
        return True


def _settings(**overrides: object) -> AuthSettings:
    values: dict[str, object] = {
        "mfa_verify_min_elapsed_seconds": 0,
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
    }
    values.update(overrides)
    return AuthSettings(**values)  # type: ignore[arg-type]


@dataclass
class _World:
    service: AuthService
    store: MessageStore
    notices: _Notices
    issuer_id: str


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


async def _world(store: MessageStore, **overrides: object) -> _World:
    notices = _Notices()
    service = AuthService(
        store,
        _settings(**overrides),
        ldap=DirectoryOf(_PRINCIPAL, _OTHER),  # type: ignore[arg-type]
        security_notifier=notices,
    )
    await service.initialize()
    await store.create_user(
        user_id="issuer-admin",
        username="issuer-admin",
        auth_provider="local",
        password_hash="not-a-real-hash",
        password_generated=False,
        notify_email="issuer@test.invalid",
        audits=(),
    )
    return _World(service, store, notices, "issuer-admin")


async def _session(
    w: _World, principal: AdPrincipal = _PRINCIPAL, *, verified: bool = False
) -> Any:
    """A directory session minted through ``_complete_ad_login``, the tail Kerberos and OIDC share.
    ``verified=False`` is a Kerberos sign-in, or a federated one with the claim gate off;
    ``verified=True`` is a federated one whose identity provider asserted MFA."""
    out = await w.service._complete_ad_login(principal, None, mfa_verified=verified)
    assert out.token is not None and out.identity is not None
    return out


async def _issue(w: _World, user_id: str) -> str:
    issued = await w.service.issue_enrolment_code(
        user_id, actor="issuer-admin", issuer_id=w.issuer_id, via="api"
    )
    return issued.code


async def _actions(store: MessageStore, action: str) -> list[dict[str, Any]]:
    rows = await store.list_audit(action=action)
    return [json.loads(r["detail"]) if r["detail"] else {} for r in rows]


async def test_ac1_a_directory_password_alone_binds_no_totp(store: MessageStore) -> None:
    """AC-1, #2609's chain: a Kerberos session on an unbound account with no factor confirms a TOTP
    enrolment without a code, and is refused, with TOTP off and the session unstamped."""
    w = await _world(store)
    out = await _session(w)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    with pytest.raises(EnrolmentCodeRefused) as refused:
        await w.service.confirm_mfa_enrollment(
            out.identity, fresh_totp(enroll.secret), token=out.token, client="198.51.100.7"
        )
    assert str(refused.value) == ENROLMENT_CODE_REFUSED
    user = await store.get_user(out.identity.user_id)
    assert user is not None and not user.totp_enabled
    assert await w.service.mfa_satisfied(out.token) is False
    assert await _actions(store, "auth.enrolment_code_refused") == [
        {"reason": "not_presented", "ceremony": "totp"}
    ]


async def test_ac2_a_valid_code_enables_totp_and_is_spent(store: MessageStore) -> None:
    """AC-2, AC-18: the code enables TOTP, stamps the session, is spent, and writes the used row
    with no issuer, plus the spent notice under the issuer, in the issuer's own feed."""
    w = await _world(store)
    out = await _session(w)
    code = await _issue(w, out.identity.user_id)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    confirmed = await w.service.confirm_mfa_enrollment(
        out.identity,
        fresh_totp(enroll.secret),
        token=out.token,
        client="198.51.100.7",
        enrolment_code=code.lower().replace("-", " "),  # normalised for case, spaces, hyphens
    )
    assert confirmed.ok and confirmed.token is not None
    user = await store.get_user(out.identity.user_id)
    assert user is not None and user.totp_enabled
    assert user.enrolment_code_digest is None and user.enrolment_code_issuer is None
    assert await w.service.mfa_satisfied(confirmed.token) is True
    assert await _actions(store, "auth.enrolment_code_used") == [{"ceremony": "totp"}]
    feed = await w.service.security_events_for("issuer-admin")
    notice = [e for e in feed if e["action"] == "auth.enrolment_code_spent_notice"]
    assert len(notice) == 1
    detail = json.loads(str(notice[0]["detail"]))
    assert detail["actor_role"] == "recipient"
    assert detail["username"] == "mlane" and detail["ceremony"] == "totp"
    assert detail["client"] == "198.51.100.7"
    spent = [e for e in w.notices.sent if e.event_type == ENROLMENT_CODE_SPENT]
    assert len(spent) == 1 and spent[0].email == "issuer@test.invalid"
    assert spent[0].detail == {"holder": "mlane"}
    assert code not in json.dumps([dict(r) for r in await store.list_audit()], default=str)


@pytest.mark.parametrize("case", ["wrong", "expired", "spent", "other_account", "malformed"])
async def test_ac3_every_refused_code_gets_one_reply_and_costs_no_step(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """AC-3, AC-19: a wrong, expired, spent, another account's or malformed code is refused at the
    code read with the one reply and one ``code_refused`` reason, before the TOTP step is consumed:
    the same TOTP code then confirms with the right enrolment code."""
    w = await _world(store)
    out = await _session(w)
    user_id = out.identity.user_id
    code = await _issue(w, user_id)
    if case == "wrong":
        shown = mint_enrolment_code()
    elif case == "malformed":
        shown = "not-a-code"
    elif case == "other_account":
        other = await _session(w, _OTHER)
        shown = await _issue(w, other.identity.user_id)
    elif case == "expired":
        shown = code
        user = await store.get_user(user_id)
        assert user is not None and user.enrolment_code_digest is not None
        await store.issue_enrolment_code(
            user_id, code_digest=user.enrolment_code_digest, expires_at=1.0, issuer_id=None
        )
    else:
        shown = code
        spender = await w.service.issue_enrolment_code(
            user_id, actor="issuer-admin", issuer_id=None, via="api"
        )
        assert spender.replaced
    pin_totp_clock(monkeypatch, _T0)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    activating = totp.totp(enroll.secret, now=_T0)
    with pytest.raises(EnrolmentCodeRefused) as refused:
        await w.service.confirm_mfa_enrollment(
            out.identity, activating, token=out.token, enrolment_code=shown
        )
    assert str(refused.value) == ENROLMENT_CODE_REFUSED
    assert await _actions(store, "auth.enrolment_code_refused") == [
        {"reason": "code_refused", "ceremony": "totp"}
    ]
    if case in ("wrong", "malformed", "other_account"):
        # Control: the step was not consumed, so the same TOTP code confirms with the right code.
        confirmed = await w.service.confirm_mfa_enrollment(
            out.identity, activating, token=out.token, enrolment_code=code
        )
        assert confirmed.ok


async def test_ac6_a_federated_session_the_idp_stamped_needs_no_code(store: MessageStore) -> None:
    """AC-6: with the claim gate on the federated session is stamped and needs no code; with it
    off the session is unstamped and does (the same rule AC-1 pins)."""
    w = await _world(store)
    stamped = await _session(w, verified=True)
    await _issue(w, stamped.identity.user_id)  # outstanding, and not needed by this session
    enroll = await w.service.begin_mfa_enrollment(stamped.identity)
    confirmed = await w.service.confirm_mfa_enrollment(
        stamped.identity, fresh_totp(enroll.secret), token=stamped.token
    )
    assert confirmed.ok
    assert await _actions(store, "auth.enrolment_code_refused") == []
    assert not await w.service.enrolment_code_required(stamped.token, stamped.identity)
    # A factor bound without the code clears it, so it cannot bind a first factor later.
    bound = await store.get_user(stamped.identity.user_id)
    assert bound is not None and bound.enrolment_code_digest is None
    unstamped = await _session(w, _OTHER, verified=False)
    assert await w.service.enrolment_code_required(unstamped.token, unstamped.identity)


@pytest.mark.parametrize("require_mfa", [True, False])
@pytest.mark.parametrize("kerberos_enabled", [True, False])
async def test_ac7_the_code_is_required_in_every_posture(
    store: MessageStore, require_mfa: bool, kerberos_enabled: bool
) -> None:
    """AC-7: the rule reads the account and the session, never ``require_mfa`` or Kerberos."""
    kerberos: dict[str, object] = (
        {"kerberos_enabled": True, "kerberos_realm": "TEST.INVALID"} if kerberos_enabled else {}
    )
    w = await _world(store, require_mfa=require_mfa, **kerberos)
    out = await _session(w)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    with pytest.raises(EnrolmentCodeRefused):
        await w.service.confirm_mfa_enrollment(
            out.identity, fresh_totp(enroll.secret), token=out.token
        )


async def test_a_local_account_needs_no_code(store: MessageStore) -> None:
    """What it must not break: a local account's enrolment asks no code."""
    w = await _world(store)
    assert not await w.service._enrolment_code_owed("anything", _local_user())


def _local_user() -> UserRecord:
    return UserRecord(
        id="l",
        username="l",
        auth_provider="local",
        display_name=None,
        email=None,
        disabled=False,
        created_at=0.0,
        updated_at=0.0,
        last_login_at=None,
        password_hash="h",
        password_changed_at=None,
        must_change_password=False,
        failed_attempts=0,
        locked_until=None,
    )


async def test_ac8_an_issue_stores_only_the_digest_and_notifies_without_the_code(
    store: MessageStore,
) -> None:
    """AC-8 at the service: the code is returned once, the store holds only its digest, and the
    target's address gets a notice that names no code."""
    w = await _world(store)
    out = await _session(w)
    user_id = out.identity.user_id
    await store.set_user_notify_email(user_id, email="mlane@test.invalid")
    issued = await w.service.issue_enrolment_code(
        user_id, actor="issuer-admin", issuer_id=w.issuer_id, via="api"
    )
    normal = normalise_enrolment_code(issued.code)
    assert normal is not None and len(normal) * 5 >= 128
    user = await store.get_user(user_id)
    assert user is not None
    assert user.enrolment_code_digest == hash_token(normal)
    assert user.enrolment_code_expires_at == pytest.approx(issued.expires_at)
    assert issued.expires_at - time.time() == pytest.approx(ENROLMENT_CODE_LIFETIME_SECONDS, abs=60)
    sent = [e for e in w.notices.sent if e.event_type == ENROLMENT_CODE_ISSUED]
    assert len(sent) == 1 and sent[0].email == "mlane@test.invalid"
    assert issued.code not in repr(sent[0]) and normal not in repr(sent[0])
    row = (await _actions(store, "auth.enrolment_code_issued"))[0]
    assert row["via"] == "api" and row["replaced"] is False and row["bound"] is False
    assert issued.code not in json.dumps(row) and hash_token(normal) not in json.dumps(row)


async def test_ac8_an_issue_is_refused_for_each_account_it_must_not_reach(
    store: MessageStore,
) -> None:
    """AC-8's refusals at the service: a local account, an account with a factor, a disabled
    account and an unknown one. Self-targeting is the route's (the API tests pin it)."""
    w = await _world(store)
    with pytest.raises(EnrolmentCodeIssueRefused) as local:
        await w.service.issue_enrolment_code("issuer-admin", actor="x", issuer_id=None, via="api")
    assert local.value.reason == "local_account"
    with pytest.raises(ValueError, match="no such user"):
        await w.service.issue_enrolment_code("nobody", actor="x", issuer_id=None, via="api")
    out = await _session(w)
    code = await _issue(w, out.identity.user_id)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    assert (
        await w.service.confirm_mfa_enrollment(
            out.identity, fresh_totp(enroll.secret), token=out.token, enrolment_code=code
        )
    ).ok
    with pytest.raises(EnrolmentCodeIssueRefused) as factor:
        await w.service.issue_enrolment_code(
            out.identity.user_id, actor="x", issuer_id=None, via="api"
        )
    assert factor.value.reason == "factor_present"
    other = await _session(w, _OTHER)
    await store.set_user_disabled(other.identity.user_id, disabled=True)
    with pytest.raises(EnrolmentCodeIssueRefused) as disabled:
        await w.service.issue_enrolment_code(
            other.identity.user_id, actor="x", issuer_id=None, via="api"
        )
    assert disabled.value.reason == "disabled"


async def test_ac9_a_revoke_clears_the_code_and_is_audited(store: MessageStore) -> None:
    w = await _world(store)
    out = await _session(w)
    code = await _issue(w, out.identity.user_id)
    assert await w.service.revoke_enrolment_code(out.identity.user_id, actor="issuer-admin")
    assert not await w.service.revoke_enrolment_code(out.identity.user_id, actor="issuer-admin")
    assert len(await _actions(store, "auth.enrolment_code_revoked")) == 1
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    with pytest.raises(EnrolmentCodeRefused):
        await w.service.confirm_mfa_enrollment(
            out.identity, fresh_totp(enroll.secret), token=out.token, enrolment_code=code
        )


async def test_ac12_a_reset_of_an_enabled_directory_account_issues_a_code(
    store: MessageStore,
) -> None:
    """AC-12: the reset returns a code once for an enabled directory account, and none for a
    disabled one. The code it returns enrols the account's next factor."""
    w = await _world(store)
    out = await _session(w)
    reset = await w.service.admin_reset_mfa(
        out.identity.user_id, actor="issuer-admin", actor_id=w.issuer_id
    )
    assert reset.credential is None and reset.enrolment_code is not None
    assert (await _actions(store, "auth.enrolment_code_issued"))[0]["via"] == "reset"
    again = await _session(w)
    enroll = await w.service.begin_mfa_enrollment(again.identity)
    assert (
        await w.service.confirm_mfa_enrollment(
            again.identity,
            fresh_totp(enroll.secret),
            token=again.token,
            enrolment_code=reset.enrolment_code.code,
        )
    ).ok
    other = await _session(w, _OTHER)
    await store.set_user_disabled(other.identity.user_id, disabled=True)
    disabled = await w.service.admin_reset_mfa(other.identity.user_id, actor="issuer-admin")
    assert disabled.enrolment_code is None


async def test_ac13_a_fold_that_matches_no_row_ends_the_session_and_spends_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-13's directory half and AC-19: a begin from another session replaces the staged secret
    after the confirm verified its code, so the folded enable matches no row. The rotated session
    is ended, no token is returned, TOTP stays off, and the code is not spent."""
    w = await _world(store)
    out = await _session(w)
    user_id = out.identity.user_id
    code = await _issue(w, user_id)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    real = store.enable_totp_spending_enrolment_code

    async def restaged(*args: Any, **kwargs: Any) -> Any:
        await store.set_totp_secret(user_id, secret="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
        return await real(*args, **kwargs)

    monkeypatch.setattr(store, "enable_totp_spending_enrolment_code", restaged)
    lost = await w.service.confirm_mfa_enrollment(
        out.identity, fresh_totp(enroll.secret), token=out.token, enrolment_code=code
    )
    assert lost.session_lost and lost.token is None
    user = await store.get_user(user_id)
    assert user is not None and not user.totp_enabled
    assert user.enrolment_code_digest is not None  # the code was not spent
    assert await _actions(store, "auth.enrolment_code_used") == []
    assert await _actions(store, "auth.enrolment_code_refused") == []


async def test_ac15_a_disable_between_the_checks_and_the_write_leaves_no_code(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-15: a disable that lands after the issue's checks makes its write change no row, so the
    issue is refused and no code is shown. A disable also clears a code, and a re-enable revives
    none."""
    w = await _world(store)
    out = await _session(w)
    user_id = out.identity.user_id
    old = await _issue(w, user_id)
    await store.set_user_disabled(user_id, disabled=True)
    await store.set_user_disabled(user_id, disabled=False)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    with pytest.raises(EnrolmentCodeRefused):  # the re-enable revived nothing
        await w.service.confirm_mfa_enrollment(
            out.identity, fresh_totp(enroll.secret), token=out.token, enrolment_code=old
        )
    real = store.issue_enrolment_code

    async def disabled_first(*args: Any, **kwargs: Any) -> Any:
        await store.set_user_disabled(user_id, disabled=True)
        return await real(*args, **kwargs)

    monkeypatch.setattr(store, "issue_enrolment_code", disabled_first)
    with pytest.raises(EnrolmentCodeIssueRefused) as refused:
        await w.service.issue_enrolment_code(user_id, actor="x", issuer_id=None, via="api")
    assert refused.value.reason == "disabled"
    user = await store.get_user(user_id)
    assert user is not None and user.enrolment_code_digest is None


async def test_ac19_a_directory_refusal_reads_no_code(store: MessageStore) -> None:
    """AC-19: the code is read after the directory lookup, so a directory refusal writes no code
    refusal and says nothing about a code."""
    w = await _world(store)
    out = await _session(w)
    enroll = await w.service.begin_mfa_enrollment(out.identity)
    w.service._ldap.principals.pop("mlane")  # type: ignore[union-attr]
    refused = await w.service.confirm_mfa_enrollment(
        out.identity, fresh_totp(enroll.secret), token=out.token
    )
    assert not refused.ok
    assert refused.directory_refusal is not None or refused.session_lost
    assert await _actions(store, "auth.enrolment_code_refused") == []


def test_a_code_is_at_least_128_bits_and_normalises() -> None:
    """Section 3: at least 128 bits from ``secrets``, grouped base32, normalised for case, spaces
    and hyphens; anything else normalises to nothing."""
    code = mint_enrolment_code()
    groups = code.split("-")
    assert all(len(g) == 4 for g in groups) and len("".join(groups)) * 5 >= 128
    assert normalise_enrolment_code(code.lower().replace("-", " ")) == "".join(groups)
    assert normalise_enrolment_code("short") is None
    assert normalise_enrolment_code("1" * 32) is None  # 1 is not in the base32 alphabet
    assert mint_enrolment_code() != code
