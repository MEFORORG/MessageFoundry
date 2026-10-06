# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1639 and ADR 0195: an unreadable ``userAccountControl``, on login and in the reconciler.

Login refuses it (#1639). The reconciler revokes a single one beside readable answers (#1639), and
holds a wave of them without revoking (ADR 0195, BACKLOG #2039).

The disabled-bit check used to run only when the attribute was present and numeric, so a bind
account that could not read it saw every principal as enabled. These tests drive the REAL
``LdapAuthenticator`` against ``ldap3`` doubles, and for the reconciler the real ``AuthService``
over an in-memory store, so the refusal is asserted where each caller reads it rather than only at
the helper.

**What is not exercised here:** a real domain controller. No test can show what a directory returns
to a bind account with restricted read rights; the doubles model the two shapes the fix names.
Synthetic data only; nothing here touches PHI.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import uuid
from collections.abc import AsyncIterator, Iterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from messagefoundry.api.app import (
    _alert_reconcile_plan,
    _directory_reconciler,
    _is_sole_reconciler,
    _without_clears,
)
from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import DirectoryAnswer, LdapAuthenticator, _account_enabled
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.reconcile import (
    HOLD_REASON,
    REFERRAL_ABORT,
    ProbeOutcome,
    ReconcilePlan,
    SessionRevocation,
)
from messagefoundry.auth.service import AuthService, _HoldStanding
from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AuthSettings
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStore, UserRecord
from tests.test_alert_sinks import _drain, _RecordingTransport
from tests.test_approval_requester_recheck import _Sink

#: "The entry carries no userAccountControl at all", which is a different fact from any value the
#: attribute could hold -- including an empty one.
ABSENT = object()

ENABLED = "512"  # NORMAL_ACCOUNT
DISABLED = "514"  # NORMAL_ACCOUNT | ACCOUNTDISABLE (0x2)
NON_NUMERIC = "NORMAL_ACCOUNT"

#: The refusals, each with the shape its warning must report (``None`` for the disabled bit, which
#: is a readable answer and warns about nothing). ``None`` as a VALUE is what ldap3 returns for an
#: attribute it was asked for and did not receive, under its return_empty_attributes option.
REFUSED = [
    pytest.param(ABSENT, "absent", id="absent"),
    pytest.param(None, "empty", id="empty"),
    pytest.param(NON_NUMERIC, "non-numeric str", id="non-numeric"),
    pytest.param(DISABLED, None, id="disabled-bit"),
]


@pytest.fixture(autouse=True)
def _reset_the_warning_latch() -> Iterator[None]:
    """The latch is process-wide, so it is emptied before each test, or a test's own warning would
    depend on which tests ran first, and after, so this module leaves nothing behind for another."""
    ldap_module._uac_shapes_warned.clear()
    yield
    ldap_module._uac_shapes_warned.clear()


# --- the one place the attribute is interpreted -------------------------------------------------


class _Attr:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else [value]


class _Entry:
    def __init__(self, dn: str, attrs: dict[str, Any]) -> None:
        self.entry_dn = dn
        self._attrs = attrs

    def __contains__(self, name: str) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> _Attr:
        return _Attr(self._attrs[name])


def _uac_entry(uac: Any) -> _Entry:
    return _Entry("CN=x,DC=x", {} if uac is ABSENT else {"userAccountControl": uac})


@pytest.mark.parametrize(
    ("value", "enabled", "shape"),
    [
        (ENABLED, True, None),
        (512, True, None),  # ldap3 with a schema loaded formats the INTEGER syntax as an int
        (b"512", True, None),
        (" 512 ", True, None),
        (DISABLED, False, None),
        (514, False, None),
        (ABSENT, False, "absent"),
        (None, False, "empty"),
        ("", False, "empty"),
        ("   ", False, "empty"),
        ([], False, "empty"),
        (NON_NUMERIC, False, "non-numeric str"),
        ("5l2", False, "non-numeric str"),
        (chr(0xB2), False, "non-numeric str"),  # superscript 2: isdigit() yes, int() no
        (True, False, "non-numeric bool"),  # a bool is an int subclass, and is not a flag word
        (["512", "514"], False, "non-numeric list"),  # a single-valued attribute answering twice
    ],
)
def test_only_a_readable_flag_word_with_the_disabled_bit_clear_is_enabled(
    value: Any, enabled: bool, shape: str | None
) -> None:
    assert _account_enabled(_uac_entry(value)) is enabled
    assert ldap_module._uac_shapes_warned == (set() if shape is None else {shape})


def test_each_unusable_shape_is_reported_once_and_names_the_consequence(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Once per shape, like the ``objectGUID`` reader: the reconciler reads every signed-in user
    every pass, so a per-read warning would print one identical line per user every interval."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        for _ in range(5):
            assert not _account_enabled(_uac_entry(ABSENT))
            assert not _account_enabled(_uac_entry("secret-looking-value"))
        # A readable answer is not a shape to report, disabled or not.
        assert not _account_enabled(_uac_entry(DISABLED))
        assert _account_enabled(_uac_entry(ENABLED))
    records = [r for r in caplog.records if r.name == "messagefoundry.auth.ldap"]
    assert [r.args[1] for r in records] == ["absent", "non-numeric str"]  # type: ignore[index]
    for record in records:
        message = record.getMessage()
        assert "userAccountControl" in message
        assert "logins are refused" in message
        assert "secret-looking-value" not in message  # the value itself is never logged


# --- ldap3 doubles: one directory, answering both the name-keyed and the id-keyed search ---------


class _Directory:
    """Accounts by ``sAMAccountName``. ``uac`` is what each entry returns for ``userAccountControl``,
    and is the one thing a test changes."""

    def __init__(self, names: list[str]) -> None:
        self.ids = {n: str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{n}.test.invalid")) for n in names}
        self.uac: dict[str, Any] = dict.fromkeys(names, ENABLED)
        #: Every search raises, as an unreachable domain controller does.
        self.down = False
        #: Every search is answered with a referral (resultCode 10), as a search base in another
        #: domain of the forest is (BACKLOG #2538).
        self.refer = False
        #: Only the nested-group search is answered with a referral, as a group search base in
        #: another domain is. The user search still answers, so only FOUND accounts are referred.
        self.refer_groups = False

    def delete(self, name: str) -> None:
        """The account leaves the directory: both the name-keyed and the id-keyed search miss."""
        del self.ids[name]

    def lookup(self, search_filter: str) -> list[_Entry]:
        if "objectGUID=" in search_filter:
            raw = bytes(int(h, 16) for h in re.findall(r"\\([0-9a-f]{2})", search_filter))
            wanted = str(uuid.UUID(bytes_le=raw))
            name = next((n for n, i in self.ids.items() if i == wanted), None)
        else:
            match = re.search(r"sAMAccountName=([^)]*)", search_filter)
            name = match.group(1) if match else None
        if name not in self.ids:
            return []
        attrs: dict[str, Any] = {
            "sAMAccountName": name,
            "objectGUID": "{" + self.ids[name].upper() + "}",
        }
        if self.uac[name] is not ABSENT:
            attrs["userAccountControl"] = self.uac[name]
        return [_Entry(f"CN={name},OU=Staff,DC=test,DC=invalid", attrs)]


def _install_directory(monkeypatch: pytest.MonkeyPatch, directory: _Directory) -> None:
    import ldap3

    class FakeServer:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    class FakeConnection:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.entries: list[_Entry] = []
            self.result: dict[str, Any] | None = None  # no referral

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def search(self, **kwargs: Any) -> bool:
            if directory.down:
                raise ldap3.core.exceptions.LDAPSocketOpenError("synthetic: DC unreachable")
            group_search = "member:" in str(kwargs["search_filter"])
            if directory.refer or (directory.refer_groups and group_search):
                self.entries = []
                self.result = {"result": 10, "referrals": ["ldap://dc1.other.test.invalid/"]}
                return False
            self.entries = directory.lookup(str(kwargs["search_filter"]))
            self.result = {"result": 0}
            return True

        def bind(self) -> bool:
            return True  # every password is right: the refusal under test is the lookup's

        def unbind(self) -> None:
            pass

    monkeypatch.setattr(ldap3, "Server", FakeServer)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)


def _settings(**over: Any) -> AuthSettings:
    base: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
        "ad_session_recheck_seconds": 60,
    }
    base.update(over)
    return AuthSettings(**base)


# --- login: the password path and the password-free (Kerberos) path ----------------------------


@pytest.mark.parametrize(("uac", "shape"), REFUSED)
def test_login_refuses_an_account_whose_disabled_bit_is_set_or_undetermined(
    monkeypatch: pytest.MonkeyPatch, uac: Any, shape: str | None
) -> None:
    directory = _Directory(["jdoe"])
    _install_directory(monkeypatch, directory)
    auth = LdapAuthenticator(_settings())
    # The control first, on the same doubles: an enabled account signs in on both paths, so the
    # refusals below are the attribute's doing and not the fixture's.
    assert auth.authenticate("jdoe", "synthetic-pw") is not None
    assert auth.resolve_principal("jdoe") is not None

    directory.uac["jdoe"] = uac
    assert auth.authenticate("jdoe", "synthetic-pw") is None
    assert auth.resolve_principal("jdoe") is None  # the Kerberos/SSO lookup
    assert auth.resolve_principal("jdoe", object_id=directory.ids["jdoe"]) is None  # id-keyed
    assert ldap_module._uac_shapes_warned == (set() if shape is None else {shape})


# --- the reconciler ------------------------------------------------------------------------------
#
# ADR 0195. An undetermined answer is its own probe outcome. A single one beside readable answers
# strikes and revokes, which is BACKLOG #1639's reconciler half. A wave of them is HELD: the
# undetermined accounts are not revoked, the rest of the estate is reconciled as usual, and the
# ad_reconcile_held alert stays latched until no signed-in account reads undetermined.

#: Each refusal, its warning shape, and the reason it is revoked with when it is not held.
REVOKED = [
    pytest.param(ABSENT, "absent", "directory_undetermined", id="absent"),
    pytest.param(None, "empty", "directory_undetermined", id="empty"),
    pytest.param(NON_NUMERIC, "non-numeric str", "directory_undetermined", id="non-numeric"),
    pytest.param(DISABLED, None, "directory_disabled", id="disabled-bit"),
]

#: The two unreadable shapes a lost read right most plausibly produces.
UNREADABLE = pytest.mark.parametrize("uac", [ABSENT, NON_NUMERIC], ids=["absent", "non-numeric"])


@asynccontextmanager
async def _signed_in_estate(
    monkeypatch: pytest.MonkeyPatch, names: list[str], **settings: Any
) -> AsyncIterator[tuple[_Directory, AuthService, MessageStore, dict[str, str]]]:
    """Every account in ``names`` enabled and holding one live AD session.

    Each session is minted through the shared tail of the surviving AD login paths, from a principal
    the REAL authenticator resolved, so every row carries the id the id-keyed probe will ask about.
    """
    directory = _Directory(names)
    _install_directory(monkeypatch, directory)
    auth = LdapAuthenticator(_settings(**settings))
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _settings(**settings), ldap=auth)
        await service.initialize()
        tokens: dict[str, str] = {}
        for name in names:
            principal = auth.resolve_principal(name)
            assert principal is not None
            login = await service._complete_ad_login(principal, None, mfa_verified=True)
            assert login.token is not None, f"{name}'s AD login issued no session token"
            tokens[name] = login.token
        yield directory, service, store, tokens
    finally:
        await store.close()


async def _pass(service: AuthService, sink: AlertSink | None = None) -> ReconcilePlan:
    """One reconciler pass, alerted exactly as the API lifespan task alerts it."""
    plan = await service.reconcile_directory_sessions()
    _alert_reconcile_plan(plan, service, sink or _Sink())
    return plan


async def _id(store: MessageStore, name: str) -> str:
    user = await store.get_user_by_username(name)
    assert user is not None
    return user.id


async def _expire(store: MessageStore, names: list[str]) -> None:
    """End these accounts' sessions, as the absolute cap would. The reconciler only probes accounts
    that still hold a live session, so this is how a held account leaves its candidate set."""
    for name in names:
        await store.revoke_user_sessions(await _id(store, name))


async def _audited(store: MessageStore, action: str) -> list[Any]:
    # Filtered by the store and unbounded in practice: a bare list_audit() returns only the newest
    # 50 rows, so an "== []" over it could pass without having looked.
    return list(await store.list_audit(action=action, limit=100_000))


async def _alive(service: AuthService, tokens: dict[str, str]) -> set[str]:
    return {n for n, t in tokens.items() if await service.identity_for_token(t) is not None}


# --- the directory layer reports WHY, without raising, and only to the reconciler (rule item 2) ---


@pytest.mark.parametrize(
    ("uac", "answer"),
    [
        (ENABLED, DirectoryAnswer.FOUND),
        (DISABLED, DirectoryAnswer.DISABLED),
        (ABSENT, DirectoryAnswer.UNDETERMINED),
        (None, DirectoryAnswer.UNDETERMINED),
        (NON_NUMERIC, DirectoryAnswer.UNDETERMINED),
    ],
    ids=["enabled", "disabled-bit", "absent", "empty", "non-numeric"],
)
def test_the_probe_names_the_refusal_on_both_keys(
    monkeypatch: pytest.MonkeyPatch, uac: Any, answer: DirectoryAnswer
) -> None:
    directory = _Directory(["jdoe"])
    _install_directory(monkeypatch, directory)
    auth = LdapAuthenticator(_settings())
    directory.uac["jdoe"] = uac
    for object_id in (None, directory.ids["jdoe"]):
        probe = auth.probe_principal("jdoe", object_id=object_id)
        assert probe.answer is answer
        assert (probe.principal is not None) is (answer is DirectoryAnswer.FOUND)
        # Every other caller keeps its None: resolve_principal is the same lookup, answer dropped.
        assert (auth.resolve_principal("jdoe", object_id=object_id) is None) is (
            answer is not DirectoryAnswer.FOUND
        )


def test_a_search_that_matches_nothing_and_an_unparseable_id_are_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule item 1: ABSENT keeps every other refusal, including the id-keyed probe whose stored id
    the filter builder cannot parse, so no search ran."""
    directory = _Directory(["jdoe"])
    _install_directory(monkeypatch, directory)
    auth = LdapAuthenticator(_settings())
    assert auth.probe_principal("nobody").answer is DirectoryAnswer.NOT_FOUND
    assert auth.probe_principal("jdoe", object_id="not-a-guid").answer is DirectoryAnswer.NOT_FOUND


# --- AC-3: one undetermined account among readable ones is still revoked (BACKLOG #1639) --------


@pytest.mark.parametrize(("uac", "shape", "reason"), REVOKED)
async def test_the_reconciler_revokes_an_account_whose_disabled_bit_is_set_or_undetermined(
    monkeypatch: pytest.MonkeyPatch, uac: Any, shape: str | None, reason: str
) -> None:
    """AC-3. One undetermined account among enabled ones strikes, and is revoked at the strike
    threshold, exactly as a disabled one is. Before #1639 it read PRESENT and kept its session to
    the absolute cap. Its reason says which refusal it was (ADR 0195, decided by the build)."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith", "bwong"]) as estate:
        directory, service, _store, tokens = estate
        directory.uac["jdoe"] = uac
        first = await _pass(service)
        assert first.revocations == ()  # strike 1: one ambiguous answer never revokes
        assert not first.hold
        assert sorted(first.strikes.values()) == [0, 0, 1]  # only the refused account struck
        second = await _pass(service)
        assert second.aborted is None and not second.hold
        assert [(r.username, r.reason) for r in second.revocations] == [("jdoe", reason)]
        assert await _alive(service, tokens) == {"asmith", "bwong"}
        assert service.directory_reconcile_hold is None
        assert ldap_module._uac_shapes_warned == (set() if shape is None else {shape})


# --- AC-1 and AC-5: a whole small estate, and its controls ---------------------------------------


@UNREADABLE
async def test_a_whole_estate_wave_of_three_is_held_not_revoked(
    monkeypatch: pytest.MonkeyPatch, uac: Any
) -> None:
    """AC-1, replacing the test that pinned the opposite. At three signed-in principals the
    mass-revoke breaker's floor lets every revocation through, so before ADR 0195 pass 2 signed the
    whole estate out. Now nothing is revoked and the held alert is raised from the first pass."""
    names = ["jdoe", "asmith", "bwong"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac = dict.fromkeys(names, uac)
        for n in range(4):
            sink = _Sink()
            plan = await _pass(service, sink)
            assert plan.aborted is None and plan.revocations == ()
            assert plan.hold and sorted(plan.held) == sorted(plan.strikes)
            assert set(plan.strikes.values()) == {0}  # held: no strike accrues
            assert [(e[0], e[1]) for e in sink.events] == [
                ("ad_reconcile_held", "directory-reconciler")
            ], f"pass {n + 1}"
            fields = sink.events[0][2]
            assert fields["reason"] == HOLD_REASON and fields["undetermined"] == 3
            assert fields["detail"] == service.directory_reconcile_hold
        assert await _alive(service, tokens) == set(names)
        hold = service.directory_reconcile_hold
        assert hold is not None and "userAccountControl" in hold and "ad_bind_dn" in hold
        assert service.directory_reconcile_alert is None  # a hold is not a breaker trip
        assert await _audited(store, "auth.ad_session_revoked") == []
        rows = await _audited(store, "auth.ad_reconcile_held")
        assert len(rows) == 4
        detail = json.loads(rows[0]["detail"])
        assert detail["reason"] == HOLD_REASON and detail["undetermined"] == 3
        assert "ceiling" not in detail  # the breaker's ceiling means nothing for a hold


@pytest.mark.parametrize("control", ["deleted", "disabled-bit"])
async def test_three_genuinely_gone_accounts_are_still_revoked_on_the_second_pass(
    monkeypatch: pytest.MonkeyPatch, control: str
) -> None:
    """AC-5, the controls for AC-1. The same three-account estate, gone for a READABLE reason, is
    revoked on pass 2 as before. So the hold is keyed on the undetermined answer, not on size."""
    names = ["jdoe", "asmith", "bwong"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        for name in names:
            if control == "deleted":
                directory.delete(name)
            else:
                directory.uac[name] = DISABLED
        first = await _pass(service)
        assert first.revocations == () and not first.hold
        second = await _pass(service)
        reason = "directory_absent" if control == "deleted" else "directory_disabled"
        assert second.aborted is None and not second.hold
        assert sorted((r.username, r.reason) for r in second.revocations) == sorted(
            (n, reason) for n in names
        )
        assert await _alive(service, tokens) == set()
        assert service.directory_reconcile_hold is None
        assert await _audited(store, "auth.ad_reconcile_held") == []


# --- AC-2: the attrition path, at 12 and at 300 signed-in principals -----------------------------


@UNREADABLE
async def test_attrition_from_twelve_to_one_revokes_nothing_and_keeps_the_alert(
    monkeypatch: pytest.MonkeyPatch, uac: Any
) -> None:
    """AC-2, replacing the 12-user breaker test. Before ADR 0195 the breaker held from pass 2 only
    until five or fewer principals remained; the next pass then revoked them all and cleared the
    alert. The old test stopped at four passes and never reached that point. This one does."""
    names = [f"user{i:02d}" for i in range(12)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac = dict.fromkeys(names, uac)
        remaining = list(names)
        while remaining:
            plan = await _pass(service)
            assert plan.aborted is None and plan.revocations == ()
            assert plan.hold and plan.undetermined == len(remaining)
            assert service.directory_reconcile_hold is not None
            await _expire(store, remaining[:1])  # one session reaches the absolute cap
            remaining = remaining[1:]
        assert await _audited(store, "auth.ad_session_revoked") == []
        # With every session gone there is no candidate, and a pass with none clears nothing.
        assert await _pass(service) == ReconcilePlan()
        assert service.directory_reconcile_hold is not None
        assert await _alive(service, tokens) == set()  # expired, not revoked by the reconciler


async def test_a_whole_estate_wave_of_three_hundred_is_held_through_the_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 300 row of ADR 0195's table. Each pass probes 200; the whole estate is held on every
    pass, through attrition down to the last session, and nothing is revoked on the way."""
    names = [f"user{i:03d}" for i in range(300)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac = dict.fromkeys(names, ABSENT)
        for _ in range(3):  # two full rotations
            plan = await _pass(service)
            assert plan.probed == 200 and plan.revocations == () and plan.aborted is None
            assert plan.hold and len(plan.held) == 200
        assert plan.undetermined == 300  # counted across the rotation, not per sample
        await _expire(store, names[:295])  # down to five: the breaker's own floor
        plan = await _pass(service)
        assert plan.revocations == () and plan.hold and plan.undetermined == 5
        await _expire(store, names[295:299])  # down to the last one
        plan = await _pass(service)
        assert plan.revocations == () and plan.hold and plan.undetermined == 1
        assert await _audited(store, "auth.ad_session_revoked") == []
        assert await _alive(service, tokens) == {names[299]}


# --- AC-4: a partial wave holds only the undetermined accounts -----------------------------------


async def test_a_partial_wave_holds_only_the_undetermined_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-4. An access change hides the attribute on three accounts. Those three are held; a
    deleted account and a disabled one in the same passes are still revoked, and the enabled ones
    are untouched."""
    names = ["u1", "u2", "u3", "gone", "off", "ok1", "ok2", "ok3", "ok4", "ok5"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac.update({"u1": ABSENT, "u2": NON_NUMERIC, "u3": None, "off": DISABLED})
        directory.delete("gone")
        first = await _pass(service)
        assert first.hold and first.undetermined == 3 and first.readable == 6
        assert first.revocations == ()
        sink = _Sink()
        second = await _pass(service, sink)
        assert second.aborted is None and second.hold
        assert sorted((r.username, r.reason) for r in second.revocations) == [
            ("gone", "directory_absent"),
            ("off", "directory_disabled"),
        ]
        assert [e[0] for e in sink.events] == [
            "ad_session_revoked",
            "ad_session_revoked",
            "ad_reconcile_held",  # last, so a sink failing on it cannot swallow the others
        ]
        assert await _alive(service, tokens) == set(names) - {"gone", "off"}
        assert service.directory_reconcile_hold is not None


async def test_a_pass_the_breaker_also_aborts_still_writes_the_held_row_and_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule item 9. Two unreadable accounts are held while a bad search base makes ten others miss.
    The breaker judges the ten (the held two are out of its count) and aborts. Both rows and both
    alerts are written, each under its own type, and nothing is revoked."""
    names = ["u1", "u2"] + [f"gone{i}" for i in range(10)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        for name in names[2:]:
            directory.delete(name)
        await _pass(service)
        sink = _Sink()
        plan = await _pass(service, sink)
        assert plan.aborted == "mass_revoke_breaker" and plan.hold
        assert [e[0] for e in sink.events] == ["ad_reconcile_aborted", "ad_reconcile_held"]
        assert sink.events[0][2]["probed"] == 12
        aborted = json.loads((await _audited(store, "auth.ad_reconcile_aborted"))[0]["detail"])
        assert aborted["probed"] == 12  # the row keeps the probed count's meaning ...
        assert aborted["judged"] == 10  # ... and the breaker judged the ten it could revoke
        assert len(await _audited(store, "auth.ad_reconcile_held")) == 2
        assert await _alive(service, tokens) == set(names)
        assert service.directory_reconcile_hold is not None
        assert service.directory_reconcile_alert is not None


# --- BACKLOG #2137: a failed write of the pass's own row does not end the pass -------------------


def _refuse_audit(monkeypatch: pytest.MonkeyPatch, store: MessageStore, action: str) -> None:
    """Make the store refuse every audit write of ``action``, as a full or failing disk would."""
    real = store.record_audit

    async def refusing(name: str, **kwargs: Any) -> None:
        if name == action:
            raise sqlite3.OperationalError("synthetic: disk I/O error")
        await real(name, **kwargs)

    monkeypatch.setattr(store, "record_audit", refusing)


def _logged_at_error(caplog: pytest.LogCaptureFixture, action: str) -> bool:
    return any(r.levelno == logging.ERROR and action in r.getMessage() for r in caplog.records)


async def test_a_failed_held_row_write_still_alerts_each_revocation_and_the_hold(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The held row is written after the pass's revocations. When that write failed, the pass
    raised and returned no plan, so the lifespan task raised no alert for the revocations it had
    already applied, nor for the hold. Now the failure is logged at ERROR and the pass returns."""
    names = ["u1", "u2", "u3", "gone", "off", "ok1", "ok2", "ok3", "ok4", "ok5"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac.update({"u1": ABSENT, "u2": NON_NUMERIC, "u3": None, "off": DISABLED})
        directory.delete("gone")
        assert (await _pass(service)).hold  # strike 1 for "gone" and "off"
        _refuse_audit(monkeypatch, store, "auth.ad_reconcile_held")
        sink = _Sink()
        with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
            plan = await _pass(service, sink)
        assert plan.hold and plan.aborted is None
        assert [e[0] for e in sink.events] == [
            "ad_session_revoked",
            "ad_session_revoked",
            "ad_reconcile_held",
        ]
        assert await _alive(service, tokens) == set(names) - {"gone", "off"}
        assert len(await _audited(store, "auth.ad_session_revoked")) == 2
        assert len(await _audited(store, "auth.ad_reconcile_held")) == 1  # pass 1's row only
        assert service.directory_reconcile_hold is not None  # latched before the write
        assert _logged_at_error(caplog, "auth.ad_reconcile_held")


async def test_a_failed_aborted_row_write_still_alerts_the_breaker_and_the_hold(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The breaker's own row gets the same answer as the held row: its failed write is logged at
    ERROR, and the pass still returns its plan, so both alerts fire and the latch still shows."""
    names = ["u1", "u2"] + [f"gone{i}" for i in range(10)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        for name in names[2:]:
            directory.delete(name)
        await _pass(service)
        _refuse_audit(monkeypatch, store, "auth.ad_reconcile_aborted")
        sink = _Sink()
        with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
            plan = await _pass(service, sink)
        assert plan.aborted == "mass_revoke_breaker" and plan.hold
        assert [e[0] for e in sink.events] == ["ad_reconcile_aborted", "ad_reconcile_held"]
        assert await _audited(store, "auth.ad_reconcile_aborted") == []
        assert len(await _audited(store, "auth.ad_reconcile_held")) == 2
        assert await _alive(service, tokens) == set(names)
        assert service.directory_reconcile_alert is not None  # latched before the write
        assert _logged_at_error(caplog, "auth.ad_reconcile_aborted")


async def test_a_failed_skipped_row_write_does_not_end_an_outage_pass(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The outage's own row is routed the same way, so an outage pass returns its plan too."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith"]) as estate:
        directory, service, store, tokens = estate
        directory.down = True
        _refuse_audit(monkeypatch, store, "auth.ad_reconcile_skipped")
        sink = _Sink()
        with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
            plan = await _pass(service, sink)
        assert plan.directory_outage and sink.events == []
        assert await _alive(service, tokens) == {"jdoe", "asmith"}
        assert _logged_at_error(caplog, "auth.ad_reconcile_skipped")


# --- AC-7: the count spans the probe rotation -----------------------------------------------------


async def test_two_undetermined_accounts_in_different_samples_are_both_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-7. With a budget of two per pass, the two unreadable accounts are never probed together.
    Counted per pass each would look single, and would be struck and revoked. Counted from each
    candidate's latest probe, the pass that sees the second one engages the hold, and it stays."""
    names = ["n1", "n2", "n3", "n4"]
    async with _signed_in_estate(monkeypatch, names, ad_session_recheck_max_users=2) as estate:
        directory, service, store, tokens = estate
        # select_candidates takes never-probed accounts first, ties broken on user_id, so the id
        # order fixes the samples: the first two on pass 1, the other two on pass 2.
        by_id = sorted([(u.id, u.username) for u in await store.list_users()])
        order = [name for _id, name in by_id if name in names]
        first_sample, second_sample = order[:2], order[2:]
        a, c = first_sample[0], second_sample[0]
        directory.uac.update({a: ABSENT, c: NON_NUMERIC})

        first = await _pass(service)
        assert set(first.strikes) == {await _id(store, n) for n in first_sample}
        assert not first.hold and first.strikes[await _id(store, a)] == 1  # a single, struck
        assert service.directory_reconcile_hold is None

        for n in range(6):
            plan = await _pass(service)
            assert plan.hold and plan.undetermined == 2, f"pass {n + 2}"
            assert plan.revocations == ()
            assert service.directory_reconcile_hold is not None
        assert await _alive(service, tokens) == set(names)
        assert await _audited(store, "auth.ad_session_revoked") == []


# --- AC-9: the hysteresis, and the release ------------------------------------------------------


async def test_the_last_held_account_stays_held_and_the_hold_releases_at_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-9. Without hysteresis, attrition defeats the hold: as a partial wave's sessions expire,
    the last held account reads as a single beside readable ones and is revoked. With it, the hold
    stays engaged until no candidate reads undetermined. After the release, a new single is struck
    and revoked as #1639 requires, from a strike count the hold reset to 0."""
    names = ["u1", "u2", "ok1", "ok2", "ok3", "late"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        assert (await _pass(service)).hold
        await _expire(store, ["u1"])
        for _ in range(3):  # u2 is now a single beside three readable answers
            plan = await _pass(service)
            assert plan.hold and plan.undetermined == 1 and plan.readable == 4
            assert plan.revocations == () and plan.strikes[await _id(store, "u2")] == 0
        assert "u2" in await _alive(service, tokens)

        await _expire(store, ["u2"])
        released = await _pass(service)
        assert not released.hold and released.undetermined == 0
        assert service.directory_reconcile_hold is None

        directory.uac["late"] = NON_NUMERIC  # a genuine single, after the release
        struck = await _pass(service)
        assert not struck.hold and struck.revocations == ()
        revoked = await _pass(service)
        assert [(r.username, r.reason) for r in revoked.revocations] == [
            ("late", "directory_undetermined")
        ]
        assert service.directory_reconcile_hold is None


async def test_a_pass_with_no_candidates_keeps_the_message_but_releases_the_latch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule item 9 keeps the held message up across a pass with no candidates. The hysteresis is a
    different thing: that pass pruned every held account out of the record, so u is 0 and nothing is
    left to hold. A genuine single signing in afterwards is struck and revoked, not held."""
    names = ["u1", "u2", "ok1", "late"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, _tokens):
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        assert (await _pass(service)).latched
        await _expire(store, names)
        assert await _pass(service) == ReconcilePlan()  # nobody signed in
        assert service.directory_reconcile_hold is not None  # the message stays (rule item 9)
        assert service._reconcile_hold_latched is False  # the control state does not

        auth = service._ldap
        assert auth is not None
        for name in ("ok1", "late"):
            principal = auth.resolve_principal(name)
            assert principal is not None
            await service._complete_ad_login(principal, None, mfa_verified=True)
        directory.uac["late"] = NON_NUMERIC  # a genuine single, beside a readable account
        struck = await _pass(service)
        assert not struck.hold and struck.revocations == ()
        assert service.directory_reconcile_hold is None
        revoked = await _pass(service)
        assert [(r.username, r.reason) for r in revoked.revocations] == [
            ("late", "directory_undetermined")
        ]


async def test_a_directory_outage_leaves_the_hold_latched(monkeypatch: pytest.MonkeyPatch) -> None:
    """An outage judges nothing: it neither releases the hold nor writes a held row, and it stays
    fail-open. The next pass that reaches the directory judges the hold again."""
    names = ["u1", "u2", "ok1"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        assert (await _pass(service)).hold
        directory.down = True
        sink = _Sink()
        outage = await _pass(service, sink)
        assert outage.directory_outage and sink.events == []
        assert service.directory_reconcile_hold is not None
        assert len(await _audited(store, "auth.ad_reconcile_held")) == 1
        directory.down = False
        assert (await _pass(service)).hold
        assert await _alive(service, tokens) == set(names)


# --- the new alert type is real, routable, and throttled apart from the breaker's ---------------


async def test_the_held_alert_is_not_throttled_by_the_breaker_alert() -> None:
    """Rule item 9: its own throttle key. The notifier keys its re-alert throttle on
    ``type:connection`` and both alerts name the same source, so a shared type would let a breaker
    page swallow the hold's."""
    transport = _RecordingTransport("t")
    sink = NotifierAlertSink([transport])
    sink.ad_reconcile_aborted(
        "directory-reconciler", reason="mass_revoke_breaker", probed=12, detail="tripped"
    )
    sink.ad_reconcile_held(
        "directory-reconciler", reason=HOLD_REASON, undetermined=2, detail="held"
    )
    sink.ad_reconcile_held(
        "directory-reconciler", reason=HOLD_REASON, undetermined=2, detail="held"
    )
    await _drain(sink)
    assert [e["type"] for e in transport.events] == ["ad_reconcile_aborted", "ad_reconcile_held"]
    held = transport.events[1]
    assert held["undetermined"] == 2 and held["reason"] == HOLD_REASON


# --- BACKLOG #2136: each standing reconcile alert resolves itself when it clears -----------------


class _InverseSink(_Sink):
    """Also records the two inverses, which the shared recorder lets fall through to the log."""

    def ad_reconcile_breaker_cleared(self, name: str) -> None:
        self.events.append(("ad_reconcile_breaker_cleared", name, {}))

    def ad_reconcile_hold_released(self, name: str) -> None:
        self.events.append(("ad_reconcile_hold_released", name, {}))


#: Stands in for the auth service: the alerting reads only these two latched messages from it.
_AUTH = SimpleNamespace(
    directory_reconcile_alert=None,
    directory_reconcile_hold=None,
    directory_reconcile_referral=None,
)

#: The referral's own source label (BACKLOG #2538), apart from the breaker's.
_REFERRAL_SOURCE = "directory-reconciler-referral"


def _alerted(plan: ReconcilePlan) -> list[str]:
    sink = _InverseSink()
    _alert_reconcile_plan(plan, _AUTH, sink)  # type: ignore[arg-type]
    return [e[0] for e in sink.events]


@pytest.mark.parametrize(
    ("plan", "expected"),
    [
        (
            ReconcilePlan(probed=3, breaker_clear=True, hold_clear=True),
            ["ad_reconcile_breaker_cleared", "ad_reconcile_hold_released"],
        ),
        (
            ReconcilePlan(probed=3, hold=True, undetermined=2, held=("a", "b"), breaker_clear=True),
            ["ad_reconcile_held", "ad_reconcile_breaker_cleared"],
        ),
        (
            ReconcilePlan(probed=12, aborted="mass_revoke_breaker", hold_clear=True),
            ["ad_reconcile_aborted", "ad_reconcile_hold_released"],
        ),
        (ReconcilePlan(probed=3), []),
    ],
    ids=["both-clear", "held", "tripped", "neither-proven"],
)
def test_each_clear_the_service_marks_is_raised_after_the_pages_on_every_pass(
    plan: ReconcilePlan, expected: list[str]
) -> None:
    """The inverses come last, so a sink raising on one cannot cost a page. And they repeat on
    every marked pass rather than once: a resolve is an idempotent update, so a repeat costs
    nothing, while a once-only inverse whose fire-and-forget write failed would never be retried."""
    assert _alerted(plan) == expected
    assert _alerted(plan) == expected


@pytest.mark.parametrize(
    ("plan", "expected"),
    [
        (
            # A referral beside an applied revocation: the revocation, then the referral's page.
            ReconcilePlan(
                probed=3,
                referred=("a",),
                revocations=(SessionRevocation("b", "bwong", reason="directory_absent"),),
            ),
            [("ad_session_revoked", "bwong"), ("ad_reconcile_aborted", _REFERRAL_SOURCE)],
        ),
        (
            # A pass of referrals only: the referral's page alone, never the breaker's instance.
            ReconcilePlan(probed=2, referred=("a", "b"), aborted=REFERRAL_ABORT),
            [("ad_reconcile_aborted", _REFERRAL_SOURCE)],
        ),
        (
            # A breaker trip beside a referral: one page on each instance.
            ReconcilePlan(probed=12, referred=("a",), aborted="mass_revoke_breaker"),
            [
                ("ad_reconcile_aborted", "directory-reconciler"),
                ("ad_reconcile_aborted", _REFERRAL_SOURCE),
            ],
        ),
        (
            ReconcilePlan(probed=3, breaker_clear=True, referral_clear=True),
            [
                ("ad_reconcile_breaker_cleared", "directory-reconciler"),
                ("ad_reconcile_breaker_cleared", _REFERRAL_SOURCE),
            ],
        ),
    ],
    ids=["beside-a-revocation", "referrals-only", "beside-a-trip", "both-clear"],
)
def test_a_referral_pages_and_clears_under_its_own_source(
    plan: ReconcilePlan, expected: list[tuple[str, str]]
) -> None:
    """BACKLOG #2538. The referral reuses the ``ad_reconcile_aborted`` type and its inverse, under
    its own source label, so it never shares an instance with the breaker."""
    sink = _InverseSink()
    _alert_reconcile_plan(plan, _AUTH, sink)  # type: ignore[arg-type]
    assert [(e[0], e[1]) for e in sink.events] == expected


def test_the_inverses_resolve_their_alerts_and_are_not_rule_targetable() -> None:
    assert _AUTO_RESOLVE["ad_reconcile_breaker_cleared"] == "ad_reconcile_aborted"
    assert _AUTO_RESOLVE["ad_reconcile_hold_released"] == "ad_reconcile_held"
    for inverse in ("ad_reconcile_breaker_cleared", "ad_reconcile_hold_released"):
        assert inverse not in _ALERT_EVENT_TYPES
        for cls in (LoggingAlertSink, NotifierAlertSink):
            assert callable(getattr(cls, inverse, None)), f"{cls.__name__}.{inverse}"


async def _settle(sink: NotifierAlertSink) -> None:
    """Wait for the sink's fire-and-forget alert-state writes, so each pass is read after its own."""
    while sink._state_tasks:
        await asyncio.gather(*list(sink._state_tasks))


async def _open_alerts(store: MessageStore) -> set[tuple[str, str]]:
    return {(i.event_type, i.connection) for i in await store.list_active_alert_instances()}


ABORTED = ("ad_reconcile_aborted", "directory-reconciler")
HELD = ("ad_reconcile_held", "directory-reconciler")
REFERRAL = ("ad_reconcile_aborted", "directory-reconciler-referral")


async def _left_open_by_an_earlier_run(store: MessageStore) -> None:
    last_run = NotifierAlertSink([], store=store)
    last_run.ad_reconcile_aborted(
        "directory-reconciler", reason="mass_revoke_breaker", probed=12, detail="tripped"
    )
    last_run.ad_reconcile_held(
        "directory-reconciler", reason=HOLD_REASON, undetermined=2, detail="held"
    )
    await _settle(last_run)
    assert await _open_alerts(store) == {ABORTED, HELD}


async def _alerted_pass(service: AuthService, sink: NotifierAlertSink) -> ReconcilePlan:
    plan = await _pass(service, sink)
    await _settle(sink)
    return plan


async def test_the_durable_held_instance_stays_open_while_held_and_resolves_on_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: the real service, the real notifier and the real alert-instance table."""
    names = ["u1", "u2", "ok1", "ok2", "ok3"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, _tokens):
        sink = NotifierAlertSink([], store=store)
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        for _ in range(2):
            plan = await _alerted_pass(service, sink)
            assert plan.hold and not plan.hold_clear
            assert await _open_alerts(store) == {HELD}
        directory.uac.update({"u1": ENABLED, "u2": ENABLED})
        plan = await _alerted_pass(service, sink)
        assert plan.hold_clear and plan.breaker_clear
        assert await _open_alerts(store) == set()


async def test_a_breaker_trip_resolves_only_once_the_directory_reads_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pass that carries a pending strike is no evidence either way: the breaker has not judged
    those accounts yet. So the first pass of a bad search base resolves nothing, the second trips,
    and only a pass that reads every account clean resolves the trip."""
    names = ["ok1", "ok2"] + [f"gone{i}" for i in range(10)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, _tokens):
        sink = NotifierAlertSink([], store=store)
        saved = dict(directory.ids)
        for name in names[2:]:
            directory.delete(name)
        first = await _alerted_pass(service, sink)
        assert first.aborted is None and not first.breaker_clear  # strike 1: not judged yet
        second = await _alerted_pass(service, sink)
        assert second.aborted == "mass_revoke_breaker" and not second.breaker_clear
        assert await _open_alerts(store) == {ABORTED}
        directory.ids.update(saved)  # the search base is fixed
        third = await _alerted_pass(service, sink)
        assert third.aborted is None and third.breaker_clear
        assert await _open_alerts(store) == set()


async def test_a_trip_on_role_changes_is_not_cleared_by_a_sample_that_missed_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A role-change revocation leaves no strike, so the strike test alone cannot hold a trip open.
    With a budget of two, the pass after the trip reads only the other two accounts, finds nothing
    to revoke, and is not aborted. That is no evidence the trip has gone: the two accounts behind it
    have not been read again. The next pass reads them and trips again."""
    names = ["n1", "n2", "n3", "n4"]
    budget = {"ad_session_recheck_max_users": 2, "ad_session_revoke_max": 0}
    async with _signed_in_estate(monkeypatch, names, **budget) as estate:
        _directory, service, store, _tokens = estate
        by_id = sorted([(u.id, u.username) for u in await store.list_users()])
        first_sample = [uid for uid, name in by_id if name in names][:2]
        for uid in first_sample:  # roles the directory no longer grants
            await store.set_user_roles(uid, [Role.VIEWER.value])
        tripped = await _pass(service)
        assert tripped.aborted == "mass_revoke_breaker"
        other_sample = await _pass(service)
        assert other_sample.aborted is None and other_sample.revocations == ()
        assert not other_sample.breaker_clear
        assert (await _pass(service)).aborted == "mass_revoke_breaker"


async def test_a_trip_on_role_changes_is_not_cleared_by_a_pass_that_held_those_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A held probe judged neither roles nor scope, and its strike went back to 0. So the pass
    after a role-change trip that holds the two accounts behind it, and reads the other two clean,
    is not aborted and still no evidence the trip has gone. The next readable pass trips again."""
    names = ["n1", "n2", "n3", "n4"]
    async with _signed_in_estate(monkeypatch, names, ad_session_revoke_max=0) as estate:
        directory, service, store, _tokens = estate
        for name in ("n1", "n2"):  # roles the directory no longer grants
            await store.set_user_roles(await _id(store, name), [Role.VIEWER.value])
        assert (await _pass(service)).aborted == "mass_revoke_breaker"
        directory.uac.update({"n1": ABSENT, "n2": ABSENT})
        held = await _pass(service)
        assert held.aborted is None and held.hold and len(held.held) == 2
        assert not held.breaker_clear, "a held account counted as read again"
        directory.uac.update({"n1": ENABLED, "n2": ENABLED})
        assert (await _pass(service)).aborted == "mass_revoke_breaker"


async def test_an_estate_that_reads_only_absent_does_not_release_a_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No account read ``userAccountControl``: the searches found no entry at all. That is no
    evidence the read right the hold is about has come back, so the open hold stays open."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith"]) as estate:
        directory, _service, store, _tokens = estate
        await _left_open_by_an_earlier_run(store)
        directory.delete("jdoe")
        directory.delete("asmith")
        service = _held_before(_fresh_process(store))
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        plan = await _alerted_pass(service, sink)
        assert plan.aborted is None and not plan.hold and plan.revocations == ()
        assert not plan.hold_clear
        assert await _open_alerts(store) == {ABORTED, HELD}


async def test_a_resolve_the_store_failed_to_write_is_retried_on_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The notifier writes alert state fire-and-forget and only logs a failure. So the inverse is
    raised on every clear pass, not once, and the next pass resolves what the last one could not."""
    names = ["u1", "u2", "ok1", "ok2", "ok3"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, _tokens):
        sink = NotifierAlertSink([], store=store)
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        assert (await _alerted_pass(service, sink)).hold
        directory.uac.update({"u1": ENABLED, "u2": ENABLED})
        real = store.resolve_alert_instances_for
        failures = [sqlite3.OperationalError("synthetic: database is locked")]

        async def failing_once(
            *, event_type: str, connection: str, now: float | None = None
        ) -> int:
            if event_type == "ad_reconcile_held" and failures:
                raise failures.pop()
            return await real(event_type=event_type, connection=connection, now=now)

        monkeypatch.setattr(store, "resolve_alert_instances_for", failing_once)
        assert (await _alerted_pass(service, sink)).hold_clear
        assert await _open_alerts(store) == {HELD}, "the failed resolve went through after all"
        assert (await _alerted_pass(service, sink)).hold_clear
        assert await _open_alerts(store) == set()


async def test_a_pass_that_aborts_and_holds_marks_neither_clear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = ["u1", "u2"] + [f"gone{i}" for i in range(10)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, _store, _tokens):
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        for name in names[2:]:
            directory.delete(name)
        await _pass(service)
        plan = await _pass(service)
        assert plan.aborted == "mass_revoke_breaker" and plan.hold
        assert not plan.breaker_clear and not plan.hold_clear


def _fresh_process(store: MessageStore, **settings: Any) -> AuthService:
    """A new engine process on the same store: the alert instances survive, and the reconciler's
    strike and outcome records start empty."""
    return AuthService(store, _settings(**settings), ldap=LdapAuthenticator(_settings(**settings)))


def _held_before(service: AuthService) -> AuthService:
    """``service`` with its hold standing set as though a pass of its own had held. A fresh
    process releases no hold at all, so a test that pins some other clause of the release first
    takes that gate out of the way. Its strike and outcome records stay empty."""
    service._reconcile_hold_standing = "held"
    return service


async def test_a_fresh_process_resolves_a_trip_its_last_run_left_open_but_not_a_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The breaker has no latch to lose, so a clean pass from a fresh process resolves the trip,
    though never on an outage. The hold's latch did not survive the restart, and this process has
    not latched one, so it cannot tell whether the last run's latch still held an account. The
    hold's instance stays open for an operator."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith"]) as estate:
        directory, _service, store, _tokens = estate
        await _left_open_by_an_earlier_run(store)
        service = _fresh_process(store)
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        directory.down = True
        assert (await _alerted_pass(service, sink)).directory_outage
        assert await _open_alerts(store) == {ABORTED, HELD}
        directory.down = False
        for _ in range(2):  # not a matter of waiting another pass
            plan = await _alerted_pass(service, sink)
            assert plan.breaker_clear and not plan.hold_clear
            assert await _open_alerts(store) == {HELD}


async def test_a_fresh_process_resolves_a_hold_once_it_has_latched_and_released_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the test above. A fresh process leaves the last run's hold open, then a wave
    of its own latches, and when that wave reads clean again this process saw the lift itself, so
    it resolves the instance."""
    names = ["u1", "u2", "ok1"]
    async with _signed_in_estate(monkeypatch, names) as (directory, _service, store, _tokens):
        await _left_open_by_an_earlier_run(store)
        service = _fresh_process(store)
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        assert not (await _alerted_pass(service, sink)).hold_clear
        assert await _open_alerts(store) == {HELD}
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        held = await _alerted_pass(service, sink)
        assert held.hold and held.latched and not held.hold_clear
        directory.uac.update({"u1": ENABLED, "u2": ENABLED})
        released = await _alerted_pass(service, sink)
        assert not released.hold and released.hold_clear
        assert await _open_alerts(store) == set()


async def test_a_fresh_process_against_a_still_bad_search_base_keeps_the_trip_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restart resets every strike, so its first pass cannot trip the breaker even when nothing
    was fixed. "Not aborted" there is not a clear, and the open trip must stay open."""
    names = ["ok1", "ok2"] + [f"gone{i}" for i in range(10)]
    async with _signed_in_estate(monkeypatch, names) as (directory, _service, store, _tokens):
        await _left_open_by_an_earlier_run(store)
        for name in names[2:]:
            directory.delete(name)
        service = _fresh_process(store)
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        plan = await _alerted_pass(service, sink)
        assert plan.aborted is None and not plan.breaker_clear
        assert ABORTED in await _open_alerts(store)


async def test_a_fresh_process_does_not_release_a_hold_its_budget_has_not_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a budget of two, a fresh process's first pass reads only half the estate. The held
    accounts are in the other half, so a clean first half is no evidence the hold has gone."""
    names = ["n1", "n2", "n3", "n4"]
    async with _signed_in_estate(monkeypatch, names, ad_session_recheck_max_users=2) as estate:
        directory, _service, store, _tokens = estate
        by_id = sorted([(u.id, u.username) for u in await store.list_users()])
        order = [name for _id, name in by_id if name in names]
        directory.uac.update(dict.fromkeys(order[2:], ABSENT))  # the second sample only
        await _left_open_by_an_earlier_run(store)
        service = _held_before(_fresh_process(store, ad_session_recheck_max_users=2))
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        first = await _alerted_pass(service, sink)
        assert not first.hold and not first.hold_clear and not first.breaker_clear
        assert await _open_alerts(store) == {ABORTED, HELD}
        second = await _alerted_pass(service, sink)
        assert second.hold and not second.hold_clear
        assert HELD in await _open_alerts(store)


async def test_a_fresh_process_does_not_clear_a_trip_on_a_pass_that_held_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restart forgets which accounts were behind the last trip. A held account's roles and
    scope were not judged, and its strike went back to 0, so a fresh process's pass that holds two
    accounts and reads the other two clean is no evidence the trip has gone."""
    names = ["n1", "n2", "n3", "n4"]
    async with _signed_in_estate(monkeypatch, names) as (directory, _service, store, _tokens):
        await _left_open_by_an_earlier_run(store)
        directory.uac.update({"n1": ABSENT, "n2": ABSENT})
        service = _fresh_process(store)
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        plan = await _alerted_pass(service, sink)
        assert plan.aborted is None and plan.hold and len(plan.held) == 2
        assert not plan.breaker_clear
        assert ABORTED in await _open_alerts(store)


async def test_a_fresh_process_does_not_release_a_hold_on_a_pass_that_read_nothing_readable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a budget of one, the first pass reads the enabled account and the second reads only
    the deleted one. The record still holds the first pass's PRESENT answer, but the second pass
    read nothing that says ``userAccountControl`` is readable now, so it releases no hold."""
    names = ["n1", "n2"]
    async with _signed_in_estate(monkeypatch, names, ad_session_recheck_max_users=1) as estate:
        directory, _service, store, _tokens = estate
        by_id = sorted([(u.id, u.username) for u in await store.list_users()])
        order = [name for _id, name in by_id if name in names]
        await _left_open_by_an_earlier_run(store)
        directory.delete(order[1])  # the second sample only
        service = _held_before(_fresh_process(store, ad_session_recheck_max_users=1))
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        first = await _alerted_pass(service, sink)
        assert first.readable == 1 and not first.hold_clear  # the other account has no answer yet
        second = await _alerted_pass(service, sink)
        assert second.aborted is None and not second.hold and second.readable == 0
        assert not second.hold_clear, "an earlier pass's readable answer released the hold"
        assert HELD in await _open_alerts(store)


@pytest.mark.parametrize(
    ("standing", "released"),
    [("fresh", False), ("held", False), ("settled", True)],
    ids=["fresh", "held-forfeits", "settled-keeps"],
)
async def test_a_fresh_process_does_not_release_a_hold_on_a_pass_that_revoked_an_undetermined(
    monkeypatch: pytest.MonkeyPatch, standing: _HoldStanding, released: bool
) -> None:
    """A restart loses the hysteresis latch. A lone undetermined account beside readable ones is
    then not held, and at the strike threshold the pass revokes it. Its answer is the hold's own
    condition, which the lost latch may still have been holding, so that pass releases no hold.
    The breaker judged the revocation, so the trip resolves. The next pass no longer sees the
    revoked account and reads the rest clean, and it still releases no hold: nothing re-read the
    account the lost latch may have held.

    ``held``: a process whose own pass held before can see its latch lift before every account has
    an answer from it, so the revocation forfeits the release there too. ``settled``: once a pass
    here has found the hold gone, its records cover what an earlier run held. The lone revocation
    is then ADR 0195's own, so the third pass releases."""
    names = ["u1", "ok1", "ok2"]
    async with _signed_in_estate(monkeypatch, names) as (directory, _service, store, _tokens):
        await _left_open_by_an_earlier_run(store)
        directory.uac["u1"] = ABSENT
        service = _fresh_process(store)
        service._reconcile_hold_standing = standing
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        first = await _alerted_pass(service, sink)
        assert not first.hold and first.revocations == () and not first.hold_clear  # strike 1
        second = await _alerted_pass(service, sink)
        assert second.aborted is None and not second.hold
        assert [r.reason for r in second.revocations] == ["directory_undetermined"]
        assert second.breaker_clear and not second.hold_clear
        open_now = await _open_alerts(store)
        assert HELD in open_now and ABORTED not in open_now
        third = await _alerted_pass(service, sink)
        assert third.aborted is None and not third.hold and third.readable == 2
        assert third.hold_clear is released, "the release did not follow the standing"
        assert (HELD in await _open_alerts(store)) is not released


# --- the clear predicate, clause by clause, and the sole-reconciler gate --------------------------
#
# Each clause of the clear predicate is pinned by a test that turns red when it goes. A [cluster]
# node or a multi-shard engine resolves nothing; what that gate misses is stated once, in
# AuthService._mark_reconcile_clears.

PRESENT, ABSENT_OUTCOME, UNDETERMINED = (
    ProbeOutcome.PRESENT,
    ProbeOutcome.ABSENT,
    ProbeOutcome.UNDETERMINED,
)


async def _marked(
    plan: ReconcilePlan,
    outcomes: dict[str, ProbeOutcome],
    *,
    strikes: dict[str, int] | None = None,
    standing: _HoldStanding = "held",
) -> tuple[bool, bool]:
    """``(breaker_clear, hold_clear)`` for ``plan``, with these records on file for exactly these
    signed-in accounts and nothing unconfirmed, on a process whose own pass held before. Every
    other input is held clean, so a test changes the one input whose clause it pins."""
    store = await MessageStore.open(":memory:")
    try:
        service = _fresh_process(store)
        service._reconcile_hold_standing = standing
        service._reconcile_outcomes = dict(outcomes)
        service._reconcile_strikes = dict.fromkeys(outcomes, 0) | (strikes or {})
        service._reconcile_unconfirmed = set()
        # The predicate reads only the candidate ids, so the records behind them are not built.
        users = cast(Mapping[str, UserRecord], dict.fromkeys(outcomes))
        marked = service._mark_reconcile_clears(plan, users)
        return marked.breaker_clear, marked.hold_clear
    finally:
        await store.close()


async def test_the_clear_predicate_control_reads_both_clear() -> None:
    """The control for the ``_marked`` tests below: on these inputs both clears hold, so each red
    there is the one clause that test changes."""
    plan = ReconcilePlan(probed=2, readable=2, outcomes={"a": PRESENT, "b": PRESENT})
    assert await _marked(plan, {"a": PRESENT, "b": PRESENT}) == (True, True)


async def test_an_estate_that_reads_only_undetermined_is_no_breaker_clear() -> None:
    """``undetermined not in outcomes``: a pass of held accounts only cannot trip the breaker at
    all, so it says nothing about whether the breaker is still tripped."""
    plan = ReconcilePlan(probed=2)
    assert await _marked(plan, {"a": UNDETERMINED, "b": UNDETERMINED}) == (False, False)


async def test_an_undetermined_answer_on_record_is_no_hold_clear_even_when_the_pass_held_none() -> (
    None
):
    """``undetermined not in outcomes``: this node's pass did not hold, but an undetermined answer
    on record is the hold's own condition, which another node's latch may still be holding on. It
    keeps the breaker open too: that account's roles and scope were not judged."""
    plan = ReconcilePlan(probed=1, readable=1, outcomes={"a": PRESENT})
    assert await _marked(plan, {"a": PRESENT, "b": UNDETERMINED}) == (False, False)


async def test_a_hold_clear_needs_one_answer_that_read_the_attribute() -> None:
    """``plan.readable > 0``: ABSENT answers alone found no entry, so they say nothing about the
    attribute the hold is about. A DISABLED answer did read it, so it counts."""
    gone = {"a": ABSENT_OUTCOME, "b": ABSENT_OUTCOME}
    plan = ReconcilePlan(probed=2, outcomes=gone)
    assert await _marked(plan, gone, strikes={"a": 1, "b": 1}) == (False, False)
    disabled = {"a": ProbeOutcome.DISABLED, "b": ABSENT_OUTCOME}
    plan = ReconcilePlan(probed=2, readable=1, outcomes=disabled)
    assert await _marked(plan, disabled, strikes={"a": 1, "b": 1}) == (False, True)


async def test_a_readable_answer_from_an_earlier_pass_is_no_hold_clear() -> None:
    """The readable answer must come from THIS pass. The record still says ``a`` read PRESENT on
    an earlier pass, but this pass read only ``b``, and found no entry. Nothing this pass read says
    the attribute is readable now, so the hold stays open."""
    plan = ReconcilePlan(probed=1, outcomes={"b": ABSENT_OUTCOME})
    for earlier in (PRESENT, ProbeOutcome.DISABLED):  # neither stands in for a readable answer now
        record = {"a": earlier, "b": ABSENT_OUTCOME}
        assert await _marked(plan, record, strikes={"b": 1}) == (False, False), earlier.value


async def test_an_undetermined_answer_this_pass_revoked_still_blocks_the_hold_clear() -> None:
    """The revoked exclusion does not reach the hold. ``a`` read undetermined and was revoked,
    because no hold engaged on this process. A restarted process has lost the latch that may still
    have held it, so its answer is the hold's own condition. The breaker judged the revocation, so
    its clear stands."""
    outcomes = {"a": UNDETERMINED, "b": PRESENT}
    plan = ReconcilePlan(
        probed=2,
        readable=1,
        outcomes=outcomes,
        revocations=(SessionRevocation("a", "alice", reason="directory_undetermined"),),
    )
    assert await _marked(plan, outcomes, strikes={"a": 2}) == (True, False)


async def test_a_process_whose_own_pass_has_not_held_releases_no_hold() -> None:
    """``_reconcile_hold_standing``: a fresh process cannot tell whether the latch an earlier run
    kept was still holding an account, and a forfeited one revoked an account such a latch may
    have held. The control's inputs, and the breaker still clears: it has no latch to lose."""
    plan = ReconcilePlan(probed=2, readable=2, outcomes={"a": PRESENT, "b": PRESENT})
    record = {"a": PRESENT, "b": PRESENT}
    assert await _marked(plan, record, standing="fresh") == (True, False)
    assert await _marked(plan, record, standing="forfeit") == (True, False)
    assert await _marked(plan, record, standing="settled") == (True, True)


@pytest.mark.parametrize(
    ("start", "event", "end"),
    [
        ("fresh", "held", "held"),
        ("fresh", "forfeit", "forfeit"),
        ("fresh", "settled", "fresh"),
        ("held", "forfeit", "forfeit"),
        ("held", "settled", "settled"),
        ("forfeit", "held", "forfeit"),
        ("forfeit", "settled", "forfeit"),
        ("settled", "held", "settled"),
        ("settled", "forfeit", "settled"),
    ],
)
async def test_the_hold_standing_never_leaves_a_forfeit(
    start: _HoldStanding, event: _HoldStanding, end: _HoldStanding
) -> None:
    """A forfeit is never left, and a settled process does not forfeit: its records cover what an
    earlier run held."""
    store = await MessageStore.open(":memory:")
    try:
        service = _fresh_process(store)
        service._reconcile_hold_standing = start
        service._advance_hold_standing(event)
        assert service._reconcile_hold_standing == end
    finally:
        await store.close()


async def test_a_pass_that_raises_after_revoking_an_undetermined_account_still_forfeits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The forfeit is recorded before the revocation lands. Here the revocation's own audit write
    fails, so the pass raises after the sessions are gone and returns no plan. The next pass no
    longer sees the account, and must not release the hold on the accounts it left."""
    names = ["u1", "ok1", "ok2"]
    async with _signed_in_estate(monkeypatch, names) as (directory, _service, store, _tokens):
        await _left_open_by_an_earlier_run(store)
        directory.uac["u1"] = ABSENT
        service = _held_before(_fresh_process(store))
        await service.initialize()
        sink = NotifierAlertSink([], store=store)
        assert (await _alerted_pass(service, sink)).revocations == ()  # strike 1
        real = store.record_audit
        _refuse_audit(monkeypatch, store, "auth.ad_session_revoked")
        with pytest.raises(sqlite3.OperationalError):
            await service.reconcile_directory_sessions()
        monkeypatch.setattr(store, "record_audit", real)
        after = await _alerted_pass(service, sink)
        assert after.aborted is None and after.revocations == () and after.readable == 2
        assert not after.hold_clear, "a pass that raised lost the forfeit"
        assert HELD in await _open_alerts(store)


async def test_a_process_releases_a_hold_it_raised_on_one_account_with_nothing_readable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lone undetermined account with nothing readable beside it is held without the latch. The
    hold is still this process's own, so when the account reads clean it releases."""
    async with _signed_in_estate(monkeypatch, ["jdoe"]) as (directory, service, store, _tokens):
        sink = NotifierAlertSink([], store=store)
        directory.uac["jdoe"] = ABSENT
        held = await _alerted_pass(service, sink)
        assert held.hold and not held.latched and not held.hold_clear
        assert await _open_alerts(store) == {HELD}
        directory.uac["jdoe"] = ENABLED
        assert (await _alerted_pass(service, sink)).hold_clear
        assert await _open_alerts(store) == set()


async def test_an_account_this_pass_revoked_does_not_hold_the_breaker_open() -> None:
    """The ``revoked`` exclusion: the account the pass just revoked still carries its strikes on
    record, and it has left the estate. Counting it would keep the breaker open after every pass
    that revokes anyone."""
    outcomes = {"a": ABSENT_OUTCOME, "b": PRESENT}
    plan = ReconcilePlan(
        probed=2,
        readable=1,
        outcomes=outcomes,
        revocations=(SessionRevocation("a", "alice", reason="directory_absent"),),
    )
    assert await _marked(plan, outcomes, strikes={"a": 2}) == (True, True)


async def test_a_breaker_trip_still_resolves_a_hold_that_has_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The aborted branch marks the clears too. A held pass writes its own row on a pass the
    breaker aborts (ADR 0195 rule item 9), and so a trip with no undetermined account on record is
    evidence that the hold this process latched has gone. The breaker's own instance stays open."""
    names = ["ok1", "ok2", "u1", "u2"] + [f"gone{i}" for i in range(10)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, _tokens):
        sink = NotifierAlertSink([], store=store)
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        for name in names[4:]:
            directory.delete(name)
        held = await _alerted_pass(service, sink)  # strike 1 for the gone ten: no trip yet
        assert held.aborted is None and held.hold and held.latched
        assert await _open_alerts(store) == {HELD}
        directory.uac.update({"u1": ENABLED, "u2": ENABLED})
        tripped = await _alerted_pass(service, sink)
        assert tripped.aborted == "mass_revoke_breaker" and not tripped.hold
        assert tripped.hold_clear and not tripped.breaker_clear
        assert await _open_alerts(store) == {ABORTED}


def test_without_clears_sets_every_clear_flag_false_and_nothing_else() -> None:
    names = {f.name for f in dataclass_fields(ReconcilePlan) if f.name.endswith("_clear")}
    assert {"breaker_clear", "hold_clear"} <= names  # the suffix match is armed
    every_clear: dict[str, Any] = dict.fromkeys(names, True)
    plan = replace(
        ReconcilePlan(probed=3, hold=True, undetermined=2, held=("a", "b")), **every_clear
    )
    stripped = _without_clears(plan)
    assert not any(getattr(stripped, name) for name in names)
    assert stripped == ReconcilePlan(probed=3, hold=True, undetermined=2, held=("a", "b"))


def _runner(all_shard_ids: tuple[str, ...] | None) -> RegistryRunner:
    return cast(
        RegistryRunner, SimpleNamespace(registry=SimpleNamespace(all_shard_ids=all_shard_ids))
    )


def test_only_a_process_alone_on_its_store_is_the_sole_reconciler() -> None:
    single = NullCoordinator()
    clustered = cast(ClusterCoordinator, SimpleNamespace(is_clustered=lambda: True))
    shard_filter = object()  # `serve --shard` passes a filter; only its presence is read
    assert _is_sole_reconciler(single, None, None)  # plain serve
    assert _is_sole_reconciler(single, shard_filter, _runner(None))  # supervise, one shard
    assert not _is_sole_reconciler(single, shard_filter, _runner(("a", "b")))  # two shards
    assert not _is_sole_reconciler(single, shard_filter, None)  # a shard with no graph
    assert not _is_sole_reconciler(clustered, None, _runner(None))  # a [cluster] node


class _PlanAuth:
    """Stands in for the auth service in the lifespan loop: every pass returns one plan."""

    directory_reconcile_alert: str | None = None
    directory_reconcile_hold = "held"

    def __init__(self, plan: ReconcilePlan) -> None:
        self.plan = plan
        self.passes = 0

    async def reconcile_directory_sessions(self) -> ReconcilePlan:
        self.passes += 1
        return self.plan


@pytest.mark.parametrize(
    ("sole", "expected"),
    [
        (True, {"ad_reconcile_held", "ad_reconcile_breaker_cleared"}),
        (False, {"ad_reconcile_held"}),
    ],
    ids=["sole-reconciler", "shared-store"],
)
async def test_a_process_that_may_share_its_store_pages_but_resolves_nothing(
    sole: bool, expected: set[str]
) -> None:
    """BACKLOG #2136. One node's clear rests on its own records and its own view of the directory,
    while the instance it would resolve is the store's. So a cluster node or an engine shard still
    pages a hold, and raises no inverse."""
    plan = ReconcilePlan(
        probed=3, hold=True, undetermined=2, held=("a", "b"), breaker_clear=True, hold_clear=False
    )
    auth = _PlanAuth(plan)
    sink = _InverseSink()
    task = asyncio.create_task(
        _directory_reconciler(auth, 0.001, sink, sole_reconciler=sole)  # type: ignore[arg-type]
    )
    try:
        for _ in range(500):
            if auth.passes >= 3:
                break
            await asyncio.sleep(0.005)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert auth.passes >= 3
    assert {event[0] for event in sink.events} == expected


# --- BACKLOG #2538: a referral pages, through the real authenticator and the real notifier ------


async def test_a_referring_search_base_pages_and_resolves_once_the_base_is_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: resultCode 10 on the user search, through the REAL ``LdapAuthenticator``, the
    real service, the real notifier and the real alert-instance table. The referral opens the
    ``ad_reconcile_aborted`` instance with reason ``directory_referral``; an ordinary outage, the
    control, opens nothing; and a pass that reads every account clean after the fix resolves it.

    RED when: the referral reaches the reconciler as a plain LdapError, so the pass reads as an
    outage, is audited as skipped and pages nobody."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith"]) as estate:
        directory, service, store, tokens = estate
        sink = NotifierAlertSink([], store=store)

        directory.down = True  # the control: an outage pages nothing
        assert (await _alerted_pass(service, sink)).directory_outage
        assert await _open_alerts(store) == set()
        directory.down = False

        directory.refer = True
        for _ in range(2):
            plan = await _alerted_pass(service, sink)
            assert plan.directory_referral and len(plan.referred) == 2 and plan.revocations == ()
            assert not plan.breaker_clear and not plan.hold_clear
        assert await _open_alerts(store) == {REFERRAL}
        rows = [
            json.loads(r["detail"]) for r in await _audited(store, "auth.ad_reconcile_referred")
        ]
        assert len(rows) == 2 and all(row["reason"] == "directory_referral" for row in rows)
        alert = service.directory_reconcile_referral
        assert alert is not None and "ad_user_search_base" in alert
        for token in tokens.values():
            assert await service.identity_for_token(token) is not None

        directory.refer = False  # the base now lies in the bound controller's own domain
        plan = await _alerted_pass(service, sink)
        assert plan.aborted is None and plan.referral_clear and plan.breaker_clear
        assert await _open_alerts(store) == set()


async def test_a_referring_group_search_base_still_revokes_disabled_and_absent_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end, through the REAL ``LdapAuthenticator``: a nested-group search base in another
    domain refers only the accounts the user search FOUND, because a disabled or absent account
    returns before its groups are read. Those two answers came from a clean user search, so they
    must still revoke. The pass pages on ``ad_reconcile_aborted`` with reason
    ``directory_referral``, and the instance resolves once the group base is fixed.

    RED when: any referral aborts the whole pass, so the disabled and the absent account keep their
    sessions on a first deployment for as long as the group base is wrong."""
    names = ["jdoe", "asmith", "bwong"]
    groups = {"ad_group_search_base": "OU=Groups,DC=other,DC=invalid"}
    async with _signed_in_estate(monkeypatch, names, **groups) as estate:
        directory, service, store, tokens = estate
        sink = NotifierAlertSink([], store=store)
        directory.refer_groups = True
        directory.uac["asmith"] = DISABLED
        directory.delete("bwong")
        first = await _alerted_pass(service, sink)
        second = await _alerted_pass(service, sink)
        for plan in (first, second):
            assert plan.aborted is None and len(plan.referred) == 1
            assert not plan.breaker_clear and not plan.hold_clear
        assert sorted((r.username, r.reason) for r in second.revocations) == [
            ("asmith", "directory_disabled"),
            ("bwong", "directory_absent"),
        ]
        assert await _alive(service, tokens) == {"jdoe"}
        revoked = {("ad_session_revoked", "asmith"), ("ad_session_revoked", "bwong")}
        assert await _open_alerts(store) == {REFERRAL, *revoked}
        rows = [
            json.loads(r["detail"]) for r in await _audited(store, "auth.ad_reconcile_referred")
        ]
        assert len(rows) == 2 and all(row["aborted"] is None for row in rows)
        alert = service.directory_reconcile_referral
        assert alert is not None and "ad_group_search_base" in alert[:200]

        # The referred account now reads DISABLED, which returns before its groups are read. That
        # is no evidence the group base was fixed, so it must clear neither the alert nor its latch.
        directory.uac["jdoe"] = DISABLED
        plan = await _alerted_pass(service, sink)
        assert plan.referred == () and not plan.referral_clear
        assert REFERRAL in await _open_alerts(store)
        assert service.directory_reconcile_referral is not None
        directory.uac["jdoe"] = ENABLED  # one strike, so still signed in

        directory.refer_groups = False  # the group base now lies in the bound controller's domain
        plan = await _alerted_pass(service, sink)
        assert plan.aborted is None and plan.referred == () and plan.referral_clear
        assert await _open_alerts(store) == revoked  # the referral's instance resolved


async def test_a_referral_pass_neither_releases_a_hold_nor_resolves_what_is_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A referral judged nothing, so like an outage it leaves the hold's message and the open held
    instance alone, and marks no clear, even though the accounts it would have read are fine now.
    It raises only its own aborted alert."""
    async with _signed_in_estate(monkeypatch, ["u1", "u2", "ok1", "ok2"]) as estate:
        directory, service, store, _tokens = estate
        sink = NotifierAlertSink([], store=store)
        directory.uac.update({"u1": ABSENT, "u2": ABSENT})
        assert (await _alerted_pass(service, sink)).hold
        held_message = service.directory_reconcile_hold
        assert held_message is not None
        directory.uac.update({"u1": ENABLED, "u2": ENABLED})  # would release, if it were read
        directory.refer = True
        plan = await _alerted_pass(service, sink)
        assert plan.directory_referral and not plan.hold
        assert not plan.hold_clear and not plan.breaker_clear and not plan.referral_clear
        assert service.directory_reconcile_hold == held_message
        assert await _open_alerts(store) == {REFERRAL, HELD}
