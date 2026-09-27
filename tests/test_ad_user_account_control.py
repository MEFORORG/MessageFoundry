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

import json
import logging
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.api.app import _alert_reconcile_plan
from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import DirectoryAnswer, LdapAuthenticator, _account_enabled
from messagefoundry.auth.reconcile import HOLD_REASON, ReconcilePlan
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.store.store import MessageStore
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

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def search(self, **kwargs: Any) -> bool:
            if directory.down:
                raise ldap3.core.exceptions.LDAPSocketOpenError("synthetic: DC unreachable")
            self.entries = directory.lookup(str(kwargs["search_filter"]))
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


async def _pass(service: AuthService, sink: _Sink | None = None) -> ReconcilePlan:
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
