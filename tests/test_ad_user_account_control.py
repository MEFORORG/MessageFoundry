# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1639: an unreadable ``userAccountControl`` is refused, on login and in the reconciler.

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

import logging
import re
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import LdapAuthenticator, _account_enabled
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

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

        def __exit__(self, *exc: object) -> bool:
            return False

        def search(self, **kwargs: Any) -> bool:
            self.entries = directory.lookup(str(kwargs["search_filter"]))
            return True

        def bind(self) -> bool:
            return True  # every password is right: the refusal under test is the lookup's

        def unbind(self) -> None:
            pass

    monkeypatch.setattr(ldap3, "Server", FakeServer)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)


def _settings() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="OU=Staff,DC=test,DC=invalid",
        ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        ad_bind_password="synthetic",
        ad_session_recheck_seconds=60,
    )


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


@asynccontextmanager
async def _signed_in_estate(
    monkeypatch: pytest.MonkeyPatch, names: list[str]
) -> AsyncIterator[tuple[_Directory, AuthService, MessageStore, dict[str, str]]]:
    """Every account in ``names`` enabled and holding one live AD session.

    Each session is minted through the shared tail of the surviving AD login paths, from a principal
    the REAL authenticator resolved, so every row carries the id the id-keyed probe will ask about.
    """
    directory = _Directory(names)
    _install_directory(monkeypatch, directory)
    auth = LdapAuthenticator(_settings())
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, _settings(), ldap=auth)
        await service.initialize()
        tokens: dict[str, str] = {}
        for name in names:
            principal = auth.resolve_principal(name)
            assert principal is not None
            login = await service._complete_ad_login(principal, None, mfa_verified=True)
            tokens[name] = login.token
        yield directory, service, store, tokens
    finally:
        await store.close()


@pytest.mark.parametrize(("uac", "shape"), REFUSED)
async def test_the_reconciler_revokes_an_account_whose_disabled_bit_is_set_or_undetermined(
    monkeypatch: pytest.MonkeyPatch, uac: Any, shape: str | None
) -> None:
    """One undetermined account among enabled ones: it reads ABSENT, strikes, and is revoked at the
    strike threshold -- exactly as a disabled one is. Before #1639 it read PRESENT and kept its
    session to the absolute cap."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith", "bwong"]) as estate:
        directory, service, _store, tokens = estate
        directory.uac["jdoe"] = uac
        first = await service.reconcile_directory_sessions()
        assert first.revocations == ()  # strike 1: one ambiguous answer never revokes
        assert sorted(first.strikes.values()) == [0, 0, 1]  # only the undetermined account struck
        second = await service.reconcile_directory_sessions()
        assert second.aborted is None
        assert [(r.username, r.reason) for r in second.revocations] == [
            ("jdoe", "directory_absent")
        ]
        for name, token in tokens.items():
            assert (await service.identity_for_token(token) is None) is (name == "jdoe")
        assert ldap_module._uac_shapes_warned == (set() if shape is None else {shape})


@pytest.mark.parametrize("uac", [ABSENT, NON_NUMERIC], ids=["absent", "non-numeric"])
async def test_a_bind_account_that_cannot_read_the_attribute_trips_the_breaker(
    monkeypatch: pytest.MonkeyPatch, uac: Any
) -> None:
    """THE RISK THE FIX CREATES, and the control that absorbs it. A bind account without read
    rights on ``userAccountControl`` makes EVERY account undetermined at once. That wave must reach
    the existing mass-revoke breaker, which aborts the pass, and must not sign the estate out."""
    names = [f"user{i:02d}" for i in range(12)]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, store, tokens):
        directory.uac = dict.fromkeys(names, uac)  # the bind account loses the read right
        first = await service.reconcile_directory_sessions()
        assert first.aborted is None and first.revocations == ()  # strike 1: nothing to abort yet
        for _ in range(3):  # from strike 2 on, the breaker holds pass after pass
            plan = await service.reconcile_directory_sessions()
            assert plan.aborted == "mass_revoke_breaker"
            assert plan.revocations == ()

        for token in tokens.values():
            assert await service.identity_for_token(token) is not None
        assert service.directory_reconcile_alert is not None
        assert not any(a["action"] == "auth.ad_session_revoked" for a in await store.list_audit())


async def test_below_the_breaker_floor_the_same_wave_revokes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The breaker's absolute floor (``ad_session_revoke_max``, 5) is an AND with the fraction, so
    an estate that small is signed out by the same wave. That is the breaker's documented design --
    it cannot tell five genuine offboardings from five unreadable entries -- and the fail-closed
    answer here: those principals can no longer sign in either. Pinned so it is a stated arm."""
    names = ["jdoe", "asmith", "bwong"]
    async with _signed_in_estate(monkeypatch, names) as (directory, service, _store, tokens):
        directory.uac = dict.fromkeys(names, ABSENT)
        await service.reconcile_directory_sessions()
        plan = await service.reconcile_directory_sessions()
        assert plan.aborted is None
        assert sorted(r.username for r in plan.revocations) == sorted(names)
        for token in tokens.values():
            assert await service.identity_for_token(token) is None
