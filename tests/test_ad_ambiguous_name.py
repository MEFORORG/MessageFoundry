# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2778: a name that matches two directory accounts signs in as neither.

The name-keyed lookup filters on ``sAMAccountName`` OR ``userPrincipalName``. A directory may give
account V the UPN ``victor@<domain>`` and account X the ``sAMAccountName`` ``victor``; the filter for
``victor`` then matches both. The lookup used to take ``entries[0]``, so the server's result order
chose which account the Kerberos sign-in landed on.

**Not exercised: a real directory.** No test here reaches a domain controller, and nobody has
confirmed on a test domain that one returns both entries for that filter. The doubles below return
two entries by construction; what this pins is that the engine refuses them. Synthetic names only.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import DirectoryAnswer, LdapAuthenticator
from messagefoundry.config.settings import AuthSettings
from messagefoundry.redaction import safe_name


class _Attr:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else [value]


class _Entry:
    def __init__(self, sam: str, dn: str) -> None:
        self.entry_dn = dn
        self._attrs = {
            "sAMAccountName": _Attr(sam),
            "userAccountControl": _Attr("512"),  # a normal enabled account
            "memberOf": _Attr([]),
        }

    def __contains__(self, name: str) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> _Attr:
        return self._attrs[name]


#: X, whose sAMAccountName is the name asked for, and V, whose UPN prefix is.
_X = _Entry("victor", "CN=X,DC=x")
_V = _Entry("vsmith", "CN=V,DC=x")


class _Conn:
    def __init__(self, entries: list[_Entry]) -> None:
        self.entries = entries
        self.result: dict[str, Any] | None = None  # no referral

    def search(self, **kwargs: Any) -> bool:
        return True


def _settings(**over: Any) -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        ad_domain="example.org",
        **over,
    )


def _authenticator() -> LdapAuthenticator:
    return LdapAuthenticator(_settings())


@pytest.fixture(autouse=True)
def _fresh_warning_latch(monkeypatch: pytest.MonkeyPatch) -> None:
    """The warning is once per name per process; give each test an empty latch."""
    monkeypatch.setattr(ldap_module, "_object_guid_shapes_warned", set())


def test_two_entries_for_one_name_are_refused_and_logged_without_the_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    auth = _authenticator()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        found = auth._lookup_by_name(_Conn([_X, _V]), "victor")
        # Repeats at sign-in rate do not repeat the line; a different name does get its own.
        auth._lookup_by_name(_Conn([_X, _V]), "victor")
        auth._lookup_by_name(_Conn([_X, _V]), "other")
    assert found.answer is DirectoryAnswer.AMBIGUOUS and found.info is None
    records = [r for r in caplog.records if r.name == "messagefoundry.auth.ldap"]
    assert len(records) == 2 and all(r.levelno == logging.WARNING for r in records)
    message = records[0].getMessage()
    assert safe_name("victor") in message and "matched 2 directory entries" in message
    # The label stands in for the name; neither account's name nor DN reaches the log.
    for raw in ("victor", "vsmith", "CN=X", "CN=V"):
        assert raw not in message.replace(safe_name("victor"), "")


def test_the_reconciler_reads_an_ambiguous_answer_as_absent() -> None:
    """Fail closed: no entry is provably the account, so its sessions end after the strikes."""
    from messagefoundry.auth import reconcile
    from messagefoundry.auth.service import _REFUSED_OUTCOMES

    assert _REFUSED_OUTCOMES[DirectoryAnswer.AMBIGUOUS] is reconcile.ProbeOutcome.ABSENT


def test_every_refused_answer_has_a_reconcile_outcome_and_a_re_bind_reason() -> None:
    """Both tables are indexed by whatever answer the lookup gave, so a member missing from either
    is a KeyError on that path, not a refusal. AMBIGUOUS reaches the step-up re-bind too: its
    id-keyed search shares ``_search_user`` with the name-keyed one."""
    from messagefoundry.auth.service import _REBIND_REFUSALS, _REFUSED_OUTCOMES

    refused = set(DirectoryAnswer) - {DirectoryAnswer.FOUND}
    assert set(_REFUSED_OUTCOMES) == refused
    assert set(_REBIND_REFUSALS) == refused | {None}
    assert _REBIND_REFUSALS[DirectoryAnswer.AMBIGUOUS] == "not_in_directory"


def test_one_entry_for_the_name_still_resolves() -> None:
    """Paired control: the same double with one entry is FOUND, so the refusal above is the count."""
    found = _authenticator()._lookup_by_name(_Conn([_X]), "victor")
    assert found.answer is DirectoryAnswer.FOUND
    assert found.info is not None and found.info["dn"] == "CN=X,DC=x"


def _install_directory(
    monkeypatch: pytest.MonkeyPatch, binds: list[str], answer: list[_Entry] | None = None
) -> None:
    """Every search answers ``answer`` (both entries by default); ``binds`` collects each bind's
    DN. The list is read at each search, so a test may change it between sign-ins."""
    import ldap3

    class FakeServer:
        def __init__(self, host: Any = None, **kwargs: Any) -> None: ...

    class FakeConnection(_Conn):
        def __init__(self, server: Any = None, **kwargs: Any) -> None:
            super().__init__([])
            self.user = str(kwargs.get("user"))

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def search(self, **kwargs: Any) -> bool:
            self.entries = list(answer) if answer is not None else [_X, _V]
            return True

        def bind(self) -> bool:
            binds.append(self.user)
            return True

        def unbind(self) -> None: ...

    monkeypatch.setattr(ldap3, "Server", FakeServer)
    monkeypatch.setattr(ldap3, "Connection", FakeConnection)


def test_the_kerberos_lookup_resolves_no_principal(monkeypatch: pytest.MonkeyPatch) -> None:
    """``resolve_principal`` with no object id is what the Kerberos sign-in calls."""
    _install_directory(monkeypatch, [])
    auth = _authenticator()
    assert auth.resolve_principal("victor") is None
    assert auth.probe_principal("victor").answer is DirectoryAnswer.AMBIGUOUS


def test_the_password_is_never_bound_as_either_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """The password leg refuses too, and its only user bind is the timing equalizer's decoy DN.

    ``authenticate`` returns a :class:`DirectoryBind` since BACKLOG #2434: refused means no
    principal, and the answer says the lookup was ambiguous rather than that a bind was judged."""
    binds: list[str] = []
    _install_directory(monkeypatch, binds)
    bound = _authenticator().authenticate("victor", "a-typed-password")
    assert bound.principal is None
    assert bound.answer is DirectoryAnswer.AMBIGUOUS
    assert "CN=X,DC=x" not in binds and "CN=V,DC=x" not in binds
    assert any("mf-nonexistent-timing-equalizer" in dn for dn in binds)


# --- vault BACKLOG #3228: the account's stored objectGUID picks among the matches ---------------

_GUID_X = uuid.UUID("0b8f6c2e-1d3a-4c5b-9e7f-102030405060")
_GUID_V = uuid.UUID("9a1b2c3d-4e5f-4a6b-8c7d-0e1f20314253")
_GUID_NEITHER = uuid.UUID("5d6e7f80-9a0b-4c1d-8e2f-a0b1c2d3e4f5")


def _carrying(entry: _Entry, guid: uuid.UUID, *groups: str) -> _Entry:
    """A copy of ``entry`` carrying ``guid`` as the 16 little-endian bytes a directory sends.

    Bytes rather than text, so a test that passes shows the stored text form and the wire form
    compare through :func:`~messagefoundry.auth.ldap.normalise_object_guid`."""
    out = _Entry(entry["sAMAccountName"].value, entry.entry_dn)
    out._attrs["objectGUID"] = _Attr(guid.bytes_le)
    out._attrs["memberOf"] = _Attr(list(groups))
    return out


def test_a_stored_object_id_picks_the_entry_that_carries_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """X, which holds the name, is chosen by its id in either result order and either spelling."""
    x, v = _carrying(_X, _GUID_X), _carrying(_V, _GUID_V)
    auth = _authenticator()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        for stored in (str(_GUID_X), "{" + str(_GUID_X).upper() + "}"):
            for order in ([x, v], [v, x]):
                found = auth._lookup_by_name(_Conn(order), "victor", tie_break_object_id=stored)
                assert found.answer is DirectoryAnswer.FOUND, (stored, order)
                assert found.info is not None and found.info["dn"] == "CN=X,DC=x"
                assert found.info["object_id"] == str(_GUID_X)
    # The collision is still reported, once per name, and still without the name or either DN.
    records = [r for r in caplog.records if r.name == "messagefoundry.auth.ldap"]
    assert len(records) == 1 and "using the one carrying" in records[0].getMessage()
    message = records[0].getMessage().replace(safe_name("victor"), "")
    for raw in ("victor", "vsmith", "CN=X", "CN=V", str(_GUID_X), str(_GUID_V)):
        assert raw not in message


def test_with_no_stored_object_id_two_entries_are_still_refused() -> None:
    """The caller holds no id, so nothing tells the entries apart. The second case pins that an
    entry with no readable id is not "matched" by a caller holding none."""
    auth = _authenticator()
    for entries in (
        [_carrying(_X, _GUID_X), _carrying(_V, _GUID_V)],
        [_carrying(_X, _GUID_X), _V],
    ):
        found = auth._lookup_by_name(_Conn(entries), "victor")
        assert found.answer is DirectoryAnswer.AMBIGUOUS and found.info is None


def test_both_id_keys_at_once_are_refused() -> None:
    """An id-keyed search has no tie to break, so a caller passing both made a mistake."""
    with pytest.raises(ValueError, match="not both"):
        _authenticator().probe_principal(
            "victor", object_id=str(_GUID_X), tie_break_object_id=str(_GUID_X)
        )


def test_two_entries_carrying_the_stored_object_id_are_refused() -> None:
    """An id is meant to name one object. Two entries reading it back prove neither is the account,
    even when only one of them holds the name."""
    conn = _Conn([_carrying(_X, _GUID_X), _carrying(_V, _GUID_X)])
    found = _authenticator()._lookup_by_name(conn, "victor", tie_break_object_id=str(_GUID_X))
    assert found.answer is DirectoryAnswer.AMBIGUOUS and found.info is None


def test_two_entries_holding_the_name_are_refused_whatever_the_stored_id() -> None:
    """Same-named accounts in two domains under one search base. The ticket's realm is dropped
    before the lookup, so it cannot say which one signed in, and the row's id must not choose."""
    other_domain = _carrying(_Entry("victor", "CN=victor,DC=y"), _GUID_V)
    conn = _Conn([_carrying(_X, _GUID_X), other_domain])
    found = _authenticator()._lookup_by_name(conn, "victor", tie_break_object_id=str(_GUID_X))
    assert found.answer is DirectoryAnswer.AMBIGUOUS and found.info is None


def test_a_stored_object_id_matching_neither_entry_is_refused() -> None:
    """The account's own entry is not among the matches, so neither match may stand in for it. An
    entry with no ``objectGUID`` at all matches no stored id either."""
    auth = _authenticator()
    for entries in (
        [_carrying(_X, _GUID_X), _carrying(_V, _GUID_V)],
        [_carrying(_X, _GUID_X), _V],
    ):
        found = auth._lookup_by_name(
            _Conn(entries), "victor", tie_break_object_id=str(_GUID_NEITHER)
        )
        assert found.answer is DirectoryAnswer.AMBIGUOUS and found.info is None


def test_a_stored_object_id_on_an_entry_matched_only_by_its_upn_is_refused() -> None:
    """The recycle case. V was ``victor``, was renamed ``vsmith`` and kept the UPN, and the name went
    to X. The row still holds V's id, but X holds the ticket's name, so choosing V would sign X in as
    V. Refused, as before #3228."""
    conn = _Conn([_carrying(_X, _GUID_X), _carrying(_V, _GUID_V)])
    found = _authenticator()._lookup_by_name(conn, "victor", tie_break_object_id=str(_GUID_V))
    assert found.answer is DirectoryAnswer.AMBIGUOUS and found.info is None


def test_the_name_check_ignores_case() -> None:
    """``sAMAccountName`` compares without case in AD, so a ticket's spelling does not matter."""
    conn = _Conn([_carrying(_X, _GUID_X), _carrying(_V, _GUID_V)])
    found = _authenticator()._lookup_by_name(conn, "VICTOR", tie_break_object_id=str(_GUID_X))
    assert found.answer is DirectoryAnswer.FOUND
    assert found.info is not None and found.info["dn"] == "CN=X,DC=x"


def test_a_stored_object_id_that_cannot_be_read_breaks_no_tie() -> None:
    conn = _Conn([_carrying(_X, _GUID_X), _carrying(_V, _GUID_V)])
    found = _authenticator()._lookup_by_name(conn, "victor", tie_break_object_id="not-a-guid")
    assert found.answer is DirectoryAnswer.AMBIGUOUS


def test_a_stored_object_id_does_not_change_a_single_match() -> None:
    """Paired control: one match is answered as before. The sign-in's own identity check refuses
    an entry whose id is not the row's (BACKLOG #1471); this lookup does not take that over."""
    conn = _Conn([_carrying(_X, _GUID_X)])
    found = _authenticator()._lookup_by_name(conn, "victor", tie_break_object_id=str(_GUID_V))
    assert found.answer is DirectoryAnswer.FOUND
    assert found.info is not None and found.info["dn"] == "CN=X,DC=x"


async def test_windows_sso_signs_a_bound_account_in_past_a_colliding_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """RED without #3228: the sign-in after the collision is refused as ``not_in_directory``.

    The real ``LdapAuthenticator`` over a faked ``ldap3``; only the SPNEGO acceptor is replaced. The
    first sign-in finds X alone, and the row it creates is bound to X's id. Then V's UPN collides
    with the name. The sign-in must land on X's row, the one the engine already holds, and a
    ticket for a name with no row must still be refused."""
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store.store import MessageStore

    async def _no_pad(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_pad)
    ticket = {"name": "victor"}
    monkeypatch.setattr(
        "messagefoundry.auth.service.kerberos_principal", lambda _t, _s: ticket["name"]
    )
    group = "CN=mf-ops,DC=x"
    answer = [_carrying(_X, _GUID_X, group)]
    _install_directory(monkeypatch, [], answer)
    store = await MessageStore.open(tmp_path / "tie-break.db")
    try:
        settings = _settings(kerberos_enabled=True)
        service = AuthService(store, settings, ldap=LdapAuthenticator(settings))
        await service.initialize()
        await service.set_ad_group_map([(group.lower(), "operator")], actor="admin")

        first = await service.authenticate_kerberos(b"spnego-token")
        assert first.ok, first.error
        row = await store.get_user_by_username("victor")
        assert row is not None and row.directory_object_id == str(_GUID_X)

        answer.append(_carrying(_V, _GUID_V, group))
        again = await service.authenticate_kerberos(b"spnego-token")
        assert again.ok, again.error
        assert again.identity is not None and again.identity.user_id == row.id

        # Control: the same two entries, for a name no row holds, are still refused.
        ticket["name"] = "vsmith-alias"
        refused = await service.authenticate_kerberos(b"spnego-token")
        assert not refused.ok
    finally:
        await store.close()


async def test_an_edited_row_on_a_keyed_store_breaks_no_tie(tmp_path: Path) -> None:
    """BACKLOG #2592 with #3228: on a keyed store, a directory row whose objectGUID was edited
    outside the engine fails its seal, so it gives the tie-break no id."""
    import sqlite3

    from messagefoundry.auth.identity import AuthProvider
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store.crypto import generate_key, make_cipher
    from messagefoundry.store.store import MessageStore

    path = tmp_path / "sealed.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        service = AuthService(store, _settings(kerberos_enabled=True), ldap=_authenticator())
        await service.initialize()
        await store.create_user(
            user_id=uuid.uuid4().hex,
            username="victor",
            auth_provider=AuthProvider.AD.value,
            directory_object_id=str(_GUID_V),
            password_generated=False,
        )
        assert await service._stored_directory_object_id("victor") == str(_GUID_V)

        # Point the row at another entry, on a connection that holds no store key.
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                "UPDATE users SET directory_object_id = ? WHERE username = ?",
                (str(_GUID_X), "victor"),
            )
            conn.commit()
        finally:
            conn.close()
        assert await service._stored_directory_object_id("victor") is None
    finally:
        await store.close()


async def test_a_like_named_local_row_breaks_no_tie(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Only a directory row's id steers the lookup. A local row carrying an id is ignored, and
    the id is read through the sealed loader (BACKLOG #2592), never the raw store reader. The
    real seal check is the next test."""
    from types import SimpleNamespace

    from messagefoundry.auth.identity import AuthProvider
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store.store import MessageStore

    store = await MessageStore.open(tmp_path / "local-row.db")
    try:
        service = AuthService(store, _settings(kerberos_enabled=True), ldap=_authenticator())
        await service.initialize()
        current: SimpleNamespace | None = SimpleNamespace(
            auth_provider=AuthProvider.AD.value, directory_object_id=str(_GUID_X)
        )

        async def _row(_name: str) -> Any:
            return current

        monkeypatch.setattr(service, "_load_user_by_username", _row)
        assert await service._stored_directory_object_id("victor") == str(_GUID_X)
        current = SimpleNamespace(
            auth_provider=AuthProvider.LOCAL.value, directory_object_id=str(_GUID_X)
        )
        assert await service._stored_directory_object_id("victor") is None
        # The loader answers None, so a row the raw store still holds gives no id.
        current = None
        raw = SimpleNamespace(auth_provider=AuthProvider.AD.value, directory_object_id=str(_GUID_X))

        async def _raw_row(_name: str) -> Any:
            return raw

        monkeypatch.setattr(store, "get_user_by_username", _raw_row)
        assert await service._stored_directory_object_id("victor") is None
    finally:
        await store.close()
