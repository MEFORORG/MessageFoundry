# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4846: a Kerberos ticket resolves only to the account it proves.

``kerberos_principal`` checks a ticket's realm against ``[auth].kerberos_realm`` and drops it
(BACKLOG #2610). The directory lookup that followed was the password path's name lookup, so
in the shipped code:

* under a forest-wide base or the global catalog, ``alice@CORP.EXAMPLE`` would resolve to the
  CHILD domain's ``alice`` when the root held none, and be refused as ambiguous when both did;
* a single entry holding only the UPN ``alice@<ad_domain>``, under another ``sAMAccountName``,
  would answer a ticket for ``alice``;
* a machine's ticket (``WS01$``) or a trust account's (``CHILD$``) was looked up like a person's.

Pinned here, each with a control showing the name-keyed lookup the other callers keep still
answers the old way, so the difference is the Kerberos lookup and not the doubles.

**Not exercised: a real directory.** The doubles return entries by construction and do not
evaluate the LDAP filter, so the ``objectCategory``/``objectClass`` clauses are pinned by reading
the filter sent, not by a domain controller answering it. Synthetic names only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import spnego

from messagefoundry.auth import ldap as ldap_mod
from messagefoundry.auth.ldap import DirectoryAnswer, LdapAuthenticator, LdapError, _Lookup
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore


class _Attr:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.values = value if isinstance(value, list) else [value]


class _Entry:
    def __init__(self, sam: str | None, dn: str) -> None:
        self.entry_dn = dn
        self._attrs = {"userAccountControl": _Attr("512"), "memberOf": _Attr([])}
        if sam is not None:
            self._attrs["sAMAccountName"] = _Attr(sam)

    def __contains__(self, name: str) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> _Attr:
        return self._attrs[name]


class _Conn:
    """Answers every search with ``entries`` and records each search's filter."""

    def __init__(self, entries: list[_Entry]) -> None:
        self.entries = entries
        self.result: dict[str, Any] | None = None  # no referral
        self.filters: list[str] = []

    def search(self, **kwargs: Any) -> bool:
        self.filters.append(kwargs["search_filter"])
        return True


_ROOT_ALICE = _Entry("alice", "CN=Alice Root,OU=Staff,DC=corp,DC=example")
_CHILD_ALICE = _Entry("alice", "CN=Alice Child,OU=Staff,DC=child,DC=corp,DC=example")
#: Holds the UPN alice@corp.example under another sAMAccountName, as a renamed account may.
_UPN_ONLY = _Entry("asmith", "CN=A Smith,OU=Staff,DC=corp,DC=example")


_REALM = "CORP.EXAMPLE"


def _authenticator() -> LdapAuthenticator:
    return LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://dc.test.invalid",
            ad_user_search_base="DC=corp,DC=example",
            ad_bind_dn="CN=svc,DC=corp,DC=example",
            ad_bind_password="synthetic",
            ad_domain="corp.example",
        )
    )


def _kerberos(conn: _Conn, name: str, realm: str = _REALM) -> _Lookup:
    return _authenticator()._lookup_by_name(conn, name, kerberos_realm=realm)


@pytest.fixture(autouse=True)
def _fresh_warning_latch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ldap_mod, "_object_guid_shapes_warned", set())


# --- the DN's realm -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dn", "realm"),
    [
        ("CN=a,OU=Staff,DC=child,DC=corp,DC=example", "child.corp.example"),
        ("cn=a,dc=CORP,dc=Example", "corp.example"),
        ("CN=a, DC=corp , DC=example", "corp.example"),
        # The type spelled as its name or its OID reads the same, and does not end the run.
        ("CN=a,domainComponent=corp,DC=example", "corp.example"),
        ("CN=a,0.9.2342.19200300.100.1.25=child,DC=corp,DC=example", "child.corp.example"),
        # Only the trailing run counts: a DC= above an OU adds nothing.
        ("CN=a,DC=evil,OU=x,DC=corp,DC=example", "corp.example"),
        # A multi-valued RDN ends the run.
        ("CN=a,DC=evil+OU=x,DC=corp,DC=example", "corp.example"),
        # A label holding a dot, escaped or not, is not the RDNs a domain is written as.
        ("CN=a,DC=corp.example", None),
        ("CN=a,DC=corp\\2Eexample", None),
        ("CN=a,DC=child.corp,DC=example", None),
        ("CN=a,OU=Staff,O=example", None),
        ("CN=a,DC=corp,OU=Staff", None),
        ("not a dn", None),
        ("", None),
    ],
)
def test_the_dn_realm_is_the_trailing_dc_run(dn: str, realm: str | None) -> None:
    assert ldap_mod._dn_realm(dn) == realm


def test_a_non_ascii_dc_never_equals_an_ascii_realm() -> None:
    # The Kelvin sign lowers to an ASCII k; the canonical form escapes it instead.
    assert ldap_mod._dn_realm("CN=a,DC=\N{KELVIN SIGN}orp,DC=example") != "korp.example"


def test_the_group_dn_form_is_unchanged_by_the_shared_parser() -> None:
    """The parser was split out of ``canonical_group_dn``; its answers must not move."""
    assert ldap_mod.canonical_group_dn("CN=C\\23 Developers,DC=x") == "cn=c# developers,dc=x"
    assert ldap_mod.canonical_group_dn("CN=Admins") is None  # one RDN is still refused
    assert ldap_mod._canonical_rdns("CN=Admins") == [["cn=admins"]]


# --- the cross-realm collision ------------------------------------------------------------------


def test_a_root_ticket_resolves_to_the_root_account_under_a_forest_wide_base() -> None:
    found = _kerberos(_Conn([_CHILD_ALICE, _ROOT_ALICE]), "alice")
    assert found.answer is DirectoryAnswer.FOUND
    assert found.info is not None and found.info["dn"] == _ROOT_ALICE.entry_dn


def test_a_root_ticket_never_resolves_to_a_child_account_alone() -> None:
    """The finding's probe: before the fix this answered the CHILD alice."""
    conn = _Conn([_CHILD_ALICE])
    assert _authenticator()._lookup_by_name(conn, "alice").answer is DirectoryAnswer.FOUND
    found = _kerberos(conn, "alice")
    assert found.answer is DirectoryAnswer.NOT_FOUND and found.info is None


def test_a_child_realm_resolves_to_the_child_account() -> None:
    found = _kerberos(_Conn([_ROOT_ALICE, _CHILD_ALICE]), "alice", "CHILD.CORP.EXAMPLE")
    assert found.info is not None and found.info["dn"] == _CHILD_ALICE.entry_dn


def test_the_realm_compare_ignores_ascii_case_as_the_ticket_compare_does() -> None:
    assert _kerberos(_Conn([_ROOT_ALICE]), "alice", "corp.EXAMPLE").answer is DirectoryAnswer.FOUND


def test_the_name_lookup_the_other_callers_keep_still_refuses_the_pair() -> None:
    """Control: without ``kerberos_realm`` the two same-named entries are still ambiguous."""
    found = _authenticator()._lookup_by_name(_Conn([_CHILD_ALICE, _ROOT_ALICE]), "alice")
    assert found.answer is DirectoryAnswer.AMBIGUOUS


def test_a_dropped_entry_is_logged_at_debug_by_label_and_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """DEBUG, not WARNING: under the global catalog a name held in several domains drops entries
    on every sign-in, which is routine rather than a fault to clear."""
    with caplog.at_level("DEBUG", logger="messagefoundry.auth.ldap"):
        _kerberos(_Conn([_CHILD_ALICE, _ROOT_ALICE]), "alice")
    messages = [
        r.getMessage()
        for r in caplog.records
        if r.name == "messagefoundry.auth.ldap" and r.getMessage().startswith("Kerberos lookup")
    ]
    assert len(messages) == 1 and "kept 1 of 2" in messages[0]
    assert all(r.levelname == "DEBUG" for r in caplog.records if "Kerberos lookup" in r.message)
    assert "alice" not in messages[0].lower()
    assert "child" not in messages[0].lower()


# --- the UPN-only match -------------------------------------------------------------------------


def test_a_ticket_never_resolves_to_an_entry_holding_only_the_upn() -> None:
    conn = _Conn([_UPN_ONLY])
    # Control: the password path's lookup still takes the single UPN match, as it did.
    assert _authenticator()._lookup_by_name(conn, "alice").answer is DirectoryAnswer.FOUND
    assert _kerberos(conn, "alice").answer is DirectoryAnswer.NOT_FOUND


def test_an_entry_with_no_readable_name_is_not_the_holder() -> None:
    found = _kerberos(_Conn([_Entry(None, "CN=x,DC=corp,DC=example")]), "alice")
    assert found.answer is DirectoryAnswer.NOT_FOUND


def test_the_kerberos_filter_asks_for_a_person_by_sam_account_name_only() -> None:
    conn = _Conn([_ROOT_ALICE])
    _kerberos(conn, "al*ce")
    assert conn.filters == ["(&(objectCategory=person)(objectClass=user)(sAMAccountName=al\\2ace))"]
    assert "userPrincipalName" not in conn.filters[0]


# --- machine and trust accounts, and the realm, before any session -------------------------------


class _NoSession(LdapAuthenticator):
    """Fails the test if a session is opened: these refusals need no directory."""

    def _service_session(self) -> Any:
        raise AssertionError("a directory session was opened")


def _no_session() -> _NoSession:
    return _NoSession(_authenticator()._s)


@pytest.mark.parametrize("name", ["WS01$", "CHILD$", "$"])
def test_a_dollar_name_is_not_found_without_a_session(name: str) -> None:
    probe = _no_session().probe_principal(name, kerberos_realm=_REALM)
    assert probe.answer is DirectoryAnswer.NOT_FOUND and probe.principal is None


@pytest.mark.parametrize("name", ["WS01$", "CHILD$"])
def test_the_kerberos_lookup_itself_never_searches_a_dollar_name(name: str) -> None:
    """Where the filter is built, too, so a caller that skips ``probe_principal`` is covered: a
    trust account is a person-category user the filter alone would return."""
    conn = _Conn([_Entry(name, "CN=CHILD$,CN=Users,DC=corp,DC=example")])
    assert _kerberos(conn, name).answer is DirectoryAnswer.NOT_FOUND and conn.filters == []


def test_the_kerberos_lookup_itself_refuses_an_empty_realm() -> None:
    conn = _Conn([_ROOT_ALICE])
    with pytest.raises(LdapError, match="kerberos_realm must be"):
        _kerberos(conn, "alice", "")
    assert conn.filters == []


def test_an_in_realm_entry_whose_dn_the_parser_refuses_is_dropped() -> None:
    """Fails closed: an unescaped quote is a shape the shared DN parser refuses."""
    quoted = _Entry("alice", 'CN=Alice "Al" Root,OU=Staff,DC=corp,DC=example')
    assert ldap_mod._dn_realm(str(quoted.entry_dn)) is None
    assert _kerberos(_Conn([quoted]), "alice").answer is DirectoryAnswer.NOT_FOUND


def test_the_name_lookup_the_other_callers_keep_still_searches_a_dollar_name() -> None:
    """Control: without ``kerberos_realm`` a ``$`` name is searched and found as before."""
    conn = _Conn([_Entry("WS01$", "CN=WS01,OU=Computers,DC=corp,DC=example")])
    assert _authenticator()._lookup_by_name(conn, "WS01$").answer is DirectoryAnswer.FOUND


@pytest.mark.parametrize("realm", ["", "CORP EXAMPLE", "alice@CORP.EXAMPLE"])
def test_an_empty_or_malformed_realm_raises_rather_than_dropping_the_check(realm: str) -> None:
    with pytest.raises(LdapError, match="kerberos_realm must be"):
        _no_session().probe_principal("alice", kerberos_realm=realm)


def test_kerberos_with_an_object_id_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="object_id or kerberos_realm"):
        _no_session().probe_principal("alice", object_id="x", kerberos_realm=_REALM)


# --- the service --------------------------------------------------------------------------------


class _RecordingDirectory:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def resolve_principal(self, username: str, **kwargs: object) -> Any:
        self.calls.append((username, kwargs))
        return None


async def test_the_kerberos_sign_in_asks_the_narrow_lookup_in_the_checked_realm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def no_sleep(_deadline: float) -> None:
        return None

    class _Server:
        client_principal = "alice@corp.example"
        complete = True

        def step(self, _token: bytes) -> None:
            return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    monkeypatch.setattr(spnego, "server", lambda **_: _Server())
    monkeypatch.setattr(ldap_mod, "_kerberos_capable", lambda: True)
    directory = _RecordingDirectory()
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.test.invalid",
        ad_user_search_base="DC=corp,DC=example",
        ad_bind_dn="CN=svc,DC=corp,DC=example",
        ad_bind_password="synthetic",
        kerberos_enabled=True,
        kerberos_realm=_REALM,
        login_rate_limit_enabled=False,
        require_mfa=False,
    )
    store = await MessageStore.open(tmp_path / "kerberos_realm_binding.db")
    try:
        service = AuthService(store, settings, ldap=directory)  # type: ignore[arg-type]
        await service.initialize()
        outcome = await service.authenticate_kerberos(b"token", client="192.0.2.7")
    finally:
        await store.close()
    assert not outcome.ok
    # The realm handed over is the configured one the ticket was checked against.
    assert directory.calls == [("alice", {"tie_break_object_id": None, "kerberos_realm": _REALM})]
