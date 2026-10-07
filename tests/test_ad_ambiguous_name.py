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


def _authenticator() -> LdapAuthenticator:
    return LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
            ad_domain="example.org",
        )
    )


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


def _install_directory(monkeypatch: pytest.MonkeyPatch, binds: list[str]) -> None:
    """Every search answers both entries; ``binds`` collects each bind's DN."""
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
            self.entries = [_X, _V]
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
