# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3010: a search that ends with any result code but success is the directory not
answering, never "no such entry".

ldap3 raises on none of these codes here (every connection keeps ``raise_exceptions=False``), so in
the code before this change a busy or admin-limit-exceeded search would come back with no entries.
``_search_user`` would read that as ``NOT_FOUND``, the session reconciler would read ``NOT_FOUND``
as ``ABSENT``, and after the strike threshold it would revoke a present account. The nested group
search would read the same answer as fewer groups. ``_search`` now refuses every code but success
with :class:`LdapUnansweredError`, which every caller already reads as an outage.

A follow-up rides here. The nested group search is paged, so an account in more groups than a
directory's unpaged cap would not end it with sizeLimitExceeded, a page that does not end with
success refuses the whole search, and a refused search is abandoned. A response ldap3 cannot decode,
such as a result code outside its table, is ``tests/test_ldap_decode_boundary.py``'s subject, and
the loopback server it uses lives here.

Driven at four depths: ``_search`` itself over a bare double; the REAL ``LdapAuthenticator`` over
the ldap3 doubles of ``tests/test_ad_user_account_control.py`` and ``tests/test_ldap_timeouts.py``;
the REAL ``AuthService`` reconciler and Kerberos sign-in over those; and a REAL ldap3 stack against
a loopback server, for the paging control, which no double can reproduce. Each refusal has a
control on the same doubles: success with no entries still reads absent, and still revokes.

**Not exercised:** a real domain controller. The doubles set the result dict the way ldap3 2.9.1's
synchronous strategy leaves it. Synthetic data only; nothing here touches PHI.
"""

from __future__ import annotations

import contextlib
import copy
import logging
import pickle
import socket
import threading
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import ldap3
import pytest
from ldap3.core.results import (
    RESULT_ADMIN_LIMIT_EXCEEDED,
    RESULT_BUSY,
    RESULT_INSUFFICIENT_ACCESS_RIGHTS,
    RESULT_INVALID_DN_SYNTAX,
    RESULT_NO_SUCH_OBJECT,
    RESULT_OPERATIONS_ERROR,
    RESULT_REFERRAL,
    RESULT_SIZE_LIMIT_EXCEEDED,
    RESULT_SUCCESS,
    RESULT_TIME_LIMIT_EXCEEDED,
    RESULT_UNAVAILABLE,
    RESULT_UNWILLING_TO_PERFORM,
)

from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import (
    DirectoryAnswer,
    LdapAuthenticator,
    LdapError,
    LdapReferralError,
    LdapUnansweredError,
)
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.reconcile import ProbeOutcome
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ad_user_account_control import _alive, _audited, _pass, _signed_in_estate
from tests.test_ldap_referrals import (
    _BIND_REQUEST,
    _BIND_RESPONSE,
    _SEARCH_DONE,
    _SEARCH_REQUEST,
    _read_message,
    _tlv,
)
from tests.test_ldap_timeouts import _ad_settings, _install_fakes

#: Stands for text the directory sends with a result: its diagnostic message and matched DN. It
#: must never reach an error, a log line or an audit row.
_LEAK = "CN=synthetic-leak-3010,OU=Staff,DC=test,DC=invalid"

_GROUPS = "OU=Groups,DC=test,DC=invalid"

#: A group only the nested group search returns, which the role test maps to the operator role.
_OPERATORS = f"CN=Operators,{_GROUPS}"

#: The codes the row names, and others a directory can end a search with. None is an answer.
_NOT_ANSWERS = [
    pytest.param(RESULT_BUSY, "busy", id="51-busy"),
    pytest.param(RESULT_ADMIN_LIMIT_EXCEEDED, "adminLimitExceeded", id="11-adminLimitExceeded"),
    pytest.param(RESULT_TIME_LIMIT_EXCEEDED, "timeLimitExceeded", id="3-timeLimitExceeded"),
    pytest.param(RESULT_SIZE_LIMIT_EXCEEDED, "sizeLimitExceeded", id="4-sizeLimitExceeded"),
    pytest.param(RESULT_UNAVAILABLE, "unavailable", id="52-unavailable"),
    pytest.param(RESULT_UNWILLING_TO_PERFORM, "unwillingToPerform", id="53-unwillingToPerform"),
    pytest.param(RESULT_NO_SUCH_OBJECT, "noSuchObject", id="32-noSuchObject"),
    pytest.param(RESULT_OPERATIONS_ERROR, "operationsError", id="1-operationsError"),
    pytest.param(4242, "an unknown result code", id="4242-unknown"),
]


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test sees its own once-per-process warnings."""
    monkeypatch.setattr(ldap_module, "_object_guid_shapes_warned", set())


def _result(code: object) -> dict[str, Any]:
    """A searchResDone as ldap3 leaves it in ``Connection.result``, with directory text attached."""
    return {
        "result": code,
        "description": "x",
        "message": _LEAK,
        "dn": _LEAK,
        "type": "searchResDone",
    }


def _conn(result: object, entries: list[object] | None = None) -> SimpleNamespace:
    def search(**_kw: object) -> bool:
        return False

    return SimpleNamespace(search=search, result=result, entries=entries or [])


def _answer_with(
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    *,
    when: Callable[[dict[str, Any]], bool],
    keep_entries: bool = False,
) -> None:
    """Over the ldap3 double already installed, end every search ``when`` picks with ``code``.

    The entries are dropped, as a refused search leaves them, unless ``keep_entries``: a size or
    admin limit can arrive with part of the answer."""
    base = ldap3.Connection

    class Answering(base):  # type: ignore[misc, valid-type]
        def search(self, **kwargs: Any) -> bool:
            super().search(**kwargs)
            if when(kwargs):
                self.result = _result(code)
                if not keep_entries:
                    dropped: list[Any] = []
                    self.entries = dropped
                return False
            return True

    monkeypatch.setattr(ldap3, "Connection", Answering)


def _user_search(kwargs: dict[str, Any]) -> bool:
    return "member:" not in str(kwargs["search_filter"])


def _group_search(kwargs: dict[str, Any]) -> bool:
    return "member:" in str(kwargs["search_filter"])


# --- _search: which code is an answer --------------------------------------------------------------


@pytest.mark.parametrize(("code", "name"), _NOT_ANSWERS)
@pytest.mark.parametrize("partial", [False, True], ids=["no-entries", "partial-entries"])
def test_a_search_that_did_not_end_with_success_is_refused(
    code: int, name: str, partial: bool
) -> None:
    """Refused whether or not entries came with it: a limit that cut the answer short leaves some,
    and they are not the whole answer."""
    conn = _conn(_result(code), entries=[object()] if partial else None)
    with pytest.raises(LdapUnansweredError) as refused:
        ldap_module._search(conn, "user search", search_base="OU=Staff")
    assert refused.value.code == code and refused.value.code_name == name
    message = str(refused.value)
    assert f"user search with result code {code} ({name})" in message
    assert "which is not an answer" in message
    assert _LEAK not in message
    # Every caller reads LdapError as an outage; a referral keeps its own subclass.
    assert isinstance(refused.value, LdapError)
    assert not isinstance(refused.value, LdapReferralError)


def test_success_is_the_only_answer_and_reads_on() -> None:
    """THE CONTROL: the same double ending with success raises nothing, with or without entries."""
    ldap_module._search(_conn(_result(RESULT_SUCCESS)), "user search")
    ldap_module._search(_conn(_result(RESULT_SUCCESS), [object()]), "user search")


def test_a_caller_can_name_its_own_answers() -> None:
    """The set is a parameter, for an operation such as a bind whose answers differ."""
    invalid_credentials = 49
    conn = _conn(_result(invalid_credentials))
    ldap_module._refuse_unanswered(conn, "user bind", answers=frozenset({0, invalid_credentials}))
    with pytest.raises(LdapUnansweredError):
        ldap_module._refuse_unanswered(conn, "user bind")


def test_a_referral_is_still_refused_as_a_referral() -> None:
    """The referral check runs first, so the reconciler still reads it as referred (#2538). It runs
    inside the helper, so a caller that names its own answers cannot skip it or reorder it."""
    conn = _conn({"result": RESULT_REFERRAL, "referrals": ["ldap://dc1.other.test.invalid/"]})
    with pytest.raises(LdapReferralError):
        ldap_module._search(conn, "user search")
    with pytest.raises(LdapReferralError):
        ldap_module._refuse_unanswered(conn, "user bind", answers=frozenset({RESULT_REFERRAL}))


def test_the_refusal_survives_a_copy_and_a_pickle() -> None:
    """``BaseException`` rebuilds from its args alone, so required keywords would raise here."""
    with pytest.raises(LdapUnansweredError) as refused:
        ldap_module._search(_conn(_result(RESULT_BUSY)), "user search")
    for clone in (copy.copy(refused.value), pickle.loads(pickle.dumps(refused.value))):
        assert isinstance(clone, LdapUnansweredError)
        assert (str(clone), clone.code, clone.code_name) == (
            str(refused.value),
            RESULT_BUSY,
            "busy",
        )


@pytest.mark.parametrize("raw", [None, "0", True, False, 0.0], ids=repr)
def test_a_result_code_that_is_not_an_integer_is_refused(raw: object) -> None:
    """``False == 0``, so a bool must not pass as success; nor a string or a float."""
    with pytest.raises(LdapUnansweredError, match="with no readable result code") as refused:
        ldap_module._search(_conn(_result(raw)), "group search")
    assert refused.value.code is None


def test_a_result_that_is_not_a_dict_is_let_through() -> None:
    """ldap3's synchronous strategy cannot return from a search without one; only a double can."""
    ldap_module._search(_conn(None), "user search")


def test_no_such_object_names_the_search_base() -> None:
    with pytest.raises(LdapUnansweredError, match="configured base or DN does not exist"):
        ldap_module._search(_conn(_result(RESULT_NO_SUCH_OBJECT)), "user search")
    with pytest.raises(LdapUnansweredError) as busy:
        ldap_module._search(_conn(_result(RESULT_BUSY)), "user search")
    assert "base" not in str(busy.value)


def test_the_refusal_warns_once_per_code_and_carries_no_directory_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.ldap"):
        for code in (RESULT_BUSY, RESULT_BUSY, RESULT_UNAVAILABLE, 4242, 4243):
            with pytest.raises(LdapUnansweredError):
                ldap_module._search(_conn(_result(code)), "user search")
    lines = [r.getMessage() for r in caplog.records]
    # Two unknown codes share ldap3's one name, so a directory cannot grow the warned set.
    assert len(lines) == 3, lines
    assert all(_LEAK not in line for line in lines)


# --- the real authenticator: the user search and the nested group search -------------------------


@pytest.mark.parametrize(("code", "name"), _NOT_ANSWERS)
def test_a_user_search_the_directory_did_not_answer_is_an_outage_not_an_absence(
    monkeypatch: pytest.MonkeyPatch, code: int, name: str
) -> None:
    """Closing items 1 and 2. Before the fix, ``probe_principal`` answered ``NOT_FOUND`` here,
    which the reconciler strikes, and the Kerberos lookup answered ``None``, an unknown user."""
    _install_fakes(monkeypatch)
    _answer_with(monkeypatch, code, when=_user_search)
    authenticator = LdapAuthenticator(_ad_settings())
    with pytest.raises(LdapUnansweredError, match="user search"):
        authenticator.probe_principal("alice")
    with pytest.raises(LdapUnansweredError):
        authenticator.resolve_principal("alice")
    with pytest.raises(LdapUnansweredError):
        authenticator.authenticate("alice", "synthetic-pw-3010")


def test_success_with_no_entries_still_reads_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """Closing item 3, THE CONTROL: the one result that means "no such entry" still says so."""
    _install_fakes(monkeypatch)
    _answer_with(monkeypatch, RESULT_SUCCESS, when=_user_search)
    probe = LdapAuthenticator(_ad_settings()).probe_principal("alice")
    assert probe.answer is DirectoryAnswer.NOT_FOUND


@pytest.mark.parametrize("partial", [False, True], ids=["no-entries", "partial-entries"])
def test_a_group_search_the_directory_did_not_finish_is_an_outage_not_fewer_groups(
    monkeypatch: pytest.MonkeyPatch, partial: bool
) -> None:
    """A busy or limited nested group search used to read as fewer groups, which narrows the
    account's roles. It raises on every path that resolves groups."""
    _install_fakes(monkeypatch)
    code = RESULT_SIZE_LIMIT_EXCEEDED if partial else RESULT_BUSY
    _answer_with(
        monkeypatch,
        code,
        when=_group_search,
        keep_entries=partial,
    )
    authenticator = LdapAuthenticator(_ad_settings())
    with pytest.raises(LdapUnansweredError, match="group search"):
        authenticator.probe_principal("alice")
    with pytest.raises(LdapUnansweredError, match="group search"):
        authenticator.authenticate("alice", "synthetic-pw-3010")


# --- the reconciler: no strike, no revocation ------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "partial"),
    [
        (RESULT_BUSY, False),
        (RESULT_ADMIN_LIMIT_EXCEEDED, False),
        (RESULT_NO_SUCH_OBJECT, False),
        (RESULT_SIZE_LIMIT_EXCEEDED, True),
    ],
    ids=["busy", "adminLimitExceeded", "noSuchObject", "sizeLimit-partial"],
)
async def test_a_directory_that_did_not_answer_never_revokes_a_present_account(
    monkeypatch: pytest.MonkeyPatch, code: int, partial: bool
) -> None:
    """The row's defect, end to end. One signed-in account, under the breaker's floor, whose user
    search the directory answers with ``code`` on every pass. Before the fix the user search read
    ABSENT and the account would be revoked at the strike threshold. Now each probe is unavailable
    and the session survives. The group search has its own test below, which also reads roles."""
    async with _signed_in_estate(monkeypatch, ["jdoe"]) as (_directory, service, store, tokens):
        _answer_with(monkeypatch, code, when=_user_search, keep_entries=partial)
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        assert (await service._probe_principal(user)).outcome is ProbeOutcome.UNAVAILABLE
        for _ in range(5):  # far past ad_session_recheck_strikes
            assert (await _pass(service)).revocations == ()
        assert await _alive(service, tokens) == {"jdoe"}
        assert await _audited(store, "auth.ad_session_revoked") == []


async def test_an_account_that_left_the_directory_is_still_revoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE CONTROL for the test above, on the same doubles: success with no entries strikes and
    revokes, so the fix did not stop offboarding."""
    async with _signed_in_estate(monkeypatch, ["jdoe"]) as (directory, service, store, tokens):
        directory.delete("jdoe")
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        assert (await service._probe_principal(user)).outcome is ProbeOutcome.ABSENT
        revoked = [r.username for _ in range(5) for r in (await _pass(service)).revocations]
        assert revoked == ["jdoe"]
        assert await _alive(service, tokens) == set()


async def test_a_busy_account_beside_a_departed_one_is_left_alone_while_the_other_is_revoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The partial outage: the pass is not aborted, so each probe is judged. The account whose
    search the directory did not answer keeps its session; the one that left is revoked."""
    async with _signed_in_estate(monkeypatch, ["jdoe", "asmith"]) as (
        directory,
        service,
        store,
        tokens,
    ):
        busy_id = ldap_module.object_guid_filter_value(directory.ids["jdoe"])
        assert busy_id is not None
        _answer_with(monkeypatch, RESULT_BUSY, when=lambda kw: busy_id in str(kw["search_filter"]))
        directory.delete("asmith")
        revoked = [r.username for _ in range(5) for r in (await _pass(service)).revocations]
        assert revoked == ["asmith"]
        assert await _alive(service, tokens) == {"jdoe"}


def _groups_answer(monkeypatch: pytest.MonkeyPatch, dns: list[str]) -> None:
    """Over the ldap3 double already installed, answer every nested group search with ``dns``."""
    base = ldap3.Connection

    class Grouped(base):  # type: ignore[misc, valid-type]
        def search(self, **kwargs: Any) -> bool:
            answered: bool = super().search(**kwargs)
            if _group_search(kwargs):
                self.entries = [SimpleNamespace(entry_dn=dn) for dn in dns]
            return answered

    monkeypatch.setattr(ldap3, "Connection", Grouped)


async def test_a_group_search_the_directory_did_not_finish_never_narrows_a_signed_in_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The nested group search, end to end, reading roles. One signed-in account holds the operator
    role through a group only that search returns. Read as fewer groups, as the code before #3010
    would, a busy group search would find the role withdrawn and revoke the session as
    ``roles_changed``. Now each probe is unavailable, the stored roles are not re-diffed, and the
    session survives. The control runs first, on the same doubles: readable, the directory grants
    what is stored, so a pass changes nothing."""
    async with _signed_in_estate(monkeypatch, ["jdoe"], ad_group_search_base=_GROUPS) as (
        _directory,
        service,
        store,
        tokens,
    ):
        _groups_answer(monkeypatch, [_OPERATORS])
        canonical = ldap_module.canonical_group_dn(_OPERATORS)
        assert canonical is not None
        await store.set_ad_group_role_map([(canonical, Role.OPERATOR.value)])
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await store.set_user_roles(user.id, [Role.OPERATOR.value])
        assert (await service._probe_principal(user)).outcome is ProbeOutcome.PRESENT
        assert (await _pass(service)).revocations == ()

        _answer_with(monkeypatch, RESULT_BUSY, when=_group_search)
        assert (await service._probe_principal(user)).outcome is ProbeOutcome.UNAVAILABLE
        for _ in range(5):  # far past ad_session_recheck_strikes
            assert (await _pass(service)).revocations == ()
        assert await store.get_user_role_ids(user.id) == [Role.OPERATOR.value]
        assert await _alive(service, tokens) == {"jdoe"}
        assert await _audited(store, "auth.ad_session_revoked") == []


# --- the nested group search is paged ---------------------------------------------------------------


def _page(code: int, entries: list[object], cookie: bytes | None) -> dict[str, Any]:
    """A searchResDone carrying the paged results control, as ldap3's fast decoder leaves it, with
    the page's entries under ``_entries`` for :func:`_replay`."""
    result = _result(code)
    if cookie is not None:
        value = {"size": 0, "cookie": cookie}
        result["controls"] = {ldap_module._PAGED_RESULTS_OID: {"value": value}}
    result["_entries"] = entries
    return result


def _replay(conn: Any, page: dict[str, Any], wrap: Callable[[Any], object] = lambda e: e) -> bool:
    """Leave ``conn`` as a search answered with ``page`` leaves it, each entry passed to ``wrap``."""
    result = dict(page)
    conn.entries = [wrap(e) for e in result.pop("_entries")]
    conn.result = result
    return bool(result["result"] == RESULT_SUCCESS)


_ABANDONED = _page(RESULT_SUCCESS, [], b"")
"""What a directory answers the RFC 2696 abandon with: success, no entries, an empty cookie."""


class _PagedConn:
    """A bare double that answers its n-th search with ``pages[n]``, recording each search. A search
    with a page size of zero is the abandon: it is recorded in ``abandons`` instead."""

    def __init__(
        self, pages: list[dict[str, Any]], abandon_raises: Exception | None = None
    ) -> None:
        self._pages, self._abandon_raises = pages, abandon_raises
        self.calls: list[dict[str, Any]] = []
        self.abandons: list[dict[str, Any]] = []
        self.result: dict[str, Any] | None = None
        self.entries: list[object] = []

    def search(self, **kwargs: Any) -> bool:
        if kwargs.get("paged_size") == 0:
            self.abandons.append(kwargs)
            if self._abandon_raises is not None:
                raise self._abandon_raises
            return _replay(self, _ABANDONED)
        self.calls.append(kwargs)
        return _replay(self, self._pages[min(len(self.calls), len(self._pages)) - 1])


def test_a_paged_search_reads_every_page_and_sends_each_cookie_back() -> None:
    a, b, c = object(), object(), object()
    conn = _PagedConn(
        [
            _page(RESULT_SUCCESS, [a], b"synthetic-cookie-1"),
            _page(RESULT_SUCCESS, [b], b"synthetic-cookie-2"),
            _page(RESULT_SUCCESS, [c], b""),  # an empty cookie marks the last page (RFC 2696)
        ]
    )
    assert ldap_module._search_paged(conn, "group search", search_base=_GROUPS) == [a, b, c]
    assert [call["paged_cookie"] for call in conn.calls] == [
        None,
        b"synthetic-cookie-1",
        b"synthetic-cookie-2",
    ]
    assert {call["paged_size"] for call in conn.calls} == {ldap_module._PAGE_SIZE}
    assert all(call["search_base"] == _GROUPS for call in conn.calls)
    assert conn.abandons == [], "a search that ended is not abandoned"


def test_a_directory_that_ignores_the_page_request_is_read_once() -> None:
    """The control is sent non-critical, so a directory may answer without it. That answer ended
    with success, so it is the whole answer."""
    entry = object()
    conn = _PagedConn([_page(RESULT_SUCCESS, [entry], None)])
    assert ldap_module._search_paged(conn, "group search") == [entry]
    assert len(conn.calls) == 1
    assert conn.abandons == []


def _abandoned_with(conn: _PagedConn) -> list[object]:
    """The cookie each abandon sent, after checking it repeats the paged search's own request."""
    asked = {k: v for k, v in conn.calls[0].items() if k not in ("paged_size", "paged_cookie")}
    for abandon in conn.abandons:
        assert {k: v for k, v in abandon.items() if k != "paged_cookie"} == {
            **asked,
            "paged_size": 0,
        }, "RFC 2696: the abandon is the same search with a page size of zero"
    return [abandon["paged_cookie"] for abandon in conn.abandons]


@pytest.mark.parametrize(
    ("code", "partial"),
    [(RESULT_BUSY, False), (RESULT_SIZE_LIMIT_EXCEEDED, True), (4242, False)],
    ids=["51-busy", "4-sizeLimitExceeded-partial", "4242-unknown"],
)
@pytest.mark.parametrize(
    ("refused_cookie", "abandoned_with"),
    [(b"synthetic-cookie-2", b"synthetic-cookie-2"), (None, b"synthetic-cookie-1")],
    ids=["refused-page-has-a-cookie", "refused-page-has-none"],
)
def test_a_later_page_that_did_not_end_with_success_refuses_the_whole_search(
    code: int, partial: bool, refused_cookie: bytes | None, abandoned_with: bytes
) -> None:
    """No silent truncation: the first page's entries are not returned as the whole answer. The
    search is abandoned with the newest cookie the directory sent (review finding 10)."""
    conn = _PagedConn(
        [
            _page(RESULT_SUCCESS, [object()], b"synthetic-cookie-1"),
            _page(code, [object()] if partial else [], refused_cookie),
        ]
    )
    with pytest.raises(LdapUnansweredError, match="group search") as refused:
        ldap_module._search_paged(conn, "group search", search_base=_GROUPS)
    assert refused.value.code == code
    assert len(conn.calls) == 2
    assert _abandoned_with(conn) == [abandoned_with]


def test_a_refused_first_page_is_not_abandoned() -> None:
    """The directory sent no cookie, so it holds no paging state to drop."""
    conn = _PagedConn([_page(RESULT_BUSY, [], None)])
    with pytest.raises(LdapUnansweredError, match=r"result code 51 \(busy\)"):
        ldap_module._search_paged(conn, "group search")
    assert conn.abandons == []


def test_a_later_page_answered_with_a_referral_is_refused_and_abandoned() -> None:
    referred = {**_page(10, [], None), "referrals": ["ldaps://dc9.other.invalid/DC=other"]}
    conn = _PagedConn([_page(RESULT_SUCCESS, [object()], b"synthetic-cookie-1"), referred])
    with pytest.raises(LdapReferralError):
        ldap_module._search_paged(conn, "group search")
    assert _abandoned_with(conn) == [b"synthetic-cookie-1"]


@pytest.mark.parametrize(
    "fault",
    [
        ldap3.core.exceptions.LDAPSocketReceiveError("synthetic"),
        LdapUnansweredError("synthetic", code=RESULT_BUSY, code_name="busy"),
    ],
    ids=["ldap3-error", "refused"],
)
def test_an_abandon_that_fails_leaves_the_original_refusal(
    fault: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    """Best effort: what the abandon answers, or raises, never replaces why the search failed."""
    caplog.set_level(logging.DEBUG, logger=ldap_module.__name__)
    conn = _PagedConn(
        [
            _page(RESULT_SUCCESS, [object()], b"synthetic-cookie-1"),
            _page(RESULT_BUSY, [], None),
        ],
        abandon_raises=fault,
    )
    with pytest.raises(LdapUnansweredError, match=r"result code 51 \(busy\)") as refused:
        ldap_module._search_paged(conn, "group search")
    assert refused.value is not fault
    assert len(conn.abandons) == 1
    if not isinstance(fault, LdapError):  # a refusal is warned by _search; an ldap3 error is not
        logged = [r for r in caplog.records if "abandon of a refused group search" in r.message]
        assert [r.levelname for r in logged] == ["DEBUG"]
        assert "synthetic" not in logged[0].getMessage()


def test_a_directory_that_never_stops_paging_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ldap_module, "_MAX_PAGES", 3)
    conn = _PagedConn([_page(RESULT_SUCCESS, [object()], b"synthetic-again")])
    with pytest.raises(LdapUnansweredError, match="still paging after 3 pages") as refused:
        ldap_module._search_paged(conn, "group search", search_base=_GROUPS)
    assert len(conn.calls) == 3
    assert (refused.value.code, refused.value.code_name) == (None, "too many pages")
    assert _abandoned_with(conn) == [b"synthetic-again"]


_UNREADABLE_CONTROLS = [
    pytest.param(None, id="no-result"),
    pytest.param({"result": 0}, id="no-controls"),
    pytest.param({"result": 0, "controls": None}, id="controls-none"),
    pytest.param(
        {"result": 0, "controls": {ldap_module._PAGED_RESULTS_OID: None}}, id="control-none"
    ),
    pytest.param(
        {"result": 0, "controls": {ldap_module._PAGED_RESULTS_OID: {"value": {"cookie": "x"}}}},
        id="cookie-not-bytes",
    ),
]


@pytest.mark.parametrize("result", _UNREADABLE_CONTROLS)
def test_a_control_that_is_absent_or_unreadable_reads_as_none(result: object) -> None:
    assert ldap_module._paged_cookie(SimpleNamespace(result=result)) is None


def test_an_empty_cookie_reads_as_the_last_page_not_as_no_control() -> None:
    conn = _PagedConn([_page(RESULT_SUCCESS, [], b"")])
    conn.search()
    assert ldap_module._paged_cookie(conn) == b""


@pytest.mark.parametrize("result", _UNREADABLE_CONTROLS[1:])
def test_a_later_page_that_drops_the_paging_control_refuses_the_whole_search(
    result: dict[str, Any],
) -> None:
    """The directory was paging, so a page that does not say whether it is the last cannot be
    read as the last: the pages read so far are not the whole answer."""
    later = {**result, "_entries": [object()]}
    conn = _PagedConn([_page(RESULT_SUCCESS, [object()], b"synthetic-cookie-1"), later])
    with pytest.raises(LdapUnansweredError, match="dropped the paging control") as refused:
        ldap_module._search_paged(conn, "group search")
    assert (refused.value.code, refused.value.code_name) == (None, "paging control lost")
    assert len(conn.calls) == 2
    assert _abandoned_with(conn) == [b"synthetic-cookie-1"]


def _paged_groups(
    monkeypatch: pytest.MonkeyPatch,
    pages: list[dict[str, Any]],
    abandons: list[object] | None = None,
) -> list[object]:
    """Over the ``_install_fakes`` doubles, answer the n-th group search with ``pages[n]``. Returns
    the cookies each group search sent. An abandon (a page size of zero) is answered with success,
    and its cookie goes to ``abandons`` instead."""
    base = ldap3.Connection
    sent: list[object] = []

    class Paging(base):  # type: ignore[misc, valid-type]
        def search(self, **kwargs: Any) -> bool:
            answered: bool = super().search(**kwargs)
            if not _group_search(kwargs):
                return answered
            if kwargs.get("paged_size") == 0:
                if abandons is not None:
                    abandons.append(kwargs.get("paged_cookie"))
                return _replay(self, _ABANDONED)
            sent.append(kwargs.get("paged_cookie"))
            return _replay(self, pages[len(sent) - 1], lambda dn: SimpleNamespace(entry_dn=dn))

    monkeypatch.setattr(ldap3, "Connection", Paging)
    return sent


def _group_dn(n: int) -> str:
    return f"CN=Synthetic Group {n},OU=Groups,DC=example,DC=com"


def test_an_account_in_more_groups_than_one_page_resolves_every_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unpaged, a directory that caps a search would end this one with sizeLimitExceeded, which
    the refusal turns into a failed sign-in. Paged, every page is read."""
    _install_fakes(monkeypatch)
    sent = _paged_groups(
        monkeypatch,
        [
            _page(RESULT_SUCCESS, [_group_dn(1), _group_dn(2)], b"synthetic-cookie-1"),
            _page(RESULT_SUCCESS, [_group_dn(3)], b""),
        ],
    )
    principal = LdapAuthenticator(_ad_settings()).authenticate("alice", "synthetic-pw").principal
    assert principal is not None
    for n in (1, 2, 3):
        assert ldap_module.canonical_group_dn(_group_dn(n)) in principal.groups
    assert sent == [None, b"synthetic-cookie-1"]


def test_a_busy_later_page_refuses_the_sign_in_rather_than_dropping_its_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fakes(monkeypatch)
    abandons: list[object] = []
    _paged_groups(
        monkeypatch,
        [
            _page(RESULT_SUCCESS, [_group_dn(1)], b"synthetic-cookie-1"),
            _page(RESULT_BUSY, [], None),
        ],
        abandons,
    )
    with pytest.raises(LdapUnansweredError, match=r"group search with result code 51 \(busy\)"):
        LdapAuthenticator(_ad_settings()).authenticate("alice", "synthetic-pw")
    assert abandons == [b"synthetic-cookie-1"]


# --- through a real ldap3 stack: the paging control ----------------------------------------------

_IN_CHAIN = b"1.2.840.113556.1.4.1941"  # the nested group search's matching rule, on the wire

_USER_DN = "CN=alice,OU=Users,DC=example,DC=com"

#: RFC 4511 ExtendedRequest and ExtendedResponse, [APPLICATION 23] and [APPLICATION 24].
_EXTENDED_REQUEST, _EXTENDED_RESPONSE = 0x77, 0x78

#: One message a loopback server sends: its protocolOp, and its controls (empty for none).
_Reply = tuple[bytes, bytes]


def _enumerated(code: int) -> bytes:
    """A non-negative resultCode as BER ENUMERATED content, two's complement, minimal.
    ``tests/test_ldap_referrals.py``'s ``_ldap_result`` writes one byte, so it cannot carry 4242."""
    return code.to_bytes(max(1, (code.bit_length() + 8) // 8), "big")


def _done(code: int, cookie: bytes | None = None, *, tag: int = _SEARCH_DONE) -> _Reply:
    """An LDAPResult with ``code``, and the paged results control when ``cookie`` is given."""
    op = _tlv(tag, _tlv(0x0A, _enumerated(code)) + _tlv(0x04, b"") + _tlv(0x04, b""))
    if cookie is None:
        return op, b""
    value = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x04, cookie))
    control = _tlv(0x30, _tlv(0x04, ldap_module._PAGED_RESULTS_OID.encode()) + _tlv(0x04, value))
    return op, _tlv(0xA0, control)


def _entry(dn: str) -> _Reply:
    return _tlv(0x64, _tlv(0x04, dn.encode()) + _tlv(0x30, b"")), b""


class _ScriptedDc:
    """A loopback LDAP server, after ``tests/test_ldap_referrals.py``'s ``_FakeDc``. A bind is
    answered by ``bind_reply(raw request)``, or with success where that is absent or returns
    ``None``; an extended operation such as Who am I is answered with ``extended_reply``, or ends
    with ``extended_code``; each search is answered by ``answer(raw request)``. ``searches`` holds every search request's bytes, and
    ``ended`` is set when a client's socket closes."""

    def __init__(
        self,
        answer: Callable[[bytes], list[_Reply]],
        extended_code: int,
        bind_reply: Callable[[bytes], _Reply | None] | None = None,
        extended_reply: _Reply | None = None,
    ) -> None:
        self._answer, self._extended_code, self._bind_reply = answer, extended_code, bind_reply
        self._extended_reply = extended_reply
        self.searches: list[bytes] = []
        self.ended = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                sock, _addr = self._listener.accept()
            except OSError:
                return  # the listener was closed
            threading.Thread(target=self._session, args=(sock,), daemon=True).start()

    def _session(self, sock: socket.socket) -> None:
        try:
            with sock, contextlib.suppress(OSError):
                sock.settimeout(10)
                while (message := _read_message(sock)) is not None:
                    raw, body = message
                    message_id = body[: 2 + body[1]]  # the messageID INTEGER, echoed verbatim
                    op = body[2 + body[1]]
                    if op == _BIND_REQUEST:
                        scripted = self._bind_reply(raw) if self._bind_reply else None
                        replies = [scripted or _done(RESULT_SUCCESS, tag=_BIND_RESPONSE)]
                    elif op == _EXTENDED_REQUEST:
                        replies = [
                            self._extended_reply
                            or _done(self._extended_code, tag=_EXTENDED_RESPONSE)
                        ]
                    elif op == _SEARCH_REQUEST:
                        self.searches.append(raw)
                        replies = self._answer(raw)
                    else:  # unbind, or anything this server does not speak
                        return
                    for reply, controls in replies:
                        sock.sendall(_tlv(0x30, message_id + reply + controls))
        finally:
            self.ended.set()

    def close(self) -> None:
        # shutdown wakes a blocked accept() on Linux, where close() alone does not.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()


@contextlib.contextmanager
def _scripted_dc(
    answer: Callable[[bytes], list[_Reply]],
    *,
    extended_code: int = RESULT_SUCCESS,
    bind_reply: Callable[[bytes], _Reply | None] | None = None,
    extended_reply: _Reply | None = None,
) -> Iterator[tuple[_ScriptedDc, LdapAuthenticator]]:
    """A loopback server, and an authenticator pointed at it over plain ``ldap://``: the property
    under test is the decode, not the hop's TLS."""
    dc = _ScriptedDc(answer, extended_code, bind_reply, extended_reply)
    try:
        settings = _ad_settings(
            ad_server=f"ldap://127.0.0.1:{dc.port}", ad_allow_insecure_ldap=True
        )
        yield dc, LdapAuthenticator(settings, enforcing=False)
    finally:
        dc.close()


@contextlib.contextmanager
def _service_conn(authenticator: LdapAuthenticator) -> Iterator[Any]:
    conn = authenticator._service_conn()
    try:
        yield conn
    finally:
        conn.unbind()


def _two_pages(raw: bytes) -> list[_Reply]:
    if b"synthetic-cookie-1" in raw:
        return [_entry(_group_dn(3)), _done(RESULT_SUCCESS, b"")]
    return [
        _entry(_group_dn(1)),
        _entry(_group_dn(2)),
        _done(RESULT_SUCCESS, b"synthetic-cookie-1"),
    ]


def test_real_ldap3_pages_the_group_search_and_sends_the_cookie_back() -> None:
    """ldap3 encodes the request control and decodes the cookie where ``_paged_cookie`` reads it."""
    with _scripted_dc(_two_pages) as (dc, authenticator), _service_conn(authenticator) as conn:
        groups = authenticator._resolve_groups(conn, _USER_DN, [])
    assert groups == {ldap_module.canonical_group_dn(_group_dn(n)) for n in (1, 2, 3)}
    assert len(dc.searches) == 2
    assert all(ldap_module._PAGED_RESULTS_OID.encode() in raw for raw in dc.searches)
    assert all(_IN_CHAIN in raw for raw in dc.searches)
    assert b"synthetic-cookie-1" not in dc.searches[0]
    assert b"synthetic-cookie-1" in dc.searches[1]


def test_real_ldap3_refuses_a_group_search_whose_second_page_is_busy() -> None:
    def answer(raw: bytes) -> list[_Reply]:
        if b"synthetic-cookie-1" in raw:
            return [_done(RESULT_BUSY)]
        return _two_pages(raw)

    with (
        _scripted_dc(answer) as (dc, authenticator),
        _service_conn(authenticator) as conn,
        pytest.raises(LdapUnansweredError, match=r"result code 51 \(busy\)"),
    ):
        authenticator._resolve_groups(conn, _USER_DN, [])
    # The third is the abandon, sent through ldap3 with a page size of zero (RFC 2696).
    assert len(dc.searches) == 3
    assert b"synthetic-cookie-1" in dc.searches[2]


# --- sign-in: a directory error, not an unknown user ---------------------------------------------


async def test_a_busy_kerberos_sign_in_is_audited_as_a_login_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Closing item 2. The row names the code and never the directory's text."""

    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "alice")
    _install_fakes(monkeypatch)
    _answer_with(monkeypatch, RESULT_BUSY, when=lambda _kw: True)
    settings = _ad_settings(kerberos_enabled=True)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, settings, ldap=LdapAuthenticator(settings))
        await service.initialize()
        out = await service.authenticate_kerberos(b"spnego-token")

        assert not out.ok
        rows = [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.login_error")]
        assert len(rows) == 1 and "result code 51 (busy)" in rows[0], rows
        assert _LEAK not in rows[0]
        assert await store.list_audit(action="auth.login_success") == []
    finally:
        await store.close()


# --- check-privileges: the bind-account read names the code ---------------------------------------


@pytest.mark.parametrize(
    ("code", "name", "hint"),
    [
        (RESULT_NO_SUCH_OBJECT, "noSuchObject", "does not exist"),
        (RESULT_INVALID_DN_SYNTAX, "invalidDNSyntax", "is not a distinguished name"),
        (RESULT_INSUFFICIENT_ACCESS_RIGHTS, "insufficientAccessRights", "may not read it"),
        (RESULT_BUSY, "busy", None),
    ],
)
def test_the_bind_account_read_names_the_code_and_keeps_the_identity(
    monkeypatch: pytest.MonkeyPatch, code: int, name: str, hint: str | None
) -> None:
    """A configuration code carries its hint; busy carries none, so check-privileges does not send
    an operator to fix ``[auth].ad_bind_dn`` when the directory was only loaded."""
    conn = _conn(_result(code))
    conn.extend = SimpleNamespace(standard=SimpleNamespace(who_am_i=lambda: "u:EXAMPLE\\svc"))
    conn.unbind = lambda: True
    authenticator = LdapAuthenticator(_ad_settings())
    monkeypatch.setattr(authenticator, "_service_conn", lambda: conn)
    reading = authenticator.read_bind_account()
    assert reading.authzid == "u:EXAMPLE\\svc"
    problem = reading.problem
    assert problem is not None and problem.startswith("group membership not read: ")
    assert f"bind-account group read with result code {code} ({name})" in problem
    assert _LEAK not in problem
    if hint is None:
        assert "distinguished name" not in problem and "may not read" not in problem
    else:
        assert hint in problem
