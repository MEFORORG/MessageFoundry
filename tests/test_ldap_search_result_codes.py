# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3010: a search that ends with any result code but success is the directory not
answering, never "no such entry".

ldap3 raises on none of these codes here (every connection keeps ``raise_exceptions=False``), so a
busy or admin-limit-exceeded search came back with no entries. ``_search_user`` read that as
``NOT_FOUND``, the session reconciler read ``NOT_FOUND`` as ``ABSENT``, and after the strike
threshold it revoked a present account. The nested group search read the same answer as fewer
groups. ``_search`` now refuses every code but success with :class:`LdapUnansweredError`, which
every caller already reads as an outage.

Driven at three depths: ``_search`` itself over a bare double; the REAL ``LdapAuthenticator`` over
the ldap3 doubles of ``tests/test_ad_user_account_control.py`` and ``tests/test_ldap_timeouts.py``;
and the REAL ``AuthService`` reconciler and Kerberos sign-in over those. Each refusal has a control
on the same doubles: success with no entries still reads absent, and still revokes.

**Not exercised:** a real domain controller. The doubles set the result dict the way ldap3 2.9.1's
synchronous strategy leaves it. Synthetic data only; nothing here touches PHI.
"""

from __future__ import annotations

import copy
import logging
import pickle
from collections.abc import Callable
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
from messagefoundry.auth.reconcile import ProbeOutcome
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ad_user_account_control import _alive, _audited, _pass, _signed_in_estate
from tests.test_ldap_timeouts import _ad_settings, _install_fakes

#: Stands for text the directory sends with a result: its diagnostic message and matched DN. It
#: must never reach an error, a log line or an audit row.
_LEAK = "CN=synthetic-leak-3010,OU=Staff,DC=test,DC=invalid"

_GROUPS = "OU=Groups,DC=test,DC=invalid"

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
    ("estate", "when", "code", "partial"),
    [
        ({}, _user_search, RESULT_BUSY, False),
        ({}, _user_search, RESULT_ADMIN_LIMIT_EXCEEDED, False),
        ({}, _user_search, RESULT_NO_SUCH_OBJECT, False),
        ({}, _user_search, RESULT_SIZE_LIMIT_EXCEEDED, True),
        ({"ad_group_search_base": _GROUPS}, _group_search, RESULT_BUSY, False),
    ],
    ids=["busy", "adminLimitExceeded", "noSuchObject", "sizeLimit-partial", "group-search-busy"],
)
async def test_a_directory_that_did_not_answer_never_revokes_a_present_account(
    monkeypatch: pytest.MonkeyPatch,
    estate: dict[str, Any],
    when: Callable[[dict[str, Any]], bool],
    code: int,
    partial: bool,
) -> None:
    """The row's defect, end to end. One signed-in account, under the breaker's floor, whose search
    the directory answers with ``code`` on every pass. Before the fix the user search read ABSENT
    and was revoked at the strike threshold, and the nested group search read as fewer groups,
    which feeds the role re-diff. Now each probe is unavailable and the session survives."""
    async with _signed_in_estate(monkeypatch, ["jdoe"], **estate) as (
        _directory,
        service,
        store,
        tokens,
    ):
        _answer_with(monkeypatch, code, when=when, keep_entries=partial)
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
