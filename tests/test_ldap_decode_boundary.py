# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3010: a directory response ldap3 cannot decode is an outage, never an unhandled error.

ldap3 2.9.1's default fast decoder indexes the BER it reads without checking it, so a malformed
response raises ``KeyError``, ``TypeError``, ``IndexError`` or ``AttributeError`` from inside the
ldap3 call. Unmapped, any of those would escape every ``except LdapError``, and a sign-in would fail
as an unhandled error with no audit row. ``_ldap3_call`` is the one boundary every ldap3 call that
reads a response runs inside, and it maps such a fault to ``LdapUndecodableError``.

It decides by ORIGIN, never by the exception's value. The mapping it replaced matched a ``KeyError``
whose argument was an integer outside ldap3's result-code table. That let ``KeyError(3)`` through
bare, which is what the decoder raises for a bind response carrying a referral, and it named a stray
context tag [22] "result code 22". Every malformed response here is driven through a REAL ldap3 stack
against a loopback server, and each test states its premise first: the bare ldap3 call raises the
fault. An exception the engine raises propagates, whatever its value.

**Not exercised:** a real domain controller. Synthetic data only; nothing here touches PHI.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
from collections.abc import AsyncIterator, Callable
from types import SimpleNamespace
from typing import Any

import ldap3
import pytest
from ldap3.core.results import RESULT_CODES, RESULT_SUCCESS
from ldap3.utils import asn1
from ldap3.utils.asn1 import decode_sequence

from messagefoundry.api.app import _PROBE_FAULT_ALERT_SOURCE, _REFERRAL_ALERT_SOURCE
from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import AdPrincipal, LdapError, LdapReferralError, LdapUndecodableError
from messagefoundry.auth.reconcile import PROBE_FAULT_ABORT, REFERRAL_ABORT, ProbeOutcome
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests._ast_sites import callee_name, parse_source
from tests.test_ad_user_account_control import _pass
from tests.test_approval_requester_recheck import _Sink
from tests.test_ldap_referrals import _BIND_PASSWORD, _BIND_RESPONSE, _SEARCH_DONE, _tlv
from tests.test_ldap_search_result_codes import (
    _EXTENDED_RESPONSE,
    _IN_CHAIN,
    _USER_DN,
    _done,
    _entry,
    _enumerated,
    _group_dn,
    _Reply,
    _scripted_dc,
    _service_conn,
)
from tests.test_ldap_timeouts import _ad_settings

#: Stands for text the directory sends: it must never reach an error, a log line or an audit row.
_REFERRED = "ldap://dc9.synthetic-leak-3010.invalid/DC=other"

#: Long enough for the loopback server to see the client close. Its own read times out at 10s.
_CLOSE_WAIT = 5.0


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test sees its own once-per-process warnings."""
    monkeypatch.setattr(ldap_module, "_object_guid_shapes_warned", set())


def _result(tag: int, code: int, *, matched: bytes | None = None, extra: bytes = b"") -> bytes:
    """An LDAPResult under ``tag``. ``matched`` replaces the matchedDN element; ``extra`` is appended
    after the diagnostic message, where a referral would go."""
    matched_dn = _tlv(0x04, b"") if matched is None else matched
    return _tlv(tag, _tlv(0x0A, _enumerated(code)) + matched_dn + _tlv(0x04, b"") + extra)


#: A bind response carrying a referral, which ldap3's decoder cannot read (``KeyError(3)``). It is
#: refused as a referral, not as an undecodable response (D3b, BACKLOG #3010 and #2538).
_REFERRAL_BIND = _result(_BIND_RESPONSE, 10, extra=_tlv(0xA3, _tlv(0x04, _REFERRED.encode())))

#: Malformed bind responses: the reply, and what ldap3's decoder raises on it.
_BAD_BINDS = [
    pytest.param(
        _result(_BIND_RESPONSE, RESULT_SUCCESS, extra=_tlv(0x96, b"synthetic")),
        KeyError,
        id="context-tag-22",
    ),
    # A universal tag 3 is not the referral field, so it stays undecodable (D3b review round 1).
    pytest.param(
        _result(_BIND_RESPONSE, RESULT_SUCCESS, extra=_tlv(0x03, b"\x00")),
        KeyError,
        id="universal-tag-3",
    ),
    pytest.param(_result(_BIND_RESPONSE, 4242), KeyError, id="unknown-code-4242"),
    pytest.param(
        _result(_BIND_RESPONSE, RESULT_SUCCESS, matched=_tlv(0x02, b"\x05")),
        AttributeError,
        id="matched-dn-not-a-string",
    ),
]


def _assert_undecodable(exc: BaseException, operation: str, fault: type[BaseException]) -> None:
    """The refusal names the operation and the fault's type, and claims no result code."""
    assert isinstance(exc, LdapUndecodableError), repr(exc)
    text = str(exc)
    assert f"{operation} with a response ldap3 could not decode ({fault.__name__})" in text
    assert "result code" not in text, "no result code was read, so none may be claimed"
    assert "synthetic" not in text and "4242" not in text, "a value the directory sent leaked"
    assert isinstance(exc.__cause__, fault)


def _bare_bind(port: int) -> None:
    ldap3.Connection(
        ldap3.Server(f"ldap://127.0.0.1:{port}", get_info=ldap3.NONE),
        user="CN=svc,DC=example,DC=com",
        password=_BIND_PASSWORD,
        auto_bind=True,
        receive_timeout=5,
    )


def _reading_connection(exc: BaseException) -> Any:
    """The ldap3 connection whose response read raised ``exc``, found the way the boundary finds
    it. A premise check closes it, so the loopback server's thread does not wait out its timeout."""
    connection = ldap_module._reading_connection(exc)
    assert connection is not None, "the premise: ldap3 raised this while reading a response"
    return connection


# --- the service-account bind, and the socket it leaves open -------------------------------------


@pytest.mark.parametrize(("reply", "fault"), _BAD_BINDS)
def test_a_service_bind_ldap3_cannot_decode_is_an_outage(
    reply: bytes, fault: type[BaseException]
) -> None:
    """Every probe and sign-in opens with this bind. THE PREMISE first: the bare ldap3 bind raises
    ``fault`` from inside the ``Connection`` constructor."""
    with _scripted_dc(
        lambda _raw: [_done(RESULT_SUCCESS)], bind_reply=lambda _raw: (reply, b"")
    ) as (
        dc,
        authenticator,
    ):
        with pytest.raises(fault) as bare:
            _bare_bind(dc.port)
        _reading_connection(bare.value).strategy.close()
        with pytest.raises(LdapError) as refused:
            authenticator.probe_principal("alice")
        _assert_undecodable(refused.value, "service-account bind", fault)
        assert dc.searches == []


def test_the_service_bind_socket_is_closed_when_its_response_cannot_be_decoded() -> None:
    """Review finding 10. The bind runs inside ldap3's constructor, so no caller holds the
    connection to unbind; the refusal closes it. The control: the bare ldap3 bind leaves the socket
    open while its error is held."""
    reply = _result(_BIND_RESPONSE, 4242)

    def bind(_raw: bytes) -> _Reply:
        return reply, b""

    with _scripted_dc(lambda _raw: [], bind_reply=bind) as (dc, authenticator):
        with pytest.raises(KeyError) as bare:
            _bare_bind(dc.port)
        left = _reading_connection(bare.value)
        assert not left.closed, "the control: ldap3 alone leaves the socket open"
        left.strategy.close()
        assert dc.ended.wait(_CLOSE_WAIT)
        dc.ended.clear()
        with pytest.raises(LdapUndecodableError) as refused:
            authenticator.probe_principal("alice")
        assert refused.value.__cause__ is not None
        assert _reading_connection(refused.value.__cause__).closed
        assert dc.ended.wait(_CLOSE_WAIT), "the refused bind's socket was left open"


# --- the user bind, and the decoy bind that must fail the same way --------------------------------


def _alice(raw: bytes) -> list[_Reply]:
    """The user search finds alice, enabled, and nobody else."""
    if b"alice" not in raw:
        return [_done(RESULT_SUCCESS)]
    attributes = _tlv(
        0x30,
        b"".join(
            _tlv(0x30, _tlv(0x04, name) + _tlv(0x31, _tlv(0x04, value)))
            for name, value in ((b"sAMAccountName", b"alice"), (b"userAccountControl", b"512"))
        ),
    )
    return [(_tlv(0x64, _tlv(0x04, _USER_DN.encode()) + attributes), b""), _done(RESULT_SUCCESS)]


@pytest.mark.parametrize(("reply", "fault"), _BAD_BINDS)
def test_a_user_bind_ldap3_cannot_decode_fails_a_present_and_an_absent_account_alike(
    reply: bytes, fault: type[BaseException]
) -> None:
    """The present account's password bind and the absent account's decoy bind (ASVS 6.3.8) both
    refuse with the same text, so the answer does not tell the two apart."""

    def bind(raw: bytes) -> _Reply | None:
        is_user = b"CN=alice" in raw or b"mf-nonexistent-timing-equalizer" in raw
        return (reply, b"") if is_user else None

    texts = []
    with _scripted_dc(_alice, bind_reply=bind) as (_dc, authenticator):
        for username in ("alice", "nobody"):
            with pytest.raises(LdapError) as refused:
                authenticator.authenticate(username, "synthetic-user-pw")
            _assert_undecodable(refused.value, "user bind", fault)
            texts.append(str(refused.value))
    assert texts[0] == texts[1]


# --- a bind response carrying a referral is a referral (D3b) --------------------------------------


def _assert_referred_bind(exc: BaseException, operation: str) -> None:
    """The refusal is a referral naming the operation, with no host: the hosts are in the part
    ldap3 could not decode, and a value the directory sent never reaches the text."""
    assert isinstance(exc, LdapReferralError), repr(exc)
    text = str(exc)
    assert f"AD answered the {operation} with a referral" in text
    assert "could not decode" not in text and "result code" not in text
    assert _REFERRED not in text and "synthetic-leak" not in text, "a referred host leaked"
    assert isinstance(exc.__cause__, KeyError) and exc.__cause__.args == (3,)


def test_a_service_bind_answered_with_a_referral_is_a_referral() -> None:
    """Before D3b it read as an undecodable response, an outage the reconciler pages nobody for.
    THE PREMISE first: the bare ldap3 bind raises ``KeyError(3)``. The socket is still closed."""
    with _scripted_dc(lambda _raw: [], bind_reply=lambda _raw: (_REFERRAL_BIND, b"")) as (
        dc,
        authenticator,
    ):
        with pytest.raises(KeyError) as bare:
            _bare_bind(dc.port)
        assert bare.value.args == (3,)
        _reading_connection(bare.value).strategy.close()
        assert dc.ended.wait(_CLOSE_WAIT)
        dc.ended.clear()
        with pytest.raises(LdapReferralError) as refused:
            authenticator.probe_principal("alice")
        _assert_referred_bind(refused.value, "service-account bind")
        assert dc.searches == []
        assert dc.ended.wait(_CLOSE_WAIT), "the referred bind's socket was left open"


def test_a_user_bind_answered_with_a_referral_fails_a_present_and_an_absent_account_alike() -> None:
    """The decoy bind meets the same referral, so the two branches refuse with one text."""

    def bind(raw: bytes) -> _Reply | None:
        is_user = b"CN=alice" in raw or b"mf-nonexistent-timing-equalizer" in raw
        return (_REFERRAL_BIND, b"") if is_user else None

    texts = []
    with _scripted_dc(_alice, bind_reply=bind) as (_dc, authenticator):
        for username in ("alice", "nobody"):
            with pytest.raises(LdapReferralError) as refused:
                authenticator.authenticate(username, "synthetic-user-pw")
            _assert_referred_bind(refused.value, "user bind")
            texts.append(str(refused.value))
    assert texts[0] == texts[1]


async def test_the_reconciler_reads_a_referred_service_bind_as_referred() -> None:
    """So the probe reaches the referral's alert path (BACKLOG #2538), not the outage's."""
    with _scripted_dc(lambda _raw: [], bind_reply=lambda _raw: (_REFERRAL_BIND, b"")) as (
        dc,
        authenticator,
    ):
        store = await MessageStore.open(":memory:")
        try:
            settings = _ad_settings(
                ad_server=f"ldap://127.0.0.1:{dc.port}", ad_allow_insecure_ldap=True
            )
            service = AuthService(store, settings, ldap=authenticator)
            user = SimpleNamespace(id="u-1", username="alice", directory_object_id=None)
            probe = await service._probe_principal(user)  # type: ignore[arg-type]
        finally:
            await store.close()
    assert probe.outcome is ProbeOutcome.REFERRED
    assert probe.detail is not None and _REFERRED not in probe.detail


def test_a_referral_in_a_who_am_i_response_is_still_undecodable() -> None:
    """THE CONTROL: only a BIND response's referral field is read as a referral. ldap3's decoder
    raises the same ``KeyError(3)`` on an extended response carrying one, and that stays an
    undecodable response, because the origin check reads which response was being decoded."""
    reply = (
        _result(_EXTENDED_RESPONSE, 10, extra=_tlv(0xA3, _tlv(0x04, _REFERRED.encode()))),
        b"",
    )
    with _scripted_dc(lambda _raw: [_done(RESULT_SUCCESS)], extended_reply=reply) as (
        _dc,
        authenticator,
    ):
        with _service_conn(authenticator) as conn, pytest.raises(KeyError) as bare:
            conn.extend.standard.who_am_i()
        assert bare.value.args == (3,)
        reading = authenticator.read_bind_account()
    assert reading.whoami_error is not None
    assert "Who am I with a response ldap3 could not decode (KeyError)" in reading.whoami_error


# --- the nested group search: a malformed paged results control ---------------------------------

_OID = ldap_module._PAGED_RESULTS_OID.encode()

#: Malformed paged results controls on a searchResDone, and what ldap3's decoder raises on each.
_BAD_CONTROLS = [
    pytest.param(_tlv(0x30, _tlv(0x04, _OID)), TypeError, id="no-value-TypeError"),
    pytest.param(
        _tlv(0x30, _tlv(0x04, _OID) + _tlv(0x04, _tlv(0x30, _tlv(0x02, b"\x00")))),
        IndexError,
        id="no-cookie-IndexError",
    ),
]


def _bad_page(control: bytes) -> _Reply:
    return _result(_SEARCH_DONE, RESULT_SUCCESS), _tlv(0xA0, control)


@pytest.mark.parametrize(("control", "fault"), _BAD_CONTROLS)
@pytest.mark.parametrize("later", [False, True], ids=["first-page", "later-page"])
def test_a_paged_control_ldap3_cannot_decode_is_an_outage_and_is_not_abandoned(
    control: bytes, fault: type[BaseException], later: bool
) -> None:
    """New with paging: asking for the control is what lets a malformed one reach the decoder.
    No abandon follows, since the cookie it would send is the part that could not be read."""

    def answer(raw: bytes) -> list[_Reply]:
        if later and b"synthetic-cookie-1" not in raw:
            return [_entry(_group_dn(1)), _done(RESULT_SUCCESS, b"synthetic-cookie-1")]
        return [_entry(_group_dn(2)), _bad_page(control)]

    with _scripted_dc(answer) as (dc, authenticator):
        if not later:
            with _service_conn(authenticator) as conn, pytest.raises(fault):
                conn.search(search_base="OU=Groups", search_filter="(cn=*)", paged_size=5)
            dc.searches.clear()
        with _service_conn(authenticator) as conn:
            with pytest.raises(LdapError) as refused:
                authenticator._resolve_groups(conn, _USER_DN, [])
            # Not closed: _search leaves the connection to its caller (_ldap3_call says why).
            assert not conn.closed, "a search refusal must not close the caller's connection"
        _assert_undecodable(refused.value, "group search", fault)
        assert len(dc.searches) == (2 if later else 1), "a search was sent after the refusal"
        assert all(_IN_CHAIN in raw for raw in dc.searches)


@pytest.mark.parametrize(("control", "fault"), _BAD_CONTROLS)
def test_a_sign_in_probe_whose_group_page_cannot_be_decoded_is_an_outage(
    control: bytes, fault: type[BaseException]
) -> None:
    """The reconciler's probe, through the real authenticator: an outage, not an unhandled error."""

    with _bad_group_page_dc(control) as (_dc, authenticator), pytest.raises(LdapError) as refused:
        authenticator.probe_principal("alice")
    _assert_undecodable(refused.value, "group search", fault)


# --- the session reconciler pages on both: vault BACKLOG #3696 item 2 and #3697 step 2 ----------


def _bad_bind_dc(reply: bytes) -> Any:
    """A loopback DC whose every bind, the service account's included, is answered with
    ``reply``."""
    return _scripted_dc(lambda _raw: [], bind_reply=lambda _raw: (reply, b""))


def _bad_group_page_dc(control: bytes) -> Any:
    return _scripted_dc(lambda raw: [_bad_page(control)] if _IN_CHAIN in raw else _alice(raw))


def _undecodable_reads() -> list[Any]:
    """Every read the probe makes that ldap3 can fail to decode: the service bind, the user search
    and a page of the nested group search."""
    return [
        *(
            pytest.param(lambda reply=p.values[0]: _bad_bind_dc(reply), id=f"service-bind-{p.id}")
            for p in _BAD_BINDS
        ),
        pytest.param(lambda: _scripted_dc(lambda _raw: [_done(4242)]), id="user-search-4242"),
        *(
            pytest.param(
                lambda control=p.values[0]: _bad_group_page_dc(control), id=f"group-page-{p.id}"
            )
            for p in _BAD_CONTROLS
        ),
    ]


@contextlib.asynccontextmanager
async def _reconciler(
    authenticator: Any, port: int, **over: Any
) -> AsyncIterator[tuple[AuthService, MessageStore]]:
    """A real ``AuthService`` over a fresh store, probing through ``authenticator``."""
    store = await MessageStore.open(":memory:")
    try:
        settings = _ad_settings(
            ad_server=f"ldap://127.0.0.1:{port}", ad_allow_insecure_ldap=True, **over
        )
        yield AuthService(store, settings, ldap=authenticator), store
    finally:
        await store.close()


async def _probe_through_the_reconciler(authenticator: Any, port: int) -> Any:
    async with _reconciler(authenticator, port) as (service, _store):
        user = SimpleNamespace(id="u-1", username="alice", directory_object_id=None)
        return await service._probe_principal(user)  # type: ignore[arg-type]


@pytest.mark.parametrize("dc", _undecodable_reads())
async def test_the_reconciler_reads_every_response_it_cannot_decode_as_a_probe_fault(
    dc: Callable[[], Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3696 item 2. On engine ``main`` these faults escaped ldap.py as ldap3's own
    ``KeyError`` or ``TypeError``, so the probe's broad arm read them as FAULT, which pages.
    ``LdapUndecodableError`` is an ``LdapError``, so without its own arm it read UNAVAILABLE, an
    outage, which pages nobody. The WARNING names the account and the type only."""
    with dc() as (scripted, authenticator), caplog.at_level("WARNING"):
        probe = await _probe_through_the_reconciler(authenticator, scripted.port)
    assert probe.outcome is ProbeOutcome.FAULT
    assert probe.detail == "LdapUndecodableError"
    warned = [r.getMessage() for r in caplog.records if r.name == "messagefoundry.auth.service"]
    assert any("directory probe of alice raised LdapUndecodableError" in m for m in warned)
    assert not any("synthetic" in m or "4242" in m for m in warned), "a directory value leaked"


async def _signed_in(service: AuthService, username: str) -> str:
    """One live directory session, minted through the shared tail of the AD sign-in paths. The
    principal is synthetic: the subject is the reconciler, not the sign-in."""
    principal = AdPrincipal(
        username=username,
        display_name=username.title(),
        email=f"{username}@example.com",
        dn=_USER_DN,
        groups=frozenset(),
        directory_object_id="3f2b8c1e-0d4a-4e5b-9c6d-7a8b9c0d1e2f",
    )
    login = await service._complete_ad_login(principal, None, mfa_verified=True)
    assert login.token is not None
    return login.token


@pytest.mark.parametrize(
    ("reply", "unjudged", "source", "reason", "latch"),
    [
        pytest.param(
            _result(_BIND_RESPONSE, 4242),
            "faulted",
            _PROBE_FAULT_ALERT_SOURCE,
            PROBE_FAULT_ABORT,
            "directory_reconcile_fault",
            id="undecodable",
        ),
        pytest.param(
            _REFERRAL_BIND,
            "referred",
            _REFERRAL_ALERT_SOURCE,
            REFERRAL_ABORT,
            "directory_reconcile_referral",
            id="referral",
        ),
    ],
)
async def test_a_pass_whose_service_bind_is_undecodable_or_referred_pages_and_revokes_nothing(
    reply: bytes, unjudged: str, source: str, reason: str, latch: str
) -> None:
    """End to end, through the real authenticator, the real reconcile pass and the alerting the API
    lifespan task runs. Every probe opens with the service bind, so every probe in the pass meets
    the same answer. A decode fault pages as a probe fault (#3696 item 2); a referral pages as a
    referral (#3697 step 2, through the #2538 alert). Neither is an outage, and neither revokes.

    RED when: either reads UNAVAILABLE, which records a skipped pass and pages nobody."""
    with _bad_bind_dc(reply) as (dc, authenticator):
        async with _reconciler(authenticator, dc.port, ad_session_recheck_seconds=60) as (
            service,
            store,
        ):
            await service.initialize()
            token = await _signed_in(service, "alice")
            for _ in range(3):  # past ad_session_recheck_strikes: it pages on every pass
                sink = _Sink()
                plan = await _pass(service, sink)
                assert len(getattr(plan, unjudged)) == 1 and plan.unavailable == 0, plan
                assert not plan.directory_outage and plan.revocations == ()
                pages = [(e[1], e[2]["reason"]) for e in sink.events]
                assert pages == [(source, reason)], pages
            assert await service.identity_for_token(token) is not None, "a session was revoked"
            latched = getattr(service, latch)
            assert latched is not None
            assert _REFERRED not in latched and "synthetic-leak" not in latched
            skipped = await store.list_audit(action="auth.ad_reconcile_skipped", limit=100)
            assert list(skipped) == [], "the pass was recorded as an outage"


# --- a result code outside ldap3's table ---------------------------------------------------------


@pytest.mark.parametrize("code", [99, 4242], ids=["99", "4242"])
def test_a_search_ending_with_a_code_ldap3_has_no_name_for_is_an_outage(code: int) -> None:
    """THE PREMISE first: a bare ldap3 search raises ``KeyError`` from inside ``conn.search``."""
    assert code not in RESULT_CODES
    with _scripted_dc(lambda _raw: [_done(code)]) as (_dc, authenticator):
        with _service_conn(authenticator) as conn, pytest.raises(KeyError):
            conn.search(search_base="OU=Users,DC=example,DC=com", search_filter="(cn=x)")
        with pytest.raises(LdapError) as refused:
            authenticator.probe_principal("alice")
    _assert_undecodable(refused.value, "user search", KeyError)


def test_a_who_am_i_value_that_is_not_utf8_is_reported_and_the_group_read_still_runs() -> None:
    """Round-one review finding. ldap3 decodes the Who am I value in ``populate_result``, after
    the response read has returned, so the boundary looks for that frame too. THE PREMISE first:
    the bare call raises ``UnicodeError``, whose text quotes the directory's bytes. ldap3 decodes
    that value with the client encoding (``stdin``'s) and then UTF-8, so the bytes are ones neither
    cp1252 nor UTF-8 decodes."""
    value = b"u:EXAMPLE\\synthetic-\x81\x8d"
    reply = (
        _result(_EXTENDED_RESPONSE, RESULT_SUCCESS, extra=_tlv(0x8B, value)),
        b"",
    )
    with _scripted_dc(lambda _raw: [_done(RESULT_SUCCESS)], extended_reply=reply) as (
        dc,
        authenticator,
    ):
        with _service_conn(authenticator) as conn, pytest.raises(UnicodeError):
            conn.extend.standard.who_am_i()
        reading = authenticator.read_bind_account()
    assert reading.bound and reading.authzid is None
    assert reading.whoami_error is not None
    assert "Who am I with a response ldap3 could not decode (UnicodeError)" in reading.whoami_error
    assert "synthetic" not in reading.whoami_error
    assert len(dc.searches) == 1, "the group read did not run after the failed Who am I"


def test_a_who_am_i_ldap3_cannot_decode_is_reported_and_the_group_read_still_runs() -> None:
    """A failed Who am I is not a bind failure: ``whoami_error`` says why, in engine text."""
    with _scripted_dc(lambda _raw: [_done(RESULT_SUCCESS)], extended_code=4242) as (
        dc,
        authenticator,
    ):
        reading = authenticator.read_bind_account()
    assert reading.bound and reading.authzid is None
    assert reading.whoami_error == (
        "Who am I failed: AD answered the Who am I with a response ldap3 could not decode "
        "(KeyError); the engine reads it as the directory not answering (BACKLOG #3010)."
    )
    assert len(dc.searches) == 1, "the group read did not run after the failed Who am I"


# --- an exception from anywhere but ldap3's response reading propagates ---------------------------


def _raise(exc: BaseException) -> Callable[..., Any]:
    def call(*_a: object, **_kw: object) -> Any:
        raise exc

    return call


_ENGINE_FAULTS = pytest.mark.parametrize(
    "fault",
    [
        KeyError(3),
        KeyError(22),
        KeyError(4242),
        KeyError("objectGUID"),
        KeyError((0, 5)),
        TypeError("synthetic"),
        IndexError("synthetic"),
        AttributeError("synthetic"),
        ValueError("synthetic"),
    ],
    ids=repr,
)


@_ENGINE_FAULTS
def test_an_engine_fault_propagates_whatever_its_value(fault: Exception) -> None:
    """The mapping this replaced turned an engine ``KeyError(4242)`` into an outage and let ldap3's
    ``KeyError(3)`` through. Mapped, an engine defect reads as an outage, which the session
    reconciler logs only at debug level."""
    double = SimpleNamespace(search=_raise(fault), result=None)
    with pytest.raises(type(fault)) as raised:
        ldap_module._search(double, "user search")
    assert raised.value is fault
    with pytest.raises(type(fault)) as raised, ldap_module._ldap3_call("user bind", close=True):
        _raise(fault)()
    assert raised.value is fault


def test_a_fault_ldap3_raises_outside_response_reading_propagates() -> None:
    """The innermost frame is ldap3's, but nothing was being read from a directory: the same
    ``KeyError(3)`` ldap3 raises on a referral in a bind response, from its decoder called
    directly. Origin is both conditions, not the package alone."""
    referral_in_a_bind = _tlv(0xA3, _tlv(0x04, b"synthetic"))
    with pytest.raises(KeyError) as bare:
        decode_sequence(referral_in_a_bind, 0, len(referral_in_a_bind), {7: None})
    assert bare.value.args == (3,)
    with pytest.raises(KeyError), ldap_module._ldap3_call("user bind"):
        decode_sequence(referral_in_a_bind, 0, len(referral_in_a_bind), {7: None})


def test_an_ldap3_error_passes_through_for_its_own_handler() -> None:
    fault = ldap3.core.exceptions.LDAPSocketReceiveError("synthetic")
    with (
        pytest.raises(ldap3.core.exceptions.LDAPSocketReceiveError) as raised,
        ldap_module._ldap3_call("user search"),
    ):
        raise fault
    assert raised.value is fault


def test_the_ldap3_methods_the_origin_check_names_still_exist() -> None:
    """A rename in ldap3 would send every decode fault back to an unhandled error at sign-in; this
    names the cause in one place, where the loopback tests would each fail on it."""
    from ldap3.extend.operation import ExtendedOperation
    from ldap3.extend.standard.whoAmI import WhoAmI
    from ldap3.strategy.base import BaseStrategy
    from ldap3.strategy.sync import SyncStrategy

    readers = dict(ldap_module._RESPONSE_READERS)
    assert readers["ldap3.strategy."] == {"get_response", "_get_response"}
    assert "get_response" in vars(BaseStrategy)
    assert "_get_response" in vars(SyncStrategy)
    assert readers["ldap3.extend."] == {"decode_response", "populate_result", "set_response"}
    assert {"decode_response", "set_response"} <= set(vars(ExtendedOperation))
    assert "populate_result" in vars(WhoAmI)
    # What _is_bind_referral reads (D3b): the decoder's locals, and a bind table with no referral.
    assert {"context_decoders", "ber_class", "ber_type"} <= set(
        asn1.decode_sequence.__code__.co_varnames
    )
    assert ldap_module._REFERRAL_TAG not in asn1.BIND_RESPONSE_CONTEXT


def test_an_unbind_error_never_replaces_the_refusal() -> None:
    """Round-one review finding. The decoy bind swallows an ``LDAPException`` and the real bind
    maps it, so an unbind failing after an undecodable bind would tell an absent account from a
    present one. After a clean block, the unbind's error still propagates."""
    unbind_fault = ldap3.core.exceptions.LDAPSocketSendError("synthetic")
    conn = SimpleNamespace(unbind=_raise(unbind_fault))
    refusal = LdapUndecodableError("synthetic refusal")
    with pytest.raises(LdapUndecodableError) as raised, ldap_module._released(conn):
        raise refusal
    assert raised.value is refusal
    with pytest.raises(ldap3.core.exceptions.LDAPSocketSendError), ldap_module._released(conn):
        pass


def test_the_refusal_warns_once_per_operation_and_fault(caplog: pytest.LogCaptureFixture) -> None:
    with _scripted_dc(lambda _raw: [_done(4242)]) as (_dc, authenticator):
        for _ in range(3):
            with pytest.raises(LdapUndecodableError):
                authenticator.probe_principal("alice")
    warned = [r for r in caplog.records if "could not decode" in r.getMessage()]
    assert len(warned) == 1 and warned[0].levelname == "WARNING"


# --- every ldap3 call that reads a response runs inside the boundary ------------------------------

#: The ldap3 methods that send a request and read its response, as this module calls them.
_READING_CALLS = frozenset({"search", "bind", "who_am_i"})


def _context_names(node: ast.With) -> list[str | None]:
    """What each item of a ``with`` calls, by bare name, or ``None`` for an item that is no call."""
    return [
        callee_name(item.context_expr, bare_only=True)
        if isinstance(item.context_expr, ast.Call)
        else None
        for item in node.items
    ]


def _outside_the_boundary(source: str) -> tuple[list[str], int]:
    """Each ldap3 call in ``source`` that reads a response and is not lexically inside a ``with``
    naming ``_ldap3_call``, and how many such calls there are in all. A ``Connection`` built with
    ``auto_bind`` counts, bare or as ``ldap3.Connection``: its constructor binds."""
    tree = parse_source(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def guarded(node: ast.AST) -> bool:
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.With) and "_ldap3_call" in _context_names(node):
                return True
        return False

    outside, total = [], 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = callee_name(node)
        reads = (name in _READING_CALLS and isinstance(node.func, ast.Attribute)) or (
            name == "Connection" and any(k.arg == "auto_bind" for k in node.keywords)
        )
        if reads:
            total += 1
            if not guarded(node):
                outside.append(f"line {node.lineno}: {ast.unparse(node.func)}")
    return outside, total


def test_every_ldap3_call_that_reads_a_response_is_inside_the_boundary() -> None:
    """Review finding 12. A new search, bind or extended operation added outside ``_ldap3_call``
    would bring back the unhandled error at sign-in for whatever it decodes."""
    outside, total = _outside_the_boundary(inspect.getsource(ldap_module))
    assert outside == []
    # The service bind, the user bind, the decoy bind, _search, and Who am I.
    assert total >= 5, f"the census found {total} calls; the instrument has lost them"


def test_a_bind_maps_a_decode_fault_before_a_socket_fault() -> None:
    """``TypeError`` and ``ValueError`` are both a socket fault and a decode fault. Where a ``with``
    names both wraps, ``_ldap3_call`` must be the inner one, so a decode fault is refused as one,
    and the service socket closed, before ``_socket_faults_as_ldap_error`` can claim it."""
    tree = parse_source(inspect.getsource(ldap_module))
    paired = [
        names
        for node in ast.walk(tree)
        if isinstance(node, ast.With)
        and {"_ldap3_call", "_socket_faults_as_ldap_error"} <= set(names := _context_names(node))
    ]
    assert len(paired) >= 2, "the service bind and the user bind"
    for names in paired:
        assert names.index("_socket_faults_as_ldap_error") < names.index("_ldap3_call"), names


def test_the_static_check_catches_a_call_outside_the_boundary() -> None:
    """The control: a planted unguarded search, and a guarded one, in the same text."""
    planted = (
        "def a(conn):\n"
        "    with _ldap3_call('x'):\n"
        "        conn.search(search_base='b')\n"
        "def b(conn):\n"
        "    with contextlib.suppress(KeyError):\n"
        "        conn.extend.standard.who_am_i()\n"
    )
    outside, total = _outside_the_boundary(planted)
    assert total == 2
    assert outside == ["line 6: conn.extend.standard.who_am_i"]
