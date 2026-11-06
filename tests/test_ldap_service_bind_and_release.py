# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3017: what ``auth/ldap.py`` answers when the directory fails, and what it leaves open.

Six properties are pinned, each with the test that failed before the change:

* a second connect that fails answers an absent account and a present one alike, and a plain wrong
  user name on a healthy directory still reads as a failed sign-in, through a real ldap3 stack;
* an ldap3 error's text, which can list every address the engine tried, never reaches the
  ``LdapError`` or the ``auth.login_error`` row;
* ``authenticate`` and ``probe_principal`` unbind the service account's connection on every path;
* a failed service-account bind closes its socket, at least on an error raised after the socket
  opened, such as on a password SASLprep refuses, and on a failed open the rule in
  ``ldap._close_without_sending`` names (L4; the host name refusal is pinned in
  ``tests/test_ldap_tls.py``);
* a service-account bind refused with a referral is refused as a referral, and any other refusal
  names its result code, through a real ldap3 stack;
* a sign-in or step-up leg answers a directory error for any fault the authenticator raises, with
  its audit row (vault BACKLOG #3100 item 11).

Synthetic data only; nothing here touches PHI.
"""

from __future__ import annotations

import ast
import functools
import inspect
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import ldap3
import pytest

from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth import service as service_module
from messagefoundry.auth.ldap import (
    DirectoryAnswer,
    LdapAuthenticator,
    LdapError,
    LdapReferralError,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ldap_error_mapping import _faulting
from tests.test_ldap_referrals import _BIND_RESPONSE
from tests.test_ldap_search_result_codes import _done, _scripted_dc
from tests.test_ldap_timeouts import _SERVICE_DN, _ad_settings, _install_fakes, _shape_search

#: Stands for the addresses an ``LDAPSocketOpenError`` lists. It must never reach an error or a row.
_ADDRESSES = "[('10.20.30.40', 636), ('fd00::synthetic-leak-3017', 636)]"
_PASSWORD = "synthetic-user-pw-3017"
_OBJECT_ID = "75920276-799f-51a3-9e67-4e4b9c43fd0c"


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test sees its own once-per-process warnings."""
    monkeypatch.setattr(ldap_module, "_object_guid_shapes_warned", set())


def _socket_open_error() -> Exception:
    return ldap3.core.exceptions.LDAPSocketOpenError(
        f"socket connection error while opening: {_ADDRESSES}"
    )


# --- (a) the decoy bind swallows nothing ---------------------------------------------------------


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(_socket_open_error, id="LDAPSocketOpenError"),
        pytest.param(
            lambda: ldap3.core.exceptions.LDAPSocketReceiveError("synthetic"),
            id="LDAPSocketReceiveError",
        ),
        pytest.param(
            lambda: ldap3.core.exceptions.LDAPResponseTimeoutError("synthetic"),
            id="LDAPResponseTimeoutError",
        ),
    ],
)
def test_a_failed_second_connect_answers_an_absent_and_a_present_account_alike(
    make: Any,
) -> None:
    """ASVS 6.3.8 (#1140). Before #3017 the decoy swallowed ldap3's own error, so an absent account
    answered as a plain failed sign-in while a present one raised a directory error."""
    texts: dict[str, str] = {}
    for branch, uac, at in (("absent", None, "decoy bind"), ("present", "512", "user bind")):
        with pytest.MonkeyPatch.context() as mp:
            _install_fakes(mp)
            _shape_search(mp, uac=uac)
            _faulting(mp, at=at, fault=make())
            with pytest.raises(LdapError) as err:
                LdapAuthenticator(_ad_settings()).authenticate("ghost", _PASSWORD)
            texts[branch] = str(err.value)
    assert texts["absent"] == texts["present"], texts


def test_a_referred_bind_answers_an_absent_and_a_present_account_alike() -> None:
    """The real bind refuses a referral its bind answer carries, so the decoy must too, or a
    referring directory would answer NOT_FOUND for an absent account only (review round 1)."""
    texts: dict[str, str] = {}
    for branch, uac in (("absent", None), ("present", "512")):
        with pytest.MonkeyPatch.context() as mp:
            _install_fakes(mp, refer="bind")
            _shape_search(mp, uac=uac)
            with pytest.raises(LdapReferralError) as err:
                LdapAuthenticator(_ad_settings()).authenticate("ghost", _PASSWORD)
            texts[branch] = str(err.value)
    assert texts["absent"] == texts["present"], texts


def test_a_wrong_user_name_on_a_healthy_directory_is_a_failed_sign_in() -> None:
    """THE GUARD the swallow existed for, through a real ldap3 stack. The directory refuses the
    decoy's DN with invalidCredentials, which ldap3 returns as ``False`` and never raises, so the
    absent account answers NOT_FOUND and not a directory error."""

    def bind(raw: bytes) -> tuple[bytes, bytes] | None:
        return _done(49, tag=_BIND_RESPONSE) if b"mf-nonexistent" in raw else None

    with _scripted_dc(lambda _raw: [_done(0)], bind_reply=bind) as (dc, authenticator):
        answer = authenticator.authenticate("ghost", _PASSWORD)
    assert answer.principal is None
    assert answer.answer is DirectoryAnswer.NOT_FOUND
    assert len(dc.searches) == 1


# --- (b) no ldap3 text in the error or the audit row --------------------------------------------


@pytest.mark.parametrize("call", ["authenticate", "probe_principal"])
def test_an_ldap3_error_names_its_type_and_never_its_text(
    monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    _install_fakes(monkeypatch)
    fault = _socket_open_error()
    _faulting(monkeypatch, at="open", fault=fault)
    authenticator = LdapAuthenticator(_ad_settings())

    with pytest.raises(LdapError) as err:
        if call == "authenticate":
            authenticator.authenticate("alice", _PASSWORD)
        else:
            authenticator.probe_principal("alice")
    assert str(err.value) == "AD directory call failed: ldap3 raised LDAPSocketOpenError"
    assert err.value.__cause__ is fault, "the error must stay chained for a traceback"


async def _kerberos_sign_in(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Run one Kerberos sign-in over the doubles installed, and return its auth.login_error rows."""

    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "alice")
    settings = _ad_settings(kerberos_enabled=True, kerberos_realm="EXAMPLE.COM")
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, settings, ldap=LdapAuthenticator(settings))
        await service.initialize()
        out = await service.authenticate_kerberos(b"spnego-token")
        assert not out.ok
        assert out.error == "directory unavailable"
        assert await store.list_audit(action="auth.login_success") == []
        return [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.login_error")]
    finally:
        await store.close()


async def test_the_audit_row_never_carries_the_directory_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fakes(monkeypatch)
    _faulting(monkeypatch, at="open", fault=_socket_open_error())
    rows = await _kerberos_sign_in(monkeypatch)
    assert len(rows) == 1, rows
    assert '"cause": "ldap3.core.exceptions.LDAPSocketOpenError"' in rows[0], rows[0]
    assert "10.20.30.40" not in rows[0] and "synthetic-leak" not in rows[0], rows[0]


# --- (c) the service connection is unbound on every path ----------------------------------------


@pytest.mark.parametrize(
    ("uac", "bind_ok"),
    [
        pytest.param(None, True, id="absent"),
        pytest.param("514", True, id="disabled"),
        pytest.param("512", False, id="wrong-password"),
        pytest.param("512", True, id="signed-in"),
    ],
)
def test_authenticate_unbinds_the_service_connection(
    monkeypatch: pytest.MonkeyPatch, uac: str | None, bind_ok: bool
) -> None:
    rec = _install_fakes(monkeypatch, bind_ok=bind_ok)
    _shape_search(monkeypatch, uac=uac)
    LdapAuthenticator(_ad_settings()).authenticate("ghost", _PASSWORD)
    assert rec.unbinds.count(_SERVICE_DN) == 1, rec.unbinds


@pytest.mark.parametrize("uac", [None, "512"], ids=["absent", "found"])
def test_probe_principal_unbinds_the_service_connection(
    monkeypatch: pytest.MonkeyPatch, uac: str | None
) -> None:
    rec = _install_fakes(monkeypatch)
    _shape_search(monkeypatch, uac=uac)
    LdapAuthenticator(_ad_settings()).probe_principal("ghost")
    assert rec.unbinds == [_SERVICE_DN]


@pytest.mark.parametrize("call", ["authenticate", "probe_principal"])
def test_a_failed_search_still_unbinds_the_service_connection(
    monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    rec = _install_fakes(monkeypatch)
    _faulting(
        monkeypatch, at="search", fault=ldap3.core.exceptions.LDAPSocketReceiveError("synthetic")
    )
    authenticator = LdapAuthenticator(_ad_settings())
    with pytest.raises(LdapError):
        if call == "authenticate":
            authenticator.authenticate("alice", _PASSWORD)
        else:
            authenticator.probe_principal("alice")
    assert rec.unbinds == [_SERVICE_DN]


def test_an_ldap3_socket_error_names_the_interpreters_error_type() -> None:
    """ldap3 merges the interpreter's error into its own class, so the type tells a CA mismatch
    from a refused port without quoting the text, which can name the directory's addresses."""
    import ssl

    from ldap3.core.exceptions import LDAPSocketOpenError, communication_exception_factory

    merged = communication_exception_factory(
        LDAPSocketOpenError, ssl.SSLCertVerificationError("synthetic")
    )
    error = ldap_module._ldap3_failed(merged(f"socket ssl wrapping error: {_ADDRESSES}"))
    assert str(error) == (
        "AD directory call failed: ldap3 raised LDAPSocketOpenError (SSLCertVerificationError)"
    )


def test_a_failed_service_unbind_does_not_change_the_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The block has answered by then, so an unbind failure is suppressed, as
    ``read_bind_account``'s is, and the socket the failed send left open is closed (BACKLOG
    #3848)."""
    _install_fakes(monkeypatch)
    base = ldap3.Connection
    closed: list[str | None] = []

    class FailingServiceUnbind(base):  # type: ignore[misc, valid-type]
        def __init__(self, server: Any = None, **kwargs: Any) -> None:
            super().__init__(server, **kwargs)
            self.strategy = SimpleNamespace(close=lambda: closed.append(self._bind_dn))

        def unbind(self) -> None:
            if self._bind_dn == _SERVICE_DN:
                raise ldap3.core.exceptions.LDAPSocketSendError("synthetic")
            super().unbind()

    monkeypatch.setattr(ldap3, "Connection", FailingServiceUnbind)
    probe = LdapAuthenticator(_ad_settings()).probe_principal("alice")
    assert probe.answer is DirectoryAnswer.FOUND
    assert closed == [_SERVICE_DN]


# --- (f) a refused service-account bind, through a real ldap3 stack -----------------------------


def test_a_service_bind_referral_with_no_referral_field_is_a_referral() -> None:
    """ldap3 decodes a referral result with no referral field, and its ``bind()`` answers
    ``False`` for it. Before #3017 that read as a directory failure, which the session reconciler
    reads as an outage. A referral that carries its hosts never
    decodes, and ``tests/test_ldap_decode_boundary.py`` pins that one."""
    referral = _done(10, tag=_BIND_RESPONSE)
    with (
        _scripted_dc(lambda _raw: [], bind_reply=lambda _raw: referral) as (dc, authenticator),
        pytest.raises(LdapReferralError) as refused,
    ):
        authenticator.probe_principal("alice")
    text = str(refused.value)
    assert "AD answered the service-account bind with a referral to <no host given>" in text
    assert dc.searches == []


def test_any_other_service_bind_refusal_names_its_result_code() -> None:
    """The code and ldap3's name for it, so an operator still sees a wrong service password,
    and never the directory's diagnostic message."""
    refused = _done(49, tag=_BIND_RESPONSE)
    with (
        _scripted_dc(lambda _raw: [], bind_reply=lambda _raw: refused) as (dc, authenticator),
        pytest.raises(LdapError) as err,
    ):
        authenticator.probe_principal("alice")
    assert not isinstance(err.value, LdapReferralError)
    assert str(err.value).startswith(
        "AD ended the service-account bind with result code 49 (invalidCredentials), which "
        "refused the bind;"
    )
    # L3: a refused bind is the directory's answer, so it is not called one it did not give.
    assert "not an answer" not in str(err.value)
    assert "check [auth].ad_bind_dn and its password" in str(err.value)
    assert dc.searches == []


_REFUSED = "which refused the bind; the engine reads the directory as unavailable until it is fixed"
_CONFIGURATION = "which refused the bind; the engine reads it as a fault in the configuration"
_NO_ANSWER = "which is not an answer; the engine reads it as the directory not answering"


@pytest.mark.parametrize(
    ("operation", "code", "bind", "verdict"),
    [
        pytest.param("service-account bind", 49, True, _REFUSED, id="bind-49"),
        pytest.param("service-account bind", 34, True, _CONFIGURATION, id="bind-34"),
        pytest.param("service-account bind", 8, True, _NO_ANSWER, id="bind-8-judged-nothing"),
        pytest.param("service-account bind", 52, True, _NO_ANSWER, id="bind-52-outage"),
        pytest.param("service-account bind", None, True, _NO_ANSWER, id="bind-no-code"),
        pytest.param("user bind", 51, False, _NO_ANSWER, id="user-bind-51-busy"),
        pytest.param("user search", 49, False, _NO_ANSWER, id="not-a-bind-49"),
    ],
)
def test_only_a_bind_the_directory_refused_is_called_refused(
    operation: str, code: int | None, bind: bool, verdict: str
) -> None:
    """L3. A bind refused with invalidCredentials or a code pointing at its DN is a refusal, and
    its reading does not also call it no answer. A code that judged nothing (an outage code,
    strongerAuthRequired) and no code at all are no answer, and the caller says which operation is
    a bind, so a label never decides it."""
    assert f", {verdict} (BACKLOG #3010)" in str(
        ldap_module._unanswered(operation, code, bind=bind)
    )


def test_a_refused_service_bind_with_no_result_code_still_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bind answered ``False`` with no result to read claims no result code, still refuses, and
    closes the socket (BACKLOG #3017 L4)."""
    rec = _install_fakes(monkeypatch)
    base = ldap3.Connection

    class Unreadable(base):  # type: ignore[misc, valid-type]
        def bind(self) -> bool:
            if self._bind_dn != _SERVICE_DN:
                return bool(super().bind())
            self.result = None
            return False

    monkeypatch.setattr(ldap3, "Connection", Unreadable)
    with pytest.raises(LdapError) as err:
        LdapAuthenticator(_ad_settings()).probe_principal("alice")
    assert not isinstance(err.value, LdapReferralError)
    assert str(err.value) == (
        "AD refused the service-account bind, with no refusing result code to name"
    )
    assert rec.closes == [_SERVICE_DN]


# --- L4: a service bind that fails after its socket opens leaves no socket open -----------------


def test_a_service_bind_that_raises_after_the_socket_opens_closes_it() -> None:
    """BACKLOG #3017 L4, through a real ldap3 stack. A password SASLprep (RFC 4013) refuses raises
    after the socket opens and before the bind request is sent. Under ``auto_bind`` the engine never
    held that connection, so its socket stayed open while anything referenced it; here the
    traceback ``pytest.raises`` keeps holds it, and the domain controller still sees the close."""
    built: list[Any] = []
    real = ldap3.Connection

    class Kept(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            built.append(self)
            super().__init__(*args, **kwargs)

    with (
        pytest.MonkeyPatch.context() as mp,
        _scripted_dc(lambda _raw: []) as (dc, authenticator),
    ):
        mp.setattr(ldap3, "Connection", Kept)
        authenticator._bind_password = "synthetic\x07pw-3017"  # a control character
        with pytest.raises(LdapError) as err:
            authenticator.probe_principal("alice")
        assert dc.ended.wait(timeout=5), "the domain controller never saw the socket close"
        assert dc.opened == 1 and dc.searches == []
    assert str(err.value).startswith("AD directory call failed: ldap3 raised LDAP")
    assert "synthetic" not in str(err.value)
    [conn] = built
    assert conn.closed and conn.socket is None


def test_a_service_bind_whose_open_fails_after_the_connect_closes_its_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Through a real ldap3 stack, the first case of the rule in ``ldap._close_without_sending``:
    a TLS wrap that raises before ``ssl`` takes the socket over. The domain controller sees the
    socket end."""
    import ssl

    built: list[Any] = []
    real = ldap3.Connection

    class Kept(real):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            built.append(self)
            super().__init__(*args, **kwargs)

    def refused_wrap(*_args: Any, **_kwargs: Any) -> None:
        raise ssl.SSLError("synthetic-leak-3017")

    with _scripted_dc(lambda _raw: []) as (dc, _plain):
        monkeypatch.setattr(ldap3, "Connection", Kept)
        authenticator = LdapAuthenticator(_ad_settings(ad_server=f"ldaps://127.0.0.1:{dc.port}"))
        monkeypatch.setattr(type(authenticator._tls), "wrap_socket", refused_wrap)
        with pytest.raises(LdapError) as err:
            authenticator.probe_principal("alice")
        assert dc.ended.wait(timeout=5), "the domain controller never saw the socket close"
        assert dc.opened == 1 and dc.searches == []
    assert "synthetic-leak" not in str(err.value)
    [conn] = built
    assert conn.socket is None


@pytest.mark.parametrize(
    "fault",
    [
        pytest.param(ldap3.core.exceptions.LDAPSocketReceiveError("synthetic"), id="ldap3-error"),
        pytest.param(OSError("synthetic"), id="socket-fault"),
        pytest.param(KeyError("synthetic"), id="engine-defect"),
    ],
)
def test_every_failed_service_bind_closes_its_socket(
    monkeypatch: pytest.MonkeyPatch, fault: Exception
) -> None:
    """Whatever the service account's bind raises, the socket is closed without sending, and the
    error the caller sees is unchanged by the close (BACKLOG #3017 L4)."""
    rec = _install_fakes(monkeypatch)
    _faulting(monkeypatch, at="open", fault=fault)
    with pytest.raises((LdapError, KeyError)) as err:
        LdapAuthenticator(_ad_settings()).probe_principal("alice")
    if isinstance(fault, KeyError):
        assert err.value is fault, "an engine defect must stay itself"
    else:
        assert err.value.__cause__ is fault
    assert rec.closes == [_SERVICE_DN]
    assert rec.unbinds == [], "a connection that never bound is closed, not unbound"


def test_a_close_that_raises_never_replaces_the_bind_refusal(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The close is best effort: the caller still gets the bind's own refusal as an
    ``LdapError``, which every sign-in arm audits. A close that raises anything but an ldap3 or
    socket error is an engine defect that may leave the socket open, so it is logged at ERROR, by
    type."""
    _install_fakes(monkeypatch)
    _faulting(
        monkeypatch, at="open", fault=ldap3.core.exceptions.LDAPSocketReceiveError("synthetic")
    )
    base = ldap3.Connection

    def broken_close() -> None:
        raise AttributeError("synthetic: a half-built strategy")

    class BrokenClose(base):  # type: ignore[misc, valid-type]
        def __init__(self, server: Any = None, **kwargs: Any) -> None:
            super().__init__(server, **kwargs)
            self.strategy = SimpleNamespace(close=broken_close)

    monkeypatch.setattr(ldap3, "Connection", BrokenClose)
    with (
        caplog.at_level(logging.ERROR, logger=ldap_module.logger.name),
        pytest.raises(LdapError, match="ldap3 raised LDAPSocketReceiveError"),
    ):
        LdapAuthenticator(_ad_settings()).probe_principal("alice")
    [record] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert "raised AttributeError, an engine defect" in record.getMessage()
    assert "half-built" not in record.getMessage()


def test_the_service_connection_is_built_without_auto_bind() -> None:
    """``auto_bind`` binds inside ldap3's constructor, where the engine holds no connection to close
    on a failure (BACKLOG #3017 L4, L5). The service connection is built unbound and bound by
    ``_service_conn`` itself."""
    tree = ast.parse(inspect.getsource(ldap_module))
    built = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Connection"
    ]
    assert len(built) >= 3, "the service, user and decoy connections; the census lost them"
    assert not [n.lineno for n in built if any(k.arg == "auto_bind" for k in n.keywords)]


# --- (e) the sign-in and step-up legs answer a directory error for any fault ---------------------


async def test_a_kerberos_sign_in_audits_an_unexpected_fault_as_a_login_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Before #3017 a ``TypeError`` from the search escaped ``except LdapError`` as an unhandled
    error, with no audit row. ``ldap.py`` leaves it as itself on purpose (BACKLOG #2566)."""
    _install_fakes(monkeypatch)
    _faulting(monkeypatch, at="search", fault=TypeError("CN=synthetic-leak-3017"))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"):
        rows = await _kerberos_sign_in(monkeypatch)
    assert len(rows) == 1 and '"cause": "TypeError"' in rows[0], rows
    assert "synthetic-leak" not in rows[0]
    # At ERROR since L6: the fault is raised in this module, not while reading an answer.
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("resolve_principal raised TypeError" in m for m in warned), warned
    assert not any("synthetic-leak" in m for m in warned), warned


async def test_the_step_up_rebind_reads_an_unexpected_fault_as_unavailable() -> None:
    class Faulty:
        def authenticate(self, *_args: object, **_kwargs: object) -> object:
            raise KeyError("synthetic")

    store = await MessageStore.open(":memory:")
    try:
        settings = _ad_settings()
        service = AuthService(store, settings, ldap=LdapAuthenticator(settings))
        await service.initialize()
        service._ldap = Faulty()  # type: ignore[assignment]
        rebind = await service._reauth_ad("alice", _PASSWORD, object_id=_OBJECT_ID)
    finally:
        await store.close()
    assert rebind == service_module._DirectoryRebind(None, "directory_unavailable")


async def test_ask_directory_passes_an_ldap_error_through_unchanged() -> None:
    raised = LdapReferralError("synthetic")

    def refer() -> None:
        raise raised

    with pytest.raises(LdapReferralError) as err:
        await service_module._ask_directory(refer)
    assert err.value is raised


async def test_ask_directory_names_an_engine_defect_at_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #3017 L6. Every fault still fails closed as an ``LdapError``, and every one ldap3
    did not raise while reading the directory's response is logged at ERROR as an engine defect,
    naming the frame and no text. ``_escape_filter(None)`` raises inside ``auth/ldap.py``,
    ``json.loads`` inside the standard library on a bad argument, and ``parse_dn(None)`` inside
    ldap3 on an engine-supplied ``None``, which is the engine's defect too."""
    engine_fault = functools.partial(ldap_module._escape_filter, None)  # type: ignore[arg-type]
    stdlib_fault = functools.partial(json.loads, "{synthetic-leak-3017")
    ldap3_fault = functools.partial(ldap3.utils.dn.parse_dn, None)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"):
        for fault, kind in (
            (engine_fault, "TypeError"),
            (stdlib_fault, "JSONDecodeError"),
            (ldap3_fault, "LDAPInvalidDnError"),
        ):
            with pytest.raises(LdapError, match=f"^directory call failed: unexpected {kind}$"):
                await service_module._ask_directory(fault)
    lines = [(r.levelno, r.getMessage()) for r in caplog.records]
    assert [level for level, _m in lines] == [logging.ERROR] * 3, lines
    engine_line, stdlib_line, ldap3_line = (m for _l, m in lines)
    assert "raised TypeError at messagefoundry.auth.ldap:" in engine_line
    assert "in _escape_filter, not in ldap3's read of the directory's answer" in engine_line
    assert "at json.decoder:" in stdlib_line and "at ldap3.utils.dn:" in ldap3_line
    assert not any("synthetic-leak" in m or "NoneType" in m or "empty dn" in m for _l, m in lines)


async def test_ask_directory_reads_a_fault_raised_reading_a_response_as_the_directorys(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the test above: a fault whose origin ``ldap.py``'s rule reads as a response
    ldap3 was reading stays at WARNING, as the directory not answering."""
    monkeypatch.setattr(service_module, "_reading_connection", lambda _exc: object())
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"),
        pytest.raises(LdapError),
    ):
        await service_module._ask_directory(functools.partial(ldap3.utils.dn.parse_dn, None))
    [record] = caplog.records
    assert record.levelno == logging.WARNING and "engine defect" not in record.getMessage()


async def test_ask_directory_reads_an_unreached_directory_as_the_directorys(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A network error that says the directory was not reached is read as the reconciler reads it,
    not as an engine defect (``_unreached_directory``)."""

    def refused() -> None:
        raise ConnectionRefusedError("synthetic-leak-3017")

    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"),
        pytest.raises(LdapError, match="unexpected ConnectionRefusedError"),
    ):
        await service_module._ask_directory(refused)
    [record] = caplog.records
    assert record.levelno == logging.WARNING and "synthetic-leak" not in record.getMessage()


def test_an_engine_defect_names_the_line_that_raised_not_its_cleanup() -> None:
    """``tb_lineno``: a ``finally`` that ran in the raising frame moves ``f_lineno`` off the raise."""

    def raises_inside_try() -> None:
        try:
            raise KeyError("synthetic")
        finally:
            _ = None

    with pytest.raises(KeyError) as caught:
        raises_inside_try()
    where = service_module._engine_frame(caught.value)
    raised_at = inspect.getsourcelines(raises_inside_try)[1] + 2
    assert where is not None and where.endswith(f":{raised_at} in raises_inside_try"), where


def test_the_login_error_detail_holds_only_names_the_code_defines() -> None:
    """BACKLOG #3196, #3727: the code, ldap3's name for it and the engine's name for the operation,
    and the interpreter error an ldap3 socket error merges in, which tells a CA mismatch from a
    refused port. None of the text."""
    import ssl

    from ldap3.core.exceptions import LDAPSocketOpenError, communication_exception_factory

    unanswered = ldap_module._unanswered("user search", 51)
    assert service_module._directory_error_detail(unanswered) == {
        "reason": "directory_error",
        "error": "LdapUnansweredError",
        "code": 51,
        "code_name": "busy",
        "operation": "user search",
    }
    merged = communication_exception_factory(
        LDAPSocketOpenError, ssl.SSLCertVerificationError("synthetic")
    )(f"socket ssl wrapping error: {_ADDRESSES}")
    failed = ldap_module._ldap3_failed(merged)
    failed.__cause__ = merged
    detail = service_module._directory_error_detail(failed)
    assert detail == {
        "reason": "directory_error",
        "error": "LdapError",
        "cause": "ldap3.core.exceptions.LDAPSocketOpenError",
        "interpreter_error": "SSLCertVerificationError",
    }
    assert "10.20.30.40" not in str(detail)


#: The callers of the authenticator that keep their own reading of a fault, and why.
_OWN_FAULT_READING = {
    # Reads any other fault as a probe fault, which alerts (BACKLOG #3100).
    "_probe_principal",
}


def _uses_of_the_authenticator(source: str) -> tuple[set[str], set[str], list[str]]:
    """Every read of an ``_ldap`` attribute in ``source``, sorted three ways: the functions that
    hand one of its methods to ``_ask_directory``, those that hand one to ``asyncio.to_thread``
    directly, and every other read, which is a stray.

    BACKLOG #3017 L7. The guard this replaced matched only the literal shape
    ``to_thread(self._ldap.X, ...)``. A method called on the event loop, an alias
    (``ldap = self._ldap``), a ``getattr`` or a ``partial`` passed it. Here only a comparison
    (``self._ldap is None``) and an assignment to the attribute are not reads of the authenticator,
    and the attribute's name as a string, as ``getattr(self, "_ldap")`` reads it, is a stray too.
    Not caught, at least: a name built at runtime, and a read through another object that holds
    the authenticator under another name.
    """
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def enclosing(node: ast.AST) -> str:
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                return node.name
        return "<module>"

    mapped: set[str] = set()
    direct: set[str] = set()
    stray: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "_ldap":
            # The attribute reached by name, as getattr(self, "_ldap") or vars(self)["_ldap"].
            stray.append(f"line {node.lineno} in {enclosing(node)}: {ast.unparse(parents[node])}")
            continue
        if not (isinstance(node, ast.Attribute) and node.attr == "_ldap"):
            continue
        parent = parents[node]
        if isinstance(parent, ast.Compare):
            continue
        if isinstance(parent, ast.Assign | ast.AnnAssign) and node is not parent.value:
            continue
        if isinstance(parent, ast.Attribute):
            call = parents.get(parent)
            if isinstance(call, ast.Call) and call.args and call.args[0] is parent:
                if isinstance(call.func, ast.Name) and call.func.id == "_ask_directory":
                    mapped.add(enclosing(node))
                    continue
                if isinstance(call.func, ast.Attribute) and call.func.attr == "to_thread":
                    direct.add(enclosing(node))
                    continue
        stray.append(f"line {node.lineno} in {enclosing(node)}: {ast.unparse(parent)}")
    return mapped, direct, stray


def test_the_authenticator_guard_catches_each_shape_the_literal_match_missed() -> None:
    """The control for the guard below: each planted shape is a stray, and the two allowed shapes
    are sorted as allowed."""
    planted = (
        "async def ok(self):\n"
        "    if self._ldap is None:\n"
        "        return\n"
        "    await _ask_directory(self._ldap.resolve_principal, 'a')\n"
        "async def raw(self):\n"
        "    await asyncio.to_thread(self._ldap.probe_principal, 'a')\n"
        "async def on_the_loop(self):\n"
        "    self._ldap.authenticate('a', 'b')\n"
        "async def alias(self):\n"
        "    ldap = self._ldap\n"
        "    await asyncio.to_thread(ldap.authenticate, 'a', 'b')\n"
        "async def by_name(self):\n"
        "    await asyncio.to_thread(getattr(self._ldap, 'authenticate'), 'a', 'b')\n"
        "async def bound_later(self):\n"
        "    await _ask_directory(partial(self._ldap.authenticate, 'a'), 'b')\n"
        "async def by_string(self):\n"
        "    getattr(self, '_ldap').authenticate('a', 'b')\n"
    )
    mapped, direct, stray = _uses_of_the_authenticator(planted)
    assert mapped == {"ok"} and direct == {"raw"}
    assert sorted(line.split(" in ")[1].split(":")[0] for line in stray) == [
        "alias",
        "bound_later",
        "by_name",
        "by_string",
        "on_the_loop",
    ], stray


def test_every_sign_in_and_step_up_leg_asks_the_directory_through_the_mapper() -> None:
    """A new ``asyncio.to_thread(self._ldap.<call>, ...)``, or any other way to reach the
    authenticator, would bring back the unmapped fault."""
    source = Path(inspect.getfile(service_module)).read_text(encoding="utf-8")
    mapped, direct, stray = _uses_of_the_authenticator(source)
    assert stray == []
    assert direct == _OWN_FAULT_READING, direct
    assert {
        "_authenticate_kerberos",
        "_authenticate_oidc",
        "complete_oidc_step_up",
        "_reauth_ad",
        "create_directory_account",
    } <= mapped, mapped
