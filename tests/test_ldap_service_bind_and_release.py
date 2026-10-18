# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3017: what ``auth/ldap.py`` answers when the directory fails, and what it leaves open.

Five properties are pinned, each with the test that failed before the change:

* a second connect that fails answers an absent account and a present one alike, and a plain wrong
  user name on a healthy directory still reads as a failed sign-in, through a real ldap3 stack;
* an ldap3 error's text, which can list every address the engine tried, never reaches the
  ``LdapError`` or the ``auth.login_error`` row;
* ``authenticate`` and ``probe_principal`` unbind the service account's connection on every path;
* a service-account bind refused with a referral is refused as a referral, and any other refusal
  names its result code, through a real ldap3 stack;
* a sign-in or step-up leg answers a directory error for any fault the authenticator raises, with
  its audit row (vault BACKLOG #3100 item 11).

Synthetic data only; nothing here touches PHI.
"""

from __future__ import annotations

import ast
import inspect
import logging
from pathlib import Path
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
from tests.test_ldap_timeouts import _ad_settings, _install_fakes, _shape_search

#: Stands for the addresses an ``LDAPSocketOpenError`` lists. It must never reach an error or a row.
_ADDRESSES = "[('10.20.30.40', 636), ('fd00::synthetic-leak-3017', 636)]"
_PASSWORD = "synthetic-user-pw-3017"
_SERVICE_DN = "CN=svc,DC=example,DC=com"  # tests/test_ldap_timeouts.py's ad_bind_dn
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
    settings = _ad_settings(kerberos_enabled=True)
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
    assert "ldap3 raised LDAPSocketOpenError" in rows[0]
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


def test_a_failed_service_unbind_does_not_change_the_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The block has answered by then, so an unbind failure is suppressed, as
    ``read_bind_account``'s is."""
    _install_fakes(monkeypatch)
    base = ldap3.Connection

    class FailingServiceUnbind(base):  # type: ignore[misc, valid-type]
        def unbind(self) -> None:
            if self._bind_dn == _SERVICE_DN:
                raise ldap3.core.exceptions.LDAPSocketSendError("synthetic")
            super().unbind()

    monkeypatch.setattr(ldap3, "Connection", FailingServiceUnbind)
    probe = LdapAuthenticator(_ad_settings()).probe_principal("alice")
    assert probe.answer is DirectoryAnswer.FOUND


# --- (f) a refused service-account bind, through a real ldap3 stack -----------------------------


def test_a_service_bind_referral_with_no_referral_field_is_a_referral() -> None:
    """ldap3 decodes a referral result with no referral field, and raises a plain
    ``LDAPBindError`` for it from the ``auto_bind``. Before #3017 that read as a directory failure,
    which the session reconciler reads as an outage. A referral that carries its hosts never
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
        "AD ended the service-account bind with result code 49 (invalidCredentials)"
    )
    assert "[auth].ad_bind_dn or its password is wrong" in str(err.value)
    assert dc.searches == []


def test_a_refusal_whose_connection_cannot_be_found_names_the_type_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Raised from anywhere but ldap3's ``_do_auto_bind``, no connection is read, and the text
    claims no result code and carries none of ldap3's."""
    _install_fakes(monkeypatch)
    _faulting(monkeypatch, at="open", fault=ldap3.core.exceptions.LDAPBindError("synthetic"))
    with pytest.raises(LdapError) as err:
        LdapAuthenticator(_ad_settings()).probe_principal("alice")
    assert not isinstance(err.value, LdapReferralError)
    assert str(err.value) == "AD refused the service-account bind; ldap3 raised LDAPBindError"


def test_the_ldap3_names_the_auto_bind_reading_relies_on_exist() -> None:
    """``_auto_binding_connection`` finds the refused connection by these names. A rename in ldap3
    would make every refusal read as an unreadable one, so pin them."""
    module, method = ldap_module._AUTO_BIND_FRAME
    assert ldap3.Connection.__module__ == module
    assert "raise LDAPBindError" in inspect.getsource(getattr(ldap3.Connection, method))


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
    assert len(rows) == 1 and "directory call failed: unexpected TypeError" in rows[0], rows
    assert "synthetic-leak" not in rows[0]
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
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


#: The callers of the authenticator that keep their own reading of a fault, and why.
_OWN_FAULT_READING = {
    # Reads any other fault as a probe fault, which alerts (BACKLOG #3100).
    "_probe_principal",
    # Not a sign-in or step-up leg: an administrator's route, which BACKLOG #3017 does not name.
    "create_directory_account",
}


def test_every_sign_in_and_step_up_leg_asks_the_directory_through_the_mapper() -> None:
    """A new ``asyncio.to_thread(self._ldap.<call>, ...)`` would bring back the unmapped fault."""
    tree = ast.parse(Path(inspect.getfile(service_module)).read_text(encoding="utf-8"))
    direct: set[str] = set()
    mapped: set[str] = set()
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(func):
            if not (isinstance(node, ast.Call) and node.args):
                continue
            target = node.args[0]
            if not (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "_ldap"
            ):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "_ask_directory":
                mapped.add(func.name)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "to_thread":
                direct.add(func.name)
    assert direct == _OWN_FAULT_READING, direct
    assert {
        "_authenticate_kerberos",
        "_authenticate_oidc",
        "complete_oidc_step_up",
        "_reauth_ad",
    } <= mapped, mapped
