# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2566: a socket fault that is not an ldap3 error still maps to ``LdapError``.

ldap3 wraps most socket faults in its own ``LDAPException`` subclasses, and ``auth/ldap.py`` used to
catch only those. An ``OSError``, ``OverflowError``, ``TypeError``, ``ValueError`` or
``struct.error`` raised while opening a socket (BACKLOG #2546 found the ``struct.error``) escaped
unmapped, so no ``LdapError`` handler saw it and the Kerberos and OIDC sign-ins wrote no
``auth.login_error`` row.

Each site is driven through the recording ldap3 doubles of ``tests/test_ldap_timeouts.py``, with one
operation made to raise. Four properties are pinned:

* the fault becomes ``LdapError`` with fixed text that names only its type, and the fault is kept
  as the cause;
* an ``LDAPException`` keeps its own handler and text, even one that is also an ``OSError`` or
  ``TypeError``. That arm is the control, and it fails if the mapper swallows ldap3's own errors;
* a ``TypeError`` where no socket opens is not mapped, because there it is a defect, and mapping
  it would hide the defect as an outage;
* an absent account and a present one fail alike on such a fault (ASVS 6.3.8, #1140), so the decoy
  bind does not swallow it.

PHI-free: synthetic directory names and passwords only.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Any

import ldap3
import pytest

from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.store.store import MessageStore
from tests.test_ldap_timeouts import _ad_settings, _install_fakes, _shape_search

#: Stands for directory data a socket fault's message might carry. It must never reach the text.
_LEAK = "CN=synthetic-leak,OU=Users,DC=example,DC=com"
_PASSWORD = "synthetic-user-pw-2566"

_FAULTS = [
    pytest.param(lambda: OSError(_LEAK), "OSError", id="OSError"),
    pytest.param(lambda: OverflowError(_LEAK), "OverflowError", id="OverflowError"),
    pytest.param(lambda: TypeError(_LEAK), "TypeError", id="TypeError"),
    pytest.param(lambda: ValueError(_LEAK), "ValueError", id="ValueError"),
    pytest.param(lambda: struct.error(_LEAK), "struct.error", id="struct.error"),
]

#: ldap3's own errors that ALSO subclass a mapped type. Each must keep the ldap3 handler.
_LDAP3_ERRORS = [
    pytest.param(
        lambda: ldap3.core.exceptions.LDAPSocketReceiveError("synthetic ldap3 text"),
        id="LDAPSocketReceiveError-is-an-OSError",
    ),
    pytest.param(
        lambda: ldap3.core.exceptions.LDAPAttributeError("synthetic ldap3 text"),
        id="LDAPAttributeError-is-a-TypeError",
    ),
]


def _faulting(monkeypatch: pytest.MonkeyPatch, *, at: str, fault: BaseException) -> None:
    """Make one ldap3 operation raise ``fault``, over the doubles already installed.

    ``at`` is ``"open"`` (the service account's ``auto_bind`` connection), ``"search"``,
    ``"user build"`` (constructing alice's bind connection), ``"user bind"``, ``"decoy bind"``
    (the #1140 equalizing bind) or ``"unbind"``. A bare fault at
    ``open`` or a bind is the shape real ldap3 raises: with one candidate address, ``open()``
    re-raises what ``settimeout`` or ``setsockopt`` raised.
    """
    base = ldap3.Connection  # the recording double, possibly shaped by _shape_search

    class Faulting(base):  # type: ignore[misc, valid-type]
        def __init__(self, server: Any = None, **kwargs: Any) -> None:
            super().__init__(server, **kwargs)
            if at == "open" and kwargs.get("auto_bind"):
                raise fault
            if at == "user build" and str(kwargs.get("user", "")).startswith("CN=alice"):
                raise fault

        def search(self, **kwargs: Any) -> bool:
            if at == "search":
                raise fault
            return bool(super().search(**kwargs))

        def bind(self) -> bool:
            decoy = str(self._bind_dn or "").startswith("CN=mf-nonexistent")
            if at == ("decoy bind" if decoy else "user bind"):
                raise fault
            return bool(super().bind())

        def unbind(self) -> None:
            if at == "unbind":
                raise fault
            super().unbind()

    monkeypatch.setattr(ldap3, "Connection", Faulting)


def _assert_mapped(err: pytest.ExceptionInfo[LdapError], fault: BaseException, name: str) -> None:
    assert str(err.value) == f"AD directory call failed: {name}"
    assert err.value.__cause__ is fault, "the fault must stay chained for a traceback"
    assert _LEAK not in str(err.value), "the fault's own message reached the LdapError text"


# --- probe_principal and resolve_principal: the Kerberos, OIDC and reconciler lookup -------------


@pytest.mark.parametrize(("make", "name"), _FAULTS)
def test_probe_principal_maps_a_socket_fault(
    monkeypatch: pytest.MonkeyPatch, make: Callable[[], BaseException], name: str
) -> None:
    _install_fakes(monkeypatch)
    fault = make()
    _faulting(monkeypatch, at="open", fault=fault)
    authenticator = LdapAuthenticator(_ad_settings())

    with pytest.raises(LdapError) as err:
        authenticator.probe_principal("alice")
    _assert_mapped(err, fault, name)
    # resolve_principal is probe_principal with the answer dropped, so it must map the same way.
    with pytest.raises(LdapError):
        authenticator.resolve_principal("alice")


@pytest.mark.parametrize("at", ["search", "user build", "unbind"])
def test_a_type_error_where_no_socket_opens_is_not_hidden_as_an_outage(
    monkeypatch: pytest.MonkeyPatch, at: str
) -> None:
    """THE NARROWING GUARD. A search or release runs on an open socket, where ldap3 re-raises a
    socket.error as its own error, and building the user connection does no I/O. So a bare
    TypeError at any of them is a defect, such as a bad keyword, and must escape as itself. Mapped,
    the session reconciler would read it as an outage, log it at debug level and never revoke."""
    _install_fakes(monkeypatch)
    _faulting(monkeypatch, at=at, fault=TypeError("synthetic engine defect"))
    authenticator = LdapAuthenticator(_ad_settings())

    with pytest.raises(TypeError, match="synthetic engine defect"):
        if at == "search":
            authenticator.probe_principal("alice")
        else:
            authenticator.authenticate("alice", _PASSWORD)


@pytest.mark.parametrize("make", _LDAP3_ERRORS)
def test_an_ldap3_error_keeps_its_own_handler_and_text(
    monkeypatch: pytest.MonkeyPatch, make: Callable[[], BaseException]
) -> None:
    """THE CONTROL. Each of these is an ldap3 error that is also an OSError or a TypeError. It must
    reach the ldap3 handler, which keeps its own text, and never the fixed socket-fault text."""
    _install_fakes(monkeypatch)
    fault = make()
    _faulting(monkeypatch, at="open", fault=fault)

    with pytest.raises(LdapError) as err:
        LdapAuthenticator(_ad_settings()).probe_principal("alice")
    assert str(err.value) == "synthetic ldap3 text"
    assert err.value.__cause__ is fault


# --- authenticate: the step-up re-bind's directory call -------------------------------------------
#
# AD password sign-in is retired, so authenticate is reached only from the step-up re-bind, which
# reads LdapError as "directory_unavailable" and writes no auth.login_error row. So these assert the
# LdapError, not an audit row.


@pytest.mark.parametrize("at", ["open", "user bind"])
@pytest.mark.parametrize(("make", "name"), _FAULTS)
def test_authenticate_maps_a_socket_fault(
    monkeypatch: pytest.MonkeyPatch, at: str, make: Callable[[], BaseException], name: str
) -> None:
    _install_fakes(monkeypatch)
    fault = make()
    _faulting(monkeypatch, at=at, fault=fault)

    with pytest.raises(LdapError) as err:
        LdapAuthenticator(_ad_settings()).authenticate("alice", _PASSWORD)
    _assert_mapped(err, fault, name)


def test_authenticate_maps_an_ldap3_error_at_the_user_bind_with_its_own_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the arm above: ldap3's own error keeps the ldap3 handler and its text."""
    _install_fakes(monkeypatch)
    fault = ldap3.core.exceptions.LDAPSocketOpenError("synthetic ldap3 text")
    _faulting(monkeypatch, at="user bind", fault=fault)

    with pytest.raises(LdapError, match="^synthetic ldap3 text$"):
        LdapAuthenticator(_ad_settings()).authenticate("alice", _PASSWORD)


@pytest.mark.parametrize(("make", "name"), _FAULTS)
def test_an_absent_and_a_present_account_fail_alike_on_a_socket_fault(
    make: Callable[[], BaseException], name: str
) -> None:
    """ASVS 6.3.8 (#1140). The absent account takes the decoy bind and the present one the real
    bind. Swallowing the fault in the decoy alone would answer "wrong password" for one and
    "directory error" for the other, which tells an attacker the account exists."""
    texts: dict[str, str] = {}
    for branch, uac, at in (("absent", None, "decoy bind"), ("present", "512", "user bind")):
        with pytest.MonkeyPatch.context() as mp:
            _install_fakes(mp)
            _shape_search(mp, uac=uac)
            fault = make()
            _faulting(mp, at=at, fault=fault)
            with pytest.raises(LdapError) as err:
                LdapAuthenticator(_ad_settings()).authenticate("ghost", _PASSWORD)
            _assert_mapped(err, fault, name)
            texts[branch] = str(err.value)
    assert texts["absent"] == texts["present"], texts


# --- read_bind_account: check-privileges ----------------------------------------------------------


@pytest.mark.parametrize(("make", "name"), _FAULTS)
def test_read_bind_account_maps_a_socket_fault_at_the_bind(
    monkeypatch: pytest.MonkeyPatch, make: Callable[[], BaseException], name: str
) -> None:
    _install_fakes(monkeypatch)
    fault = make()
    _faulting(monkeypatch, at="open", fault=fault)

    with pytest.raises(LdapError) as err:
        LdapAuthenticator(_ad_settings()).read_bind_account()
    _assert_mapped(err, fault, name)


# --- where an operator meets it: the audit row ----------------------------------------------------


@pytest.mark.parametrize(("make", "name"), _FAULTS)
async def test_a_socket_fault_on_a_kerberos_sign_in_is_audited_as_a_login_error(
    monkeypatch: pytest.MonkeyPatch, make: Callable[[], BaseException], name: str
) -> None:
    """Before #2566 the fault escaped ``resolve_principal`` unmapped, so this sign-in wrote no
    ``auth.login_error`` row. The row names the fault's type and never its message."""

    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "alice")
    _install_fakes(monkeypatch)
    _faulting(monkeypatch, at="open", fault=make())
    settings = _ad_settings(kerberos_enabled=True)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, settings, ldap=LdapAuthenticator(settings))
        await service.initialize()
        out = await service.authenticate_kerberos(b"spnego-token")

        assert not out.ok
        rows = [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.login_error")]
        assert len(rows) == 1 and f"AD directory call failed: {name}" in rows[0], rows
        assert _LEAK not in rows[0]
        assert await store.list_audit(action="auth.login_success") == []
    finally:
        await store.close()
