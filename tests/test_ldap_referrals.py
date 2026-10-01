# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2530: the AD hop follows no LDAP referral, and a referral is a refusal.

ldap3 2.9.1 follows a referral by default (``Connection(auto_referrals=True)``, and
``Server(allowed_referral_hosts=None)``, which it reads as ``[('*', True)]``). On a bound connection
its ``create_referral_connection`` opens a new connection to the referred host and binds there with
the same user and password, over a plain ``ldap3.Tls`` or none at all. So one referral would carry
the service-account password off the anchored hop.

The end-to-end tests run a REAL ``ldap3`` stack against two loopback servers that speak just enough
of RFC 4511. The first answers the user search with a referral to the second. The second records
every byte it receives, so "not followed" is a count of connections it accepted, and the
positive-control arm shows the same instrument does see the password when both guards are removed.

The primary hop here is plain ``ldap://`` (``ad_allow_insecure_ldap``), because the property under
test is whether ldap3 follows, and that does not depend on the primary's TLS.

PHI-free: synthetic directory names and passwords only.
"""

from __future__ import annotations

import ast
import contextlib
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import ldap3
import pytest
from ldap3.core.results import RESULT_REFERRAL

from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests.test_ldap_timeouts import (
    REFERRAL_RESULT,
    _ad_settings,
    _install_fakes,
    _ldap3_construction_sites,
)

_BIND_PASSWORD = "synthetic-bind-pw"  # what _ad_settings binds the service account with
_USER_PASSWORD = "synthetic-user-pw-2530"

# --- a loopback LDAP server: just enough RFC 4511 BER to bind, search and unbind ------------------

_BIND_REQUEST, _SEARCH_REQUEST, _UNBIND_REQUEST = 0x60, 0x63, 0x42
_BIND_RESPONSE, _SEARCH_DONE = 0x61, 0x65


def _tlv(tag: int, content: bytes) -> bytes:
    """One BER tag-length-value, definite length."""
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def _ldap_result(tag: int, code: int, referrals: tuple[str, ...] = ()) -> bytes:
    """An LDAPResult (RFC 4511 section 4.1.9): code, empty matchedDN and message, the referrals."""
    content = _tlv(0x0A, bytes([code])) + _tlv(0x04, b"") + _tlv(0x04, b"")
    if referrals:
        content += _tlv(0xA3, b"".join(_tlv(0x04, uri.encode()) for uri in referrals))
    return _tlv(tag, content)


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_message(sock: socket.socket) -> tuple[bytes, bytes] | None:
    """One LDAPMessage off the wire: ``(raw bytes, the SEQUENCE's content)``, or ``None`` at EOF."""
    head = _recv_exact(sock, 2)
    if head is None:
        return None
    length, extra = head[1], b""
    if length & 0x80:
        extra = _recv_exact(sock, length & 0x7F) or b""
        length = int.from_bytes(extra, "big")
    body = _recv_exact(sock, length)
    if body is None:
        return None
    return head + extra + body, body


class _FakeDc:
    """A loopback LDAP server. Binds succeed; a search is answered with ``search_referral`` when set,
    else with success and no entries. ``received`` holds every byte any client sent it."""

    def __init__(self, *, search_referral: str | None = None) -> None:
        self._referral = search_referral
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self.accepted = 0
        self.received = bytearray()
        self._lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                sock, _addr = self._listener.accept()
            except OSError:
                return  # the listener was closed
            with self._lock:
                self.accepted += 1
            threading.Thread(target=self._session, args=(sock,), daemon=True).start()

    def _session(self, sock: socket.socket) -> None:
        with sock, contextlib.suppress(OSError):
            sock.settimeout(10)
            while (message := _read_message(sock)) is not None:
                raw, body = message
                with self._lock:
                    self.received += raw
                message_id = body[: 2 + body[1]]  # the messageID INTEGER, echoed verbatim
                op = body[2 + body[1]]
                if op == _BIND_REQUEST:
                    reply = _ldap_result(_BIND_RESPONSE, 0)
                elif op == _SEARCH_REQUEST and self._referral is not None:
                    reply = _ldap_result(_SEARCH_DONE, RESULT_REFERRAL, (self._referral,))
                elif op == _SEARCH_REQUEST:
                    reply = _ldap_result(_SEARCH_DONE, 0)
                else:  # unbind, or anything this server does not speak
                    return
                sock.sendall(_tlv(0x30, message_id + reply))

    def close(self) -> None:
        # shutdown wakes a blocked accept() on Linux, where close() alone does not.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()


@pytest.fixture
def dcs() -> Iterator[tuple[_FakeDc, _FakeDc]]:
    """``(primary, referred)``: the primary refers every search to ``referred``."""
    referred = _FakeDc()
    primary = _FakeDc(
        search_referral=f"ldap://127.0.0.1:{referred.port}/OU=Users,DC=other,DC=example?sub"
    )
    try:
        yield primary, referred
    finally:
        primary.close()
        referred.close()


def _settings(primary: _FakeDc, **over: Any) -> AuthSettings:
    return _ad_settings(
        ad_server=f"ldap://127.0.0.1:{primary.port}", ad_allow_insecure_ldap=True, **over
    )


def _revert(monkeypatch: pytest.MonkeyPatch, *, connection: bool, server: bool) -> None:
    """Put back ldap3's referral defaults on the engine's own constructions, the mutation arms."""
    real_connection, real_server = ldap3.Connection, ldap3.Server

    class Following(real_connection):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["auto_referrals"] = True
            super().__init__(*args, **kwargs)

    class AnyHost(real_server):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs["allowed_referral_hosts"] = None
            super().__init__(*args, **kwargs)

    if connection:
        monkeypatch.setattr(ldap3, "Connection", Following)
    if server:
        monkeypatch.setattr(ldap3, "Server", AnyHost)


# --- end to end, through a real ldap3 stack --------------------------------------------------------


def test_a_referred_search_is_refused_and_the_referred_host_never_hears_from_the_engine(
    dcs: tuple[_FakeDc, _FakeDc],
) -> None:
    """The fix. The primary answers the user search with a referral; the engine raises instead of
    following, and the referred server accepts no connection at all."""
    primary, referred = dcs
    with pytest.raises(LdapError) as refused:
        LdapAuthenticator(_settings(primary)).probe_principal("jsmith")

    assert primary.accepted == 1, "the primary was never asked, so nothing below is measured"
    assert referred.accepted == 0, "the engine followed the referral"
    message = str(refused.value)
    assert "referral" in message and "user search" in message and "127.0.0.1" in message
    # The host is named; the rest of the URL, which is the directory's text, is not.
    assert "DC=other" not in message
    assert _BIND_PASSWORD not in message


@pytest.mark.parametrize(
    ("connection", "server"),
    [(True, False), (False, True)],
    ids=["auto_referrals-reverted", "allowed_referral_hosts-reverted"],
)
def test_each_guard_alone_still_stops_the_follow(
    dcs: tuple[_FakeDc, _FakeDc],
    monkeypatch: pytest.MonkeyPatch,
    connection: bool,
    server: bool,
) -> None:
    """Belt and braces, measured: with either guard put back to ldap3's default, the other still
    stops ldap3 from opening a connection to the referred host."""
    primary, referred = dcs
    _revert(monkeypatch, connection=connection, server=server)
    with pytest.raises(LdapError):
        LdapAuthenticator(_settings(primary)).probe_principal("jsmith")
    assert referred.accepted == 0


def test_with_both_guards_reverted_ldap3_carries_the_bind_password_to_the_referred_host(
    dcs: tuple[_FakeDc, _FakeDc],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE POSITIVE CONTROL, and the defect as it was. With ldap3's defaults back on both, ldap3
    connects to the referred host and binds there with the service-account password, and the search
    comes back as a quiet "no such account". Without this arm, ``accepted == 0`` above could be a
    server that cannot be reached rather than a referral that was not followed."""
    primary, referred = dcs
    _revert(monkeypatch, connection=True, server=True)
    probe = LdapAuthenticator(_settings(primary)).probe_principal("jsmith")

    assert referred.accepted == 1
    assert _BIND_PASSWORD.encode() in bytes(referred.received), (
        "the referred host did not receive the bind password, so this arm no longer shows the leak "
        "the guards exist to stop"
    )
    assert probe.answer is ldap_module.DirectoryAnswer.NOT_FOUND


async def test_a_referred_kerberos_sign_in_is_audited_as_a_login_error(
    dcs: tuple[_FakeDc, _FakeDc], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where an operator meets it: a Windows SSO sign-in whose directory lookup is referred fails as
    ``directory unavailable`` and writes ``auth.login_error`` naming the referral. Nothing reaches
    the referred host, and neither password is on the audit row."""

    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jsmith")
    primary, referred = dcs
    settings = _settings(primary, kerberos_enabled=True)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, settings, ldap=LdapAuthenticator(settings))
        await service.initialize()
        out = await service.authenticate_kerberos(b"spnego-token")

        assert not out.ok
        rows = [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.login_error")]
        assert len(rows) == 1 and "referral" in rows[0] and "user search" in rows[0]
        assert _BIND_PASSWORD not in rows[0]
        assert await store.list_audit(action="auth.login_success") == []
        assert referred.accepted == 0
    finally:
        await store.close()


# --- the user bind and the group search, through the recording doubles ------------------------------


def test_a_referred_user_bind_is_refused_not_read_as_a_wrong_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A referred bind returns ``False`` from ldap3, the same as a rejected password. Read that way,
    the step-up re-bind would count it toward the engine lockout. It raises instead, which the
    re-bind reads as ``directory_unavailable`` and does not count."""
    _install_fakes(monkeypatch, refer="bind")
    with pytest.raises(LdapError, match=r"user bind with a referral to dc9\.other\.example"):
        LdapAuthenticator(_ad_settings()).authenticate("alice", _USER_PASSWORD)


def test_a_referred_group_search_is_refused_not_read_as_no_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A referred nested-group search would otherwise read as "no nested groups", which drops
    roles without a word. It raises on every path that resolves groups."""
    _install_fakes(monkeypatch, refer="group")
    with pytest.raises(LdapError, match="group search"):
        LdapAuthenticator(_ad_settings()).authenticate("alice", _USER_PASSWORD)
    with pytest.raises(LdapError, match="group search"):
        LdapAuthenticator(_ad_settings()).probe_principal("alice")


def test_the_doubles_control_signs_in_when_nothing_is_referred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE CONTROL for the two refusals above: the same doubles, with no referral, sign in."""
    _install_fakes(monkeypatch)
    principal = LdapAuthenticator(_ad_settings()).authenticate("alice", _USER_PASSWORD)
    assert principal is not None and principal.username == "alice"


# --- the refusal's text ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "result",
    [None, {"result": 0}, {"result": 32, "referrals": ["ldap://x/"]}],
    ids=["no-operation-yet", "success", "no-such-object"],
)
def test_only_a_referral_result_is_refused(result: dict[str, Any] | None) -> None:
    ldap_module._refuse_referral(SimpleNamespace(result=result), "user search")


def test_the_doubles_answer_with_ldap3s_referral_code() -> None:
    """The doubles spell the code as a literal; ``_refuse_referral`` reads ldap3's constant."""
    assert REFERRAL_RESULT["result"] == RESULT_REFERRAL


def test_the_refusal_names_hosts_and_nothing_else_the_directory_sent() -> None:
    """An LDAP URL can carry a DN, a filter and a bindname extension (RFC 4516). Only the host is
    named, and a host that is not a plain host name is replaced rather than logged."""
    referrals = [
        "ldap://dc2.other.example:389/DC=other,DC=example??sub?(cn=x)?bindname=CN%3Dsvc",
        "ldap://dc2.other.example/DC=again",
        "ldap://evil\x1b[2Jhost/DC=x",
        "not a url",
    ]
    with pytest.raises(LdapError) as refused:
        ldap_module._refuse_referral(
            SimpleNamespace(result={"result": RESULT_REFERRAL, "referrals": referrals}),
            "user search",
        )
    message = str(refused.value)
    assert "referral to dc2.other.example, <unreadable host>;" in message
    for leaked in ("DC=other", "bindname", "cn=x", "\x1b", "evil"):
        assert leaked not in message


def test_the_refusal_names_a_few_hosts_and_counts_the_rest() -> None:
    """A directory decides how many referrals it sends, so the log line and audit row stay short."""
    referrals = [f"ldap://dc{i}.other.example/" for i in range(5)] + ["ldap://dc_9.corp.example/"]
    with pytest.raises(LdapError) as refused:
        ldap_module._refuse_referral(
            SimpleNamespace(result={"result": RESULT_REFERRAL, "referrals": referrals}), "user bind"
        )
    message = str(refused.value)
    assert "dc0.other.example, dc1.other.example, dc2.other.example and 3 more;" in message
    assert "dc3" not in message
    # An underscore is legal in an AD host name, and the bad-URL placeholder never takes a slot
    # ahead of a readable host.
    assert ldap_module._referred_hosts(["ldap://dc_9.corp.example/"]) == "dc_9.corp.example"
    assert ldap_module._referred_hosts(["not a url"] * 2 + referrals[:3]) == (
        "dc0.other.example, dc1.other.example, dc2.other.example and 1 more"
    )
    assert ldap_module._referred_hosts([]) == "<no host given>"


# --- static: no construction site may bring ldap3's referral defaults back --------------------------


def test_every_search_in_the_ldap_module_goes_through_the_refusing_wrapper() -> None:
    """A search called directly would read a referral as "no entries" again. ``_search`` is the one
    place a ``.search(...)`` call may appear in ``auth/ldap.py``, at any depth, async or not. A
    regular expression's ``.search`` would go red here too; name it in this test if one is added."""
    tree = ast.parse(Path(ldap_module.__file__).read_text(encoding="utf-8"))
    owner = {
        id(node): scope.name
        for scope in ast.walk(tree)
        if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef)
        for statement in scope.body  # the body only: defaults and decorators run outside it
        for node in ast.walk(statement)
    }  # the innermost scope wins: ast.walk visits outer functions first, and later keys overwrite
    callers = [
        owner.get(id(node), "<module>")
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "search"
    ]
    assert callers == ["_search"], callers


def test_every_ldap3_construction_site_turns_referrals_off() -> None:
    """Every ``ldap3.Connection`` in the package passes ``auto_referrals=False`` and every
    ``ldap3.Server`` passes ``allowed_referral_hosts=[]``, both as literals. A new construction site
    that omits either goes red here even if no runtime test reaches it."""
    sites = _ldap3_construction_sites()
    kinds = [attr for attr, _module, _line, _kw in sites]
    assert kinds.count("Server") >= 1 and kinds.count("Connection") >= 3, sites

    def literal(node: ast.expr | None) -> object:
        # Only a literal proves the value at every call; a name or an attribute could be anything.
        try:
            return ast.literal_eval(node) if node is not None else "<absent>"
        except ValueError:
            return "<not a literal>"

    wrong = [
        f"{attr} at {module}:{line}"
        for attr, module, line, kwargs in sites
        if (attr == "Connection" and literal(kwargs.get("auto_referrals")) is not False)
        or (attr == "Server" and literal(kwargs.get("allowed_referral_hosts")) != [])
    ]
    assert not wrong, (
        "ldap3 construction site(s) that leave referral following on; ldap3 would re-send the "
        f"bind credentials to whatever host a referral names (BACKLOG #2530): {wrong}"
    )
