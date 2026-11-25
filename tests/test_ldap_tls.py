# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2494: LDAPS wraps its socket with a context the engine built, and still gets ldap3's checks.

``messagefoundry.auth.ldap_tls.NarrowedTls`` replaces ldap3's ``Tls.wrap_socket`` so the engine can
narrow TLS 1.3 too. These tests drive the REAL override over a connected socket pair against a TLS
server thread, so each claim is a handshake rather than an attribute read:

* the anchored CA verifies, a foreign CA is refused, and ldap3's own host name check still runs
  after the handshake (and still does not run with verification off, as in ldap3);
* a host name refusal closes the TLS socket it wrapped, where ldap3's own ``Tls``, the control,
  leaves it open while the refusal's traceback is held (BACKLOG #3017);
* the copy of ldap3's wrap step is pinned to the ldap3 source it was taken from;
* the ClientHello names the host each connection dials, normalised, where ldap3's own ``Tls``, the
  control, sends no SNI, and the host name check gets the host less its trailing dot (BACKLOG #6879);
* on an interpreter with ``SSLContext.set_ciphersuites`` (CPython 3.15) the hop refuses a TLS 1.3
  peer offering only ``TLS_AES_128_GCM_SHA256``, while ldap3's own ``Tls`` accepts it as the
  control, and the bind constructs instead of refusing. On 3.14 the paired test measures the
  recorded gap.

The per-hop CBC, AES-128 and suite-order handshakes live with every other hop, in
``tests/test_tls_default_suites.py``.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import socket
import ssl
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import ldap3
import pytest
from ldap3.core.exceptions import LDAPCertificateError, LDAPSocketOpenError

from messagefoundry.auth import ldap as ldap_auth
from messagefoundry.auth.ldap_tls import NarrowedTls
from messagefoundry.config import tls_policy
from tests.test_tls_cipher_assertion_sites import _ad_settings, _self_signed
from tests.test_tls_default_suites import (
    _DEFAULT_SUITE_NAMES,
    CBC_ONLY,
    _Pki,
    _tls12,
    _tls13,
)
from tests.test_tls_default_suites import pki as pki  # noqa: F401  (the fixture, re-exported)

#: sha256 of ``inspect.getsource(ldap3.Tls.wrap_socket)`` in ldap3 2.9.1, line endings as ``\n``.
_LDAP3_WRAP_SOCKET_SHA256 = "428733b595fea962ca8d0132986fef7aea2df98031bb0efeac450f2506d4c0cd"

_TLS13_AES128 = tls_policy._TLS13_AES128_SUITE
_has_set_ciphersuites = hasattr(ssl.SSLContext, "set_ciphersuites")
_FULL_WIDTH_DOT = chr(0x3002)  # IDEOGRAPHIC FULL STOP, which IDNA maps to "."


def _tls(ca_pem: str, validate: ssl.VerifyMode = ssl.CERT_REQUIRED) -> NarrowedTls:
    """The engine's ``Tls`` for a bind anchored at ``ca_pem``, built as ``LdapAuthenticator`` does."""
    return NarrowedTls(validate=validate, ca_certs_data=ca_pem, connector="LDAPS (test)")


def _server(pki: _Pki, *, tls13_only_aes128: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki.cert, pki.key)
    if tls13_only_aes128:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        cast(Any, ctx).set_ciphersuites(_TLS13_AES128)  # a 3.15 method; typeshed gates it
    return ctx


def _bind(tls: Any, server: ssl.SSLContext, host: str = "localhost") -> tuple[str, str]:
    """Run ``tls.wrap_socket`` with a handshake, as ldap3 does for LDAPS, against ``server`` on the
    other end of a socket pair. Returns ``(suite, protocol)``; raises what the client raised."""
    left, right = socket.socketpair()
    left.settimeout(10)
    right.settimeout(10)
    release = threading.Event()

    def serve() -> None:
        with contextlib.suppress(ssl.SSLError, OSError):
            wrapped = server.wrap_socket(right, server_side=True)
            release.wait(10)
            wrapped.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    conn = SimpleNamespace(socket=left, server=SimpleNamespace(host=host))
    try:
        tls.wrap_socket(conn, do_handshake=True)
        cipher = conn.socket.cipher()
        assert cipher is not None
        return str(cipher[0]), str(cipher[1])
    finally:
        release.set()
        conn.socket.close()
        left.close()
        right.close()
        thread.join(10)


def _open_ldaps(tls: Any, server: ssl.SSLContext, host: str = "127.0.0.1") -> Any:
    """Open a real ``ldap3.Connection`` to ``server`` on a loopback port, so the TLS goes through
    ldap3's own call site rather than a direct ``wrap_socket`` call. Returns the TLS socket ldap3
    kept; the caller closes it. ldap3 raises its own ``LDAPSocketOpenError`` on a refusal."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)
    port = listener.getsockname()[1]

    def serve() -> None:
        with contextlib.suppress(ssl.SSLError, OSError):
            raw, _addr = listener.accept()
            raw.settimeout(10)
            with server.wrap_socket(raw, server_side=True):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        conn = ldap3.Connection(
            ldap3.Server(
                host,
                port=port,
                use_ssl=True,
                tls=tls,
                get_info=ldap3.NONE,
                connect_timeout=10,
                mode=ldap3.IP_V4_ONLY,  # the listener is IPv4: a refused ::1 costs 2 s on Windows
            ),
            receive_timeout=10,
        )
        conn.open()
        return conn.socket
    finally:
        listener.close()
        thread.join(10)


@pytest.mark.skipif(CBC_ONLY not in _DEFAULT_SUITE_NAMES, reason="default lacks the CBC suite")
def test_a_real_ldap3_connection_uses_the_narrowed_context(pki: _Pki) -> None:
    """Through ``ldap3.Connection.open``, ldap3's real call site. A DC offering only a CBC-SHA2
    suite is refused by the engine's ``Tls`` and accepted by ldap3's own, the control, so the
    refusal can only come from the override having run. Verification is off in both, because the
    connection is to an IP address the test leaf does not name; the suite is what is measured."""
    cbc_server = _server(pki)
    cbc_server.maximum_version = ssl.TLSVersion.TLSv1_2
    cbc_server.set_ciphers(CBC_ONLY)
    control = _open_ldaps(ldap3.Tls(validate=ssl.CERT_NONE), cbc_server)
    try:
        assert control.cipher()[0] == CBC_ONLY
    finally:
        control.close()
    with pytest.raises(LDAPSocketOpenError):
        _open_ldaps(_tls(Path(pki.ca).read_text(), ssl.CERT_NONE), cbc_server)

    engine = _open_ldaps(_tls(Path(pki.ca).read_text(), ssl.CERT_NONE), _server(pki))
    try:
        assert _tls12(engine.context) == list(tls_policy.APPROVED_TLS12_SUITES)
    finally:
        engine.close()


def test_ldap3_wrap_socket_is_the_one_narrowed_tls_copies() -> None:
    """``NarrowedTls.wrap_socket`` copies ldap3's wrap step. If ldap3 changes that method, this goes
    red: read the new source, carry over what changed, then update the hash."""
    source = inspect.getsource(ldap3.Tls.wrap_socket).replace("\r\n", "\n")
    assert hashlib.sha256(source.encode()).hexdigest() == _LDAP3_WRAP_SOCKET_SHA256, (
        f"ldap3 {ldap3.__version__} changed Tls.wrap_socket; re-derive messagefoundry/auth/"
        f"ldap_tls.py against it before updating the pinned hash"
    )


def test_a_verifying_bind_completes_against_a_dc_the_anchor_signed(pki: _Pki) -> None:
    """The positive control for every refusal below, and the suite is an approved one."""
    suite, _protocol = _bind(_tls(Path(pki.ca).read_text()), _server(pki))
    assert suite in tls_policy._APPROVED_TLS_SUITES


def test_ldap3s_host_name_check_still_runs_after_the_handshake(pki: _Pki) -> None:
    """The engine's context leaves ``check_hostname`` off, as ldap3's does, because ldap3 checks the
    name itself after the handshake. The override must still call that check. Same server as the
    control above; only the name ldap3 checks against differs."""
    with pytest.raises(LDAPCertificateError):
        _bind(_tls(Path(pki.ca).read_text()), _server(pki), host="dc1.example.test")


def _close_held_tls_sockets(refusal: BaseException) -> None:
    """Close whatever TLS socket a refusal's frames still hold, so a control that leaks one ends
    cleanly rather than at the collector."""
    tb = refusal.__traceback__
    while tb is not None:
        for leaked in list(tb.tb_frame.f_locals.values()):
            if isinstance(leaked, ssl.SSLSocket):
                leaked.close()
        tb = tb.tb_next


def _dc_sees_the_end_of_a_host_name_refusal(tls: Any, pki: _Pki, wait: float) -> bool:
    """Run ``tls.wrap_socket`` against a TLS listener on localhost whose leaf names ``localhost``
    while the bind checks ``dc1.example.test``, so the handshake completes and the host name check
    refuses. With the refusal still held, its traceback keeps every frame alive. Returns whether
    the listener saw the connection end within ``wait`` seconds."""
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)
    ended = threading.Event()
    server = _server(pki)

    def serve() -> None:
        # The client may close before this side's handshake finishes, so an end read during the
        # handshake counts as well as one read after it. A timeout is not an end.
        try:
            raw, _addr = listener.accept()
            raw.settimeout(10)
            with server.wrap_socket(raw, server_side=True) as wrapped:
                if wrapped.recv(1) == b"":
                    ended.set()
        except TimeoutError:
            pass
        except OSError:
            ended.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = socket.create_connection(listener.getsockname(), timeout=10)
    conn = SimpleNamespace(socket=client, server=SimpleNamespace(host="dc1.example.test"))
    held: LDAPCertificateError | None = None
    try:
        try:
            tls.wrap_socket(conn, do_handshake=True)
        except LDAPCertificateError as refused:
            held = refused
        assert held is not None, "the host name check did not refuse"
        return ended.wait(timeout=wait)
    finally:
        if held is not None:
            _close_held_tls_sockets(held)
        held = None
        conn.socket.close()
        client.close()
        listener.close()
        thread.join(10)


def test_a_host_name_refusal_closes_the_tls_socket_it_wrapped(pki: _Pki) -> None:
    """A real host name mismatch after a completed handshake: the engine's ``Tls`` closes the TLS
    socket it wrapped, so the domain controller sees the end while the refusal is still held.
    ldap3's own ``Tls`` is the control: it leaves that socket open while the refusal is held, so
    the same instrument sees no end. The rule this pins is stated once, in
    :func:`messagefoundry.auth.ldap._close_without_sending` (BACKLOG #3017)."""
    ca = Path(pki.ca).read_text()
    control = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=ca)
    assert not _dc_sees_the_end_of_a_host_name_refusal(control, pki, wait=1), (
        "the control saw an end, so the instrument cannot tell a closed socket from a leaked one"
    )
    assert _dc_sees_the_end_of_a_host_name_refusal(_tls(ca), pki, wait=5), (
        "the domain controller never saw the TLS socket close"
    )


def test_a_dc_outside_the_anchor_is_refused(pki: _Pki, tmp_path: Path) -> None:
    """``ca_certs_data`` reaches the engine's context: a CA other than the anchor is refused."""
    other_ca, _key = _self_signed(tmp_path)
    with pytest.raises(ssl.SSLCertVerificationError):
        _bind(_tls(other_ca.read_text()), _server(pki))


def test_with_verification_off_ldap3_skips_the_host_name_check_as_before(pki: _Pki) -> None:
    """ldap3 runs its name check only for ``CERT_REQUIRED`` or ``CERT_OPTIONAL``. The override keeps
    that, so ``ad_tls_verify=false`` (refused at startup since vault BACKLOG #3230) behaves as it did."""
    suite, _protocol = _bind(
        _tls(Path(pki.ca).read_text(), ssl.CERT_NONE), _server(pki), host="dc1.example.test"
    )
    assert suite in tls_policy._APPROVED_TLS_SUITES


# --- TLS 1.3: the reason for BACKLOG #2494 --------------------------------------------------------


@pytest.mark.skipif(not _has_set_ciphersuites, reason="needs SSLContext.set_ciphersuites (3.15)")
def test_on_315_the_ldaps_bind_constructs_and_offers_no_tls13_aes128() -> None:
    """Before #2494 the assertion refused LDAPS here: ldap3's context kept ``TLS_AES_128_GCM_SHA256``
    and the allow-list had dropped it. Now the bind constructs, and its context offers exactly the
    approved TLS 1.3 list."""
    tls = ldap_auth.LdapAuthenticator(_ad_settings())._tls
    assert tls is not None
    ctx = tls._context_factory()
    assert _tls13(ctx) == list(tls_policy.APPROVED_TLS13_SUITES)
    assert _TLS13_AES128 not in tls_policy._APPROVED_TLS_SUITES


@pytest.mark.skipif(not _has_set_ciphersuites, reason="needs SSLContext.set_ciphersuites (3.15)")
def test_on_315_the_ldaps_bind_refuses_a_tls13_aes128_only_dc(pki: _Pki) -> None:
    """A real TLS 1.3 handshake against a DC offering only AES-128. The control is ldap3's own
    ``Tls`` with the same anchor, which completes: without it the refusal could be a broken peer."""
    control = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=Path(pki.ca).read_text())
    assert _bind(control, _server(pki, tls13_only_aes128=True)) == (_TLS13_AES128, "TLSv1.3")
    with pytest.raises(ssl.SSLError):
        _bind(_tls(Path(pki.ca).read_text()), _server(pki, tls13_only_aes128=True))


@pytest.mark.skipif(_has_set_ciphersuites, reason="measures the 3.14 gap; 3.15 has its own tests")
def test_on_314_the_ldaps_bind_keeps_the_recorded_tls13_gap() -> None:
    """The 3.14 arm. No API can drop ``TLS_AES_128_GCM_SHA256`` here, so the LDAPS context offers
    what a stock one does at TLS 1.3, and the allow-list admits it (``narrow_tls13_suites``)."""
    tls = ldap_auth.LdapAuthenticator(_ad_settings())._tls
    assert tls is not None
    ctx = tls._context_factory()
    assert _tls13(ctx) == _tls13(ssl.create_default_context())
    assert _TLS13_AES128 in tls_policy._APPROVED_TLS_SUITES


# --- SNI: each bind names its own directory host (BACKLOG #6879) ----------------------------------


def _sni_server(pki: _Pki, seen: list[str | None]) -> ssl.SSLContext:
    """A DC context that records the ``server_name`` each ClientHello carried, ``None`` for none."""
    server = _server(pki)

    def record(_sock: ssl.SSLObject, name: str | None, _ctx: ssl.SSLContext) -> None:
        seen.append(name)

    server.sni_callback = record
    return server


def test_the_bind_names_the_directory_host_in_sni(pki: _Pki) -> None:
    """One engine ``Tls`` serves every configured server, so each name is the host that connection
    dials. ldap3's own ``Tls``, the control, sends none."""
    seen: list[str | None] = []
    server = _sni_server(pki, seen)
    _bind(ldap3.Tls(validate=ssl.CERT_NONE), server)
    assert seen == [None]

    seen.clear()
    tls = _tls(Path(pki.ca).read_text(), ssl.CERT_NONE)
    _bind(tls, server, host="dc1.example.test")
    _bind(tls, server, host="dc2.example.test")
    assert seen == ["dc1.example.test", "dc2.example.test"]

    seen.clear()
    tls.sni = "LDAP.Example.Test."  # ldap3's own attribute: the engine never sets it or reads it
    _bind(tls, server, host="dc1.example.test")
    tls.sni = "127.0.0.1"
    _bind(tls, server, host="dc2.example.test")
    assert seen == ["dc1.example.test", "dc2.example.test"]


def test_a_trailing_dot_host_verifies_without_its_dot(pki: _Pki) -> None:
    """``localhost.`` matches a leaf naming ``localhost``. ldap3's own ``Tls``, the control, checks
    the host as written and refuses."""
    ca = Path(pki.ca).read_text()
    control = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=ca)
    with pytest.raises(LDAPCertificateError) as refused:
        _bind(control, _server(pki), host="localhost.")
    _close_held_tls_sockets(refused.value)
    seen: list[str | None] = []
    _bind(_tls(ca), _sni_server(pki, seen), host="localhost.")
    assert seen == ["localhost"]


@pytest.mark.parametrize(
    ("host", "checked"),
    [
        ("stra" + chr(0xDF) + "e.example.test", "stra" + chr(0xDF) + "e.example.test"),
        ("127.0.0.1", "127.0.0.1"),
        ("dc1.example.test.", "dc1.example.test"),
    ],
)
def test_the_host_name_check_gets_the_host_not_its_idna_form(
    pki: _Pki, host: str, checked: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """IDNA 2003 maps sharp s to ``ss``, so checking the IDNA form would let a certificate for a
    different name match. The check gets the host less its trailing dot, and an IP literal, which
    sends no SNI, is checked as itself."""
    names: list[str] = []
    monkeypatch.setattr(
        "messagefoundry.auth.ldap_tls.check_hostname",
        lambda _sock, name, _extra: names.append(name),
    )
    _bind(_tls(Path(pki.ca).read_text()), _server(pki), host=host)
    assert names == [checked]


def test_a_real_ldap3_connection_sends_its_server_host_as_sni(pki: _Pki) -> None:
    """Through ``ldap3.Connection.open``, so the host is the one ldap3 itself hands the wrap step,
    not a stand-in's attribute. Verification is on: the name adds no stdlib host name check,
    because the engine's context leaves ``check_hostname`` off."""
    seen: list[str | None] = []
    sock = _open_ldaps(_tls(Path(pki.ca).read_text()), _sni_server(pki, seen), host="localhost")
    sock.close()
    assert seen == ["localhost"]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", None),
        ("::1", None),
        ("fe80::1%2", None),
        ("127.1", None),
        ("0x7f.1", None),
        ("127" + _FULL_WIDTH_DOT + "1", None),
        ("dc1.example.test.", "dc1.example.test"),
        ("dc1.example.test" + _FULL_WIDTH_DOT, "dc1.example.test"),
        ("dc" + chr(0xE9) + ".example.test", "xn--dc-cja.example.test"),
        ("a" * 64 + ".test", None),
        ("a." * 126 + "b", "a." * 126 + "b"),  # 253 bytes, a DNS name's limit
        ("a." * 130 + "b", None),  # 261 bytes: OpenSSL would refuse it at the wrap
        ("DC1.Example.Test", "dc1.example.test"),
    ],
)
def test_the_sni_name_is_normalised(pki: _Pki, host: str, expected: str | None) -> None:
    """The rules are ``_sni_name``'s. The stdlib already drops a canonical IP literal, so the
    other rows are the engine's. Verification is off because the test leaf names none of these
    hosts; the ClientHello is what is measured."""
    seen: list[str | None] = []
    _bind(_tls(Path(pki.ca).read_text(), ssl.CERT_NONE), _sni_server(pki, seen), host=host)
    assert seen == [expected]
