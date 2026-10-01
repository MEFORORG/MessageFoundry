# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2494: LDAPS wraps its socket with a context the engine built, and still gets ldap3's checks.

``messagefoundry.auth.ldap_tls.NarrowedTls`` replaces ldap3's ``Tls.wrap_socket`` so the engine can
narrow TLS 1.3 too. These tests drive the REAL override over a connected socket pair against a TLS
server thread, so each claim is a handshake rather than an attribute read:

* the anchored CA verifies, a foreign CA is refused, and ldap3's own host name check still runs
  after the handshake (and still does not run with verification off, as in ldap3);
* the copy of ldap3's wrap step is pinned to the ldap3 source it was taken from;
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


def _open_ldaps(tls: Any, server: ssl.SSLContext) -> Any:
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
                "127.0.0.1",
                port=port,
                use_ssl=True,
                tls=tls,
                get_info=ldap3.NONE,
                connect_timeout=10,
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


def test_a_dc_outside_the_anchor_is_refused(pki: _Pki, tmp_path: Path) -> None:
    """``ca_certs_data`` reaches the engine's context: a CA other than the anchor is refused."""
    other_ca, _key = _self_signed(tmp_path)
    with pytest.raises(ssl.SSLCertVerificationError):
        _bind(_tls(other_ca.read_text()), _server(pki))


def test_with_verification_off_ldap3_skips_the_host_name_check_as_before(pki: _Pki) -> None:
    """ldap3 runs its name check only for ``CERT_REQUIRED`` or ``CERT_OPTIONAL``. The override keeps
    that, so ``ad_tls_verify=false`` (refused at startup unless escaped) behaves as it did."""
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
