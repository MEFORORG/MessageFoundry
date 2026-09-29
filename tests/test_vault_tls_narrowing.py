# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Vault hops handshake on the narrowed context, and still verify the peer (BACKLOG #300).

Owner ruling 2026-09-27 narrowed the library-built TLS contexts to the approved AEAD list.
``tls_policy.assert_hvac_tls_suites`` now returns a factory that builds the Vault hop's context with
urllib3's own constructor and narrows and asserts it. The strict reply adapter calls it for every
new connection and urllib3 handshakes on the result.

A supplied context changes how urllib3 reaches peer verification, so verification is measured here
rather than argued. A Vault hop that silently stops verifying is worse than an unnarrowed one. Each
test below drives a REAL ``hvac.Client``, built by the shipped ``_build_client``, through a real TLS
handshake with a local listener:

* the right operator CA verifies, and the negotiated suite is an approved one;
* a wrong CA, a wrong host name, and no CA at all (the certifi default) are each refused;
* the context trusts ONLY the operator's CA after a handshake, not the OS store as well;
* a CA removed from the file stops verifying on the next connection;
* a peer that offers only a CBC suite is refused, and a plain ``requests`` session that is not
  narrowed reaches the same peer. So the refusal is the narrowing, not a broken listener.

Synthetic data only: the token and the certificates are made up, generated per test.
"""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import select
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.tls_policy import _APPROVED_TLS_SUITES, APPROVED_TLS12_SUITES
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
_BODY = b'{"initialized": true}'
#: What hvac's JSON adapter returns for ``_BODY``.
_REPLY = {"initialized": True}
_PATH = "v1/sys/health"
_CA_ENV = "MEFOR_SECRETS_VAULT_CA_FILE"
#: A CBC suite the interpreter default offers and the approved list does not.
_CBC_ONLY = "ECDHE-ECDSA-AES256-SHA384"

#: Environment that would move where requests or hvac find a CA, or send the hop through a proxy.
_ENV_THAT_MOVES_THE_HOP = (
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


class _Pki(NamedTuple):
    ca: Path
    other_ca: Path
    leaf: Path
    leaf_key: Path
    wrong_name_leaf: Path
    wrong_name_key: Path


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn: str) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(
    ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey, san: x509.GeneralName
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("vault.synthetic.test"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def _write_cert(path: Path, cert: x509.Certificate) -> Path:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> Path:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


@pytest.fixture
def pki(tmp_path: Path) -> _Pki:
    ca, ca_key = _ca("synthetic vault ca")
    other, _other_key = _ca("synthetic unrelated ca")
    leaf, leaf_key = _leaf(ca, ca_key, x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    wrong, wrong_key = _leaf(ca, ca_key, x509.DNSName("other.synthetic.test"))
    return _Pki(
        ca=_write_cert(tmp_path / "ca.pem", ca),
        other_ca=_write_cert(tmp_path / "other-ca.pem", other),
        leaf=_write_cert(tmp_path / "leaf.pem", leaf),
        leaf_key=_write_key(tmp_path / "leaf-key.pem", leaf_key),
        wrong_name_leaf=_write_cert(tmp_path / "wrong.pem", wrong),
        wrong_name_key=_write_key(tmp_path / "wrong-key.pem", wrong_key),
    )


@pytest.fixture(autouse=True)
def _hop_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_THAT_MOVES_THE_HOP:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv(_CA_ENV, raising=False)
    # With no *_proxy variable left, urllib's getproxies() falls back to the host's own system
    # proxy (the Windows Internet Settings, or macOS's), which would send the loopback test Vault
    # through a corporate proxy. Only the proxies a test sets should apply.
    import urllib.request

    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    # hvac reads these once, at import, into hvac.v1's namespace, so an unset env var here would
    # not undo a value the test process started with.
    import hvac.v1  # type: ignore[import-untyped]  # the [vault] extra ships no stubs

    for name in ("VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
        monkeypatch.setattr(hvac.v1, name, None, raising=False)


class _TlsVault:
    """A TLS listener on 127.0.0.1 that answers each request with one small JSON reply.

    Records the suite each completed handshake negotiated. A handshake the client refuses is
    recorded as a failure and the listener carries on, so a refusing client does not hang it.
    """

    def __init__(self, cert: Path, key: Path, *, ciphers: str | None = None) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        if ciphers is not None:
            # TLS 1.2 only, so the suite list below is the whole offer.
            self._ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            self._ctx.set_ciphers(ciphers)
        self.negotiated: list[str] = []
        self.failures = 0
        self._stop = False
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop:
            try:
                raw, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            raw.settimeout(5)
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as conn:
                    cipher = conn.cipher()
                    self.negotiated.append(cipher[0] if cipher else "?")
                    head = b""
                    while b"\r\n\r\n" not in head:
                        data = conn.recv(4096)
                        if not data:
                            break
                        head += data
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Connection: close\r\nContent-Length: "
                        + str(len(_BODY)).encode()
                        + b"\r\n\r\n"
                        + _BODY
                    )
            except (ssl.SSLError, OSError):
                self.failures += 1
                raw.close()

    def __enter__(self) -> _TlsVault:
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop = True
        self._thread.join(timeout=5)
        self._listener.close()


def _relay(client: ssl.SSLSocket, upstream: socket.socket) -> None:
    """Copy bytes both ways between the proxy's TLS socket and the target until either side closes.

    One thread and ``select``, not a thread per direction: one ``SSLSocket`` must not be read and
    written from two threads at once. ``pending()`` covers bytes OpenSSL already decrypted, which
    ``select`` cannot see."""
    while True:
        ready: list[socket.socket] = [client] if client.pending() else []
        if not ready:
            ready, _, _ = select.select([client, upstream], [], [], 5)
            if not ready:
                return
        for side in ready:
            data = side.recv(65536)
            if not data:
                return
            (upstream if side is client else client).sendall(data)


class _TlsProxy:
    """An ``https://`` forward proxy on 127.0.0.1: TLS from the client, then ``CONNECT``, then a relay.

    Records the suite each completed handshake with the CLIENT negotiated, which is the proxy leg this
    file is about. A handshake the client refuses is counted as a failure. A request that is not
    ``CONNECT`` is recorded and answered 502, because nothing in these tests should forward one.
    """

    def __init__(self, cert: Path, key: Path, *, ciphers: str | None = None) -> None:
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        if ciphers is not None:
            self._ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            self._ctx.set_ciphers(ciphers)
        self.negotiated: list[str] = []
        self.failures = 0
        self.forwarded: list[bytes] = []
        self.connects: list[bytes] = []
        #: Connections finished with, whatever happened on them.
        self.handled = 0
        self._stop = False
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop:
            try:
                raw, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            raw.settimeout(5)
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as conn:
                    cipher = conn.cipher()
                    self.negotiated.append(cipher[0] if cipher else "?")
                    head = b""
                    while b"\r\n\r\n" not in head:
                        data = conn.recv(4096)
                        if not data:
                            break
                        head += data
                    if not head:
                        continue  # the client closed without a request
                    method, _, rest = head.partition(b" ")
                    if method != b"CONNECT":
                        self.forwarded.append(head)
                        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        continue
                    target = rest.partition(b" ")[0]
                    self.connects.append(target)
                    host, _, port = target.rpartition(b":")
                    with socket.create_connection((host.decode(), int(port)), timeout=5) as up:
                        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        _relay(conn, up)
            except (ssl.SSLError, OSError):
                self.failures += 1
                raw.close()
            finally:
                self.handled += 1

    def __enter__(self) -> _TlsProxy:
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop = True
        self._thread.join(timeout=5)
        self._listener.close()


@pytest.fixture
def vault(pki: _Pki) -> Iterator[_TlsVault]:
    with _TlsVault(pki.leaf, pki.leaf_key) as server:
        yield server


def _kv_client(url: str) -> Any:
    from messagefoundry.config import secretprovider_vault

    return secretprovider_vault._build_client(url, _TOKEN)


def _transit_client(url: str) -> Any:
    from messagefoundry.store import keyprovider_vault

    return keyprovider_vault._build_client(url, _TOKEN)


@contextlib.contextmanager
def _handshake_contexts() -> Iterator[list[ssl.SSLContext]]:
    """Record the context urllib3 wraps each new socket with, whoever built it."""
    import urllib3.connection
    from urllib3.util.ssl_ import ssl_wrap_socket as real

    seen: list[ssl.SSLContext] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        ctx = kwargs.get("ssl_context")
        assert isinstance(ctx, ssl.SSLContext), "urllib3 no longer passes ssl_context by keyword"
        seen.append(ctx)
        return real(*args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib3.connection, "ssl_wrap_socket", spy)
        yield seen


# --- the right CA verifies, and the suite is an approved one ---------------------------------------


@pytest.mark.parametrize("build", [_kv_client, _transit_client], ids=["kv", "transit"])
def test_the_operator_ca_verifies_and_an_approved_suite_is_negotiated(
    build: Any, pki: _Pki, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    monkeypatch.setenv("MEFOR_STORE_VAULT_CA_FILE", str(pki.ca))
    client = build(vault.url)
    assert client.adapter.get(_PATH) == _REPLY
    assert vault.negotiated, "the listener saw no completed handshake"
    assert all(name in _APPROVED_TLS_SUITES for name in vault.negotiated), vault.negotiated


def test_a_tls12_peer_negotiates_an_approved_tls12_suite(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TLS 1.3 is negotiated in the test above, and 3.14 cannot narrow it, so this forces TLS 1.2.
    A CPython server context prefers its own order, so the listener's ``ALL`` order picks among the
    suites the client offered. It is a positive check and NOT a discriminating one: against an
    unnarrowed client the server picks the same suite. The CBC-only test below is the one that fails
    when the narrowing is gone."""
    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    with _TlsVault(pki.leaf, pki.leaf_key, ciphers="ALL") as server:
        client = _kv_client(server.url)
        assert client.adapter.get(_PATH) == _REPLY
        assert server.negotiated and server.negotiated[0] in APPROVED_TLS12_SUITES, (
            server.negotiated
        )


def test_the_hop_trusts_only_the_operator_ca_after_a_handshake(
    pki: _Pki, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    """urllib3 loads requests' ``verify`` path onto the supplied context. It must not load the OS
    store as well, which it does on a context it builds itself; that would widen a hop the operator
    anchored to one CA."""
    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    client = _kv_client(vault.url)
    factory = client.adapter.session.get_adapter(vault.url)._ssl_context_factory
    assert factory().cert_store_stats()["x509_ca"] == 0, "control: a context starts with no roots"
    with _handshake_contexts() as seen:
        assert client.adapter.get(_PATH) == _REPLY
    assert len(seen) == 1, seen
    assert seen[0].cert_store_stats()["x509_ca"] == 1, seen[0].cert_store_stats()
    assert seen[0].verify_mode == ssl.CERT_REQUIRED


def test_every_connection_gets_a_fresh_context_so_a_removed_ca_stops_verifying(
    pki: _Pki, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """urllib3 loads the CA file onto a context on every connect and never unloads one. A context
    shared by every connection would therefore keep trusting a CA the operator had removed from the
    file, until restart. Each connection gets its own context, so the removal takes effect on the
    next connection, as it did before BACKLOG #300. The listener closes after every reply, so the
    second request opens a new connection."""
    import requests

    anchor = tmp_path / "vault-anchor.pem"
    anchor.write_bytes(pki.ca.read_bytes())
    monkeypatch.setenv(_CA_ENV, str(anchor))
    client = _kv_client(vault.url)
    with _handshake_contexts() as seen:
        assert client.adapter.get(_PATH) == _REPLY
        anchor.write_bytes(pki.other_ca.read_bytes())
        with pytest.raises(requests.exceptions.SSLError, match="CERTIFICATE_VERIFY_FAILED"):
            client.adapter.get(_PATH)
    assert len(seen) == 2 and seen[0] is not seen[1], seen


# --- every way verification should fail, fails ---------------------------------------------------


def test_a_wrong_ca_is_refused(
    pki: _Pki, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    import requests

    monkeypatch.setenv(_CA_ENV, str(pki.other_ca))
    client = _kv_client(vault.url)
    with pytest.raises(requests.exceptions.SSLError, match="CERTIFICATE_VERIFY_FAILED"):
        client.adapter.get(_PATH)


def test_no_ca_falls_back_to_certifi_and_refuses_a_private_ca(
    vault: _TlsVault,
) -> None:
    """Unset, the hop trusts requests' certifi bundle, as it did before. A synthetic CA is not in it.

    The refusal alone cannot tell "certifi loaded" from "no roots at all", and the second would
    break every public-CA Vault. So the context the handshake ran on must hold the bundle."""
    import requests

    client = _kv_client(vault.url)
    with (
        _handshake_contexts() as seen,
        pytest.raises(requests.exceptions.SSLError, match="CERTIFICATE_VERIFY_FAILED"),
    ):
        client.adapter.get(_PATH)
    assert len(seen) == 1, seen
    assert seen[0].cert_store_stats()["x509_ca"] > 1, "the certifi bundle was not loaded"


def test_a_wrong_host_name_is_refused(pki: _Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    with _TlsVault(pki.wrong_name_leaf, pki.wrong_name_key) as server:
        client = _kv_client(server.url)
        with pytest.raises(requests.exceptions.SSLError, match="127.0.0.1|match|mismatch"):
            client.adapter.get(_PATH)


def _recording_adapter(factory: Any) -> Any:
    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    return StrictReplyAdapter(connector="Vault test hop", ssl_context_factory=factory)


def test_an_https_pool_that_is_not_narrowed_is_refused_before_sending(vault: _TlsVault) -> None:
    """The pre-send check holds the narrowing the way it holds the strict head reader: an https
    pool whose class lacks the narrowing is refused, and nothing reaches the listener. Mutation:
    drop that check; the request then handshakes on urllib3's own context."""
    import requests

    from messagefoundry.transports.bounded_read import EgressReplyError

    adapter = _recording_adapter(ssl.create_default_context)
    classes = dict(adapter.poolmanager.pool_classes_by_scheme)
    # The narrowed class's own base: a strict-head https pool that is NOT narrowed.
    classes["https"] = classes["https"].__mro__[1]
    adapter.poolmanager.pool_classes_by_scheme = classes
    session = requests.Session()
    session.mount("https://", adapter)
    with pytest.raises(EgressReplyError, match="did not narrow"):
        session.get(f"{vault.url}/{_PATH}", timeout=5)
    assert vault.negotiated == [], "a handshake reached the listener"


def test_a_hop_through_a_proxy_is_narrowed_too(vault: _TlsVault) -> None:
    """With HTTPS_PROXY set, requests takes the pools from a proxy manager, not the adapter's own.
    Mutation: delete ``StrictReplyAdapter.proxy_manager_for``; red. Structural, and paired with
    the on-wire proxy tests at the end of this file: it checks that the proxy manager's https
    connections take their context from the same factory, and that a cached manager keeps the same
    classes on every call, so it is never briefly un-narrowed or re-wrapped."""
    made: list[ssl.SSLContext] = []

    def factory() -> ssl.SSLContext:
        made.append(ssl.create_default_context())
        return made[-1]

    adapter = _recording_adapter(factory)
    manager = adapter.proxy_manager_for("http://127.0.0.1:9")
    classes = manager.pool_classes_by_scheme
    assert adapter.proxy_manager_for("http://127.0.0.1:9") is manager
    assert manager.pool_classes_by_scheme is classes, "a cached proxy manager was re-wrapped"
    conn = classes["https"].ConnectionCls("127.0.0.1", vault.port)
    with contextlib.suppress(Exception):  # only the context the connect took matters
        conn.connect()
    conn.close()
    assert made and conn.ssl_context is made[0], "the proxied connection skipped the factory"


def test_a_connection_that_will_not_verify_is_refused_before_its_socket_opens(
    vault: _TlsVault,
) -> None:
    """requests sets CERT_NONE for an ``http://`` Vault reached through an ``https://`` proxy; that
    TLS hop is to the proxy, and it carries the token. It used to keep urllib3's own unverified
    context. Since BACKLOG #300's proxy limb it is refused, and before any socket opens. Driven
    against the local listener with CERT_NONE, which is exactly that connection's shape. The
    adapter refuses the case earlier, by name; this is the connection's own backstop."""
    from messagefoundry.transports.bounded_read import EgressReplyError

    made: list[ssl.SSLContext] = []

    def factory() -> ssl.SSLContext:
        made.append(ssl.create_default_context())
        return made[-1]

    manager = _recording_adapter(factory).proxy_manager_for("https://127.0.0.3:9")
    conn = manager.pool_classes_by_scheme["https"].ConnectionCls(
        "127.0.0.1", vault.port, cert_reqs="CERT_NONE"
    )
    with pytest.raises(EgressReplyError, match="verifies no peer"):
        conn.connect()
    conn.close()
    assert made == [], "the factory ran for a connection that does not verify"
    assert vault.negotiated == [] and vault.failures == 0, "a socket reached the listener"


# --- the narrowing is live on the wire -----------------------------------------------------------


def test_a_cbc_only_peer_is_refused_and_an_unnarrowed_client_reaches_it(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    import requests

    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    with _TlsVault(pki.leaf, pki.leaf_key, ciphers=_CBC_ONLY) as server:
        # CONTROL: a plain requests session, which urllib3 does not narrow, handshakes with it.
        plain = requests.get(f"{server.url}/{_PATH}", verify=str(pki.ca), timeout=5)
        assert plain.status_code == 200
        assert server.negotiated == [_CBC_ONLY], server.negotiated

        client = _kv_client(server.url)
        with pytest.raises(requests.exceptions.SSLError):
            client.adapter.get(_PATH)
        assert server.negotiated == [_CBC_ONLY], "the narrowed hop negotiated a CBC suite"


# --- the TLS hop to an https proxy is the engine's too (BACKLOG #300) ---------------------------
#
# requests honours HTTPS_PROXY, HTTP_PROXY and ALL_PROXY by default (and, on Windows, the Internet
# Settings proxy), so an operator's proxy reaches both Vault clients without any engine setting.
# For an https Vault through an https proxy there are two TLS legs: one to the proxy, then one to
# Vault inside the CONNECT tunnel. Before this change urllib3 built the first itself, unnarrowed.


def _proxy_failed_once(server: _TlsProxy) -> bool:
    """Whether the proxy counted exactly one refused handshake, waiting up to five seconds.

    The client raises as soon as it sends its alert, while the listener thread may still be inside
    ``wrap_socket``, so reading the counter at once races that thread."""
    deadline = time.monotonic() + 5
    while server.failures == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    return server.failures == 1


@pytest.fixture
def proxy(pki: _Pki) -> Iterator[_TlsProxy]:
    with _TlsProxy(pki.leaf, pki.leaf_key) as server:
        yield server


def test_an_https_proxy_offering_only_cbc_is_refused_and_an_unnarrowed_client_reaches_it(
    pki: _Pki, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED before the change: the Vault client handshook with this proxy on a CBC suite and read
    Vault's reply through it. The control shows the proxy and the tunnel work, so the refusal is the
    narrowing of the proxy leg and not a broken fixture."""
    import requests

    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    with _TlsProxy(pki.leaf, pki.leaf_key, ciphers=_CBC_ONLY) as cbc_proxy:
        # CONTROL: a plain requests session reaches Vault through this proxy on the CBC suite.
        plain = requests.get(
            f"{vault.url}/{_PATH}",
            verify=str(pki.ca),
            proxies={"https": cbc_proxy.url},
            timeout=5,
        )
        assert plain.status_code == 200
        assert cbc_proxy.negotiated == [_CBC_ONLY], cbc_proxy.negotiated
        assert len(vault.negotiated) == 1, "control: the tunnel did not reach Vault"

        monkeypatch.setenv("HTTPS_PROXY", cbc_proxy.url)
        client = _kv_client(vault.url)
        with pytest.raises(requests.exceptions.RequestException):
            client.adapter.get(_PATH)
        assert cbc_proxy.negotiated == [_CBC_ONLY], "the proxy leg negotiated a CBC suite"
        assert len(vault.negotiated) == 1, "a request crossed the refused proxy leg to Vault"


@pytest.mark.parametrize("build", [_kv_client, _transit_client], ids=["kv", "transit"])
def test_both_legs_through_an_https_proxy_handshake_on_narrowed_verifying_contexts(
    build: Any,
    pki: _Pki,
    vault: _TlsVault,
    proxy: _TlsProxy,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED before the change: the first context, the proxy leg's, offered suites off the list."""
    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    monkeypatch.setenv("MEFOR_STORE_VAULT_CA_FILE", str(pki.ca))
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    client = build(vault.url)
    with _handshake_contexts() as seen:
        assert client.adapter.get(_PATH) == _REPLY
    assert len(seen) == 2, "expected the proxy leg and the Vault leg"
    assert seen[0] is not seen[1], "the two legs shared one context"
    for ctx in seen:
        offered = {str(c["name"]) for c in ctx.get_ciphers()}
        assert offered <= _APPROVED_TLS_SUITES, sorted(offered - _APPROVED_TLS_SUITES)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
        # The operator's one CA, not the OS store as well.
        assert ctx.cert_store_stats()["x509_ca"] == 1, ctx.cert_store_stats()
    assert proxy.negotiated and all(n in _APPROVED_TLS_SUITES for n in proxy.negotiated)
    assert vault.negotiated and all(n in _APPROVED_TLS_SUITES for n in vault.negotiated)
    assert proxy.forwarded == [], "the request was forwarded, not tunnelled"


def test_a_urllib3_that_ignores_the_supplied_proxy_context_is_refused(
    pki: _Pki, vault: _TlsVault, proxy: _TlsProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Which object urllib3's proxy handshake reads is not documented, so the connection checks
    that the proxy leg ran on the context it supplied, before ``CONNECT`` is sent. Simulated here by
    a urllib3 that drops the supplied context and builds its own, the pre-change behaviour."""
    import urllib3.connection

    from messagefoundry.transports.bounded_read import EgressReplyError

    real = urllib3.connection.HTTPSConnection._connect_tls_proxy

    def builds_its_own(self: Any, hostname: str, sock: Any) -> Any:
        self.proxy_config = self.proxy_config._replace(ssl_context=None)
        return real(self, hostname, sock)

    monkeypatch.setattr(urllib3.connection.HTTPSConnection, "_connect_tls_proxy", builds_its_own)
    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    client = _kv_client(vault.url)
    with pytest.raises(EgressReplyError, match="did not run on the engine's narrowed"):
        client.adapter.get(_PATH)
    # The refusal above is raised only on a leg urllib3 finished handshaking, so the proxy was
    # reached. The client closes straight after, so the listener's side of that handshake may not
    # complete; wait for it to finish with the connection before reading what it saw.
    deadline = time.monotonic() + 5
    while proxy.handled == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert proxy.handled == 1, "control: the simulated urllib3 never reached the proxy"
    assert proxy.connects == [], "CONNECT crossed the proxy leg before the refusal"


def test_an_https_proxy_with_the_wrong_host_name_is_refused(
    pki: _Pki, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    import requests

    monkeypatch.setenv(_CA_ENV, str(pki.ca))
    with _TlsProxy(pki.wrong_name_leaf, pki.wrong_name_key) as bad_proxy:
        monkeypatch.setenv("HTTPS_PROXY", bad_proxy.url)
        client = _kv_client(vault.url)
        with pytest.raises(requests.exceptions.RequestException, match="127.0.0.1|match"):
            client.adapter.get(_PATH)
        assert _proxy_failed_once(bad_proxy) and bad_proxy.negotiated == []
    assert vault.negotiated == [], "a request crossed an unverified proxy to Vault"


def test_an_https_proxy_the_anchor_did_not_issue_is_refused(
    pki: _Pki, vault: _TlsVault, proxy: _TlsProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The proxy leg verifies against the same anchor as the Vault leg, as urllib3 always did."""
    import requests

    monkeypatch.setenv(_CA_ENV, str(pki.other_ca))
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    client = _kv_client(vault.url)
    with pytest.raises(requests.exceptions.RequestException, match="CERTIFICATE_VERIFY_FAILED"):
        client.adapter.get(_PATH)
    assert _proxy_failed_once(proxy) and proxy.negotiated == []
    assert vault.negotiated == []


@pytest.mark.parametrize("build", [_kv_client, _transit_client], ids=["kv", "transit"])
def test_an_http_vault_through_an_https_proxy_is_refused_at_construction(
    build: Any, proxy: _TlsProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """requests clears the CA and sets CERT_NONE for an ``http://`` URL, so the only TLS leg, the one
    to the proxy carrying the token, would authenticate nobody. RED before the change: the client
    was built."""
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    with pytest.raises(ValueError, match=r"https:// proxy"):
        build("http://127.0.0.1:9")
    assert proxy.negotiated == [] and proxy.failures == 0


def test_a_proxy_that_appears_after_construction_is_refused_before_sending(
    proxy: _TlsProxy, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The start check reads the proxy settings once. The Windows Internet Settings proxy, or an
    environment changed later, can still move the hop, so the adapter checks again before sending.
    RED before the change: the request reached the proxy on an unverified handshake."""
    from messagefoundry.transports.bounded_read import EgressReplyError

    client = _kv_client("http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    with pytest.raises(EgressReplyError, match=r"https:// proxy"):
        client.adapter.get(_PATH)
    assert proxy.negotiated == [] and proxy.failures == 0, "a socket reached the proxy"
