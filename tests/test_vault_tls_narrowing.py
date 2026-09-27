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
import socket
import ssl
import threading
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
    "ALL_PROXY",
    "all_proxy",
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


def test_a_hop_through_a_proxy_is_narrowed_too(vault: _TlsVault) -> None:
    """With HTTPS_PROXY set, requests takes the pools from a proxy manager, not the adapter's own.
    Mutation: delete ``StrictReplyAdapter.proxy_manager_for``; red. Structural rather than on the
    wire, because driving a real proxy is out of scope here: it checks that the proxy manager's
    https connections take their context from the same factory."""
    client = _kv_client(vault.url)
    adapter = client.adapter.session.get_adapter(vault.url)
    manager = adapter.proxy_manager_for("http://127.0.0.1:9")
    conn_cls = manager.pool_classes_by_scheme["https"].ConnectionCls
    made: list[ssl.SSLContext] = []

    def factory() -> ssl.SSLContext:
        made.append(ssl.create_default_context())
        return made[-1]

    adapter._ssl_context_factory = factory
    manager = adapter.proxy_manager_for("http://127.0.0.2:9")
    conn = manager.pool_classes_by_scheme["https"].ConnectionCls("127.0.0.1", vault.port)
    with contextlib.suppress(Exception):  # only the context the connect took matters
        conn.connect()
    conn.close()
    assert made and conn.ssl_context is made[0], "the proxied connection skipped the factory"
    assert conn_cls.__name__ == "NarrowedHTTPSConnection"


def test_a_connection_that_will_not_verify_keeps_urllib3s_own_context(vault: _TlsVault) -> None:
    """requests sets CERT_NONE for an ``http://`` Vault reached through an ``https://`` proxy; that
    TLS hop is to the proxy. The factory's context checks host names, so handing it to urllib3
    there raised ValueError on every call. Such a connection is left to urllib3, as before. Driven
    against the local listener with CERT_NONE, which is exactly that connection's shape."""
    client = _kv_client(vault.url)
    adapter = client.adapter.session.get_adapter(vault.url)
    made: list[ssl.SSLContext] = []

    def factory() -> ssl.SSLContext:
        made.append(ssl.create_default_context())
        return made[-1]

    adapter._ssl_context_factory = factory
    manager = adapter.proxy_manager_for("https://127.0.0.3:9")
    conn = manager.pool_classes_by_scheme["https"].ConnectionCls(
        "127.0.0.1", vault.port, cert_reqs="CERT_NONE"
    )
    conn.connect()  # raised ValueError before the fix
    conn.close()
    assert made == [], "the factory ran for a connection that does not verify"


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
