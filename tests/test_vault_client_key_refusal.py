# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Vault hop refuses an encrypted client key before the TLS library reads it (BACKLOG #3458).

hvac reads ``VAULT_CLIENT_CERT`` and ``VAULT_CLIENT_KEY`` once, at import, into ``hvac.v1``, and
hands them to requests as ``cert=(cert, key)``. With no ``VAULT_CLIENT_KEY``, urllib3 calls
``load_cert_chain(certfile, None)``, and OpenSSL reads the key out of the certificate file.
urllib3 checks for an encrypted key only when a key file is set. So an encrypted key in a combined
PEM reached OpenSSL, which asked for a passphrase and waited. The connection now checks the key
with ``keywrap.refuse_weak_cert_chain_key`` first, and refuses with fixed text.

**This process never lets OpenSSL load an encrypted fixture**, because a load that waits would
hang the test run. urllib3's ``ssl_wrap_socket`` is replaced by a spy that fails the test on one,
so the unfixed code fails here, on the spy, rather than at a prompt. The control passes a plain
combined PEM through to the real function, which proves the patched ``hvac.v1`` value reaches the
load at all.

The values are patched on ``hvac.v1``, not set in the environment: hvac has already read the
environment by the time a test runs, so a ``setenv`` would change nothing.

Synthetic data only: the token, certificates, keys and passphrase are made up, generated per test.
"""

from __future__ import annotations

import contextlib
import ipaddress
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from tests.test_vault_tls_narrowing import (
    _CA_ENV,
    _PATH,
    _REPLY,
    _ca,
    _hop_environment,  # noqa: F401  # autouse: clears the proxy and hvac.v1 values for each test
    _kv_client,
    _leaf,
    _TlsVault,
    _transit_client,
    _write_cert,
    _write_key,
)

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_PASSPHRASE = b"synthetic-passphrase"  # nosec B105 - a made-up test value, not a credential


class _Files:
    """The server's CA and chain, and the client certificate shapes the tests hand hvac."""

    def __init__(self, root: Path) -> None:
        ca, ca_key = _ca("synthetic vault ca")
        server, server_key = _leaf(ca, ca_key, x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        client, client_key = _leaf(ca, ca_key, x509.DNSName("client.synthetic.test"))
        self.ca = _write_cert(root / "ca.pem", ca)
        self.server = _write_cert(root / "server.pem", server)
        self.server_key = _write_key(root / "server-key.pem", server_key)
        cert = client.public_bytes(serialization.Encoding.PEM)
        wrap = serialization.BestAvailableEncryption(_PASSPHRASE)
        plain = client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pkcs8 = client_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, wrap
        )
        legacy = client_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, wrap
        )
        self.combined_plain = self._write(root / "client-plain.pem", cert + plain)
        self.combined_pkcs8 = self._write(root / "client-pkcs8.pem", cert + pkcs8)
        self.combined_legacy = self._write(root / "client-legacy.pem", cert + legacy)
        self.cert_only = self._write(root / "client-cert.pem", cert)
        self.key_pkcs8 = self._write(root / "client-key-pkcs8.pem", pkcs8)
        #: Every file holding an encrypted key, as urllib3 is handed it. The spy fails on any.
        self.encrypted = {
            str(p) for p in (self.combined_pkcs8, self.combined_legacy, self.key_pkcs8)
        }

    @staticmethod
    def _write(path: Path, data: bytes) -> Path:
        path.write_bytes(data)
        return path


@pytest.fixture
def files(tmp_path: Path) -> _Files:
    return _Files(tmp_path)


@pytest.fixture
def vault(files: _Files) -> Iterator[_TlsVault]:
    with _TlsVault(files.server, files.server_key) as server:
        yield server


@pytest.fixture(autouse=True)
def _ca_env(request: pytest.FixtureRequest, files: _Files, monkeypatch: pytest.MonkeyPatch) -> None:
    """The server's CA, set after ``test_vault_tls_narrowing``'s fixture has cleared the hop."""
    request.getfixturevalue("_hop_environment")
    monkeypatch.setenv(_CA_ENV, str(files.ca))
    monkeypatch.setenv("MEFOR_STORE_VAULT_CA_FILE", str(files.ca))


def _client_cert(monkeypatch: pytest.MonkeyPatch, cert: Path, key: Path | None) -> None:
    """What hvac would have read from ``VAULT_CLIENT_CERT`` and ``VAULT_CLIENT_KEY`` at import."""
    import hvac.v1  # type: ignore[import-untyped]  # the [vault] extra ships no stubs

    monkeypatch.setattr(hvac.v1, "VAULT_CLIENT_CERT", str(cert))
    monkeypatch.setattr(hvac.v1, "VAULT_CLIENT_KEY", None if key is None else str(key))


@contextlib.contextmanager
def _tls_loads(refused: set[str]) -> Iterator[list[tuple[Any, Any]]]:
    """Record the client certificate and key urllib3 hands the TLS library on each new socket.

    A file in ``refused`` fails the test instead of reaching OpenSSL, so nothing here loads one.
    """
    import urllib3.connection
    from urllib3.util.ssl_ import ssl_wrap_socket as real

    seen: list[tuple[Any, Any]] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        assert "certfile" in kwargs, "urllib3 no longer passes certfile by keyword"
        pair = (kwargs.get("certfile"), kwargs.get("keyfile"))
        seen.append(pair)
        if refused.intersection(str(name) for name in pair if name):
            raise AssertionError(
                f"an encrypted client key reached the TLS library unchecked: {pair}"
            )
        return real(*args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib3.connection, "ssl_wrap_socket", spy)
        yield seen


@pytest.mark.parametrize("build", [_kv_client, _transit_client], ids=["kv", "transit"])
@pytest.mark.parametrize(
    ("cert", "key"),
    [
        ("combined_pkcs8", None),
        ("combined_legacy", None),
        ("cert_only", "key_pkcs8"),
    ],
    ids=["combined-pkcs8", "combined-legacy-pem", "separate-key"],
)
def test_an_encrypted_client_key_is_refused_before_the_tls_library_reads_it(
    build: Any,
    cert: str,
    key: str | None,
    files: _Files,
    vault: _TlsVault,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The red test. Unfixed, the combined shapes reach the spy with no key file set."""
    from messagefoundry.transports.strict_requests import VaultHopRefused, vault_failure_text

    cert_path = getattr(files, cert)
    key_path = None if key is None else getattr(files, key)
    _client_cert(monkeypatch, cert_path, key_path)
    client = build(vault.url)
    with _tls_loads(files.encrypted) as seen, pytest.raises(VaultHopRefused) as caught:
        client.adapter.get(_PATH)
    assert seen == [], f"the TLS library was handed a client certificate: {seen}"
    assert vault.negotiated == [], "the refusal came after a handshake"
    text = str(caught.value)
    assert "BACKLOG #3458" in text
    # Fixed text: no path or file name, so a provider's handler may print it.
    for path in (cert_path, key_path):
        if path is not None:
            assert str(path.parent) not in text
            assert path.name not in text
    assert vault_failure_text(caught.value) == text


@pytest.mark.parametrize("build", [_kv_client, _transit_client], ids=["kv", "transit"])
def test_an_unencrypted_combined_client_pem_still_connects(
    build: Any, files: _Files, vault: _TlsVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control. The same route with a plain key loads it and reaches Vault, and the spy shows
    the patched ``hvac.v1`` value was the file handed to the TLS library, with no key file."""
    _client_cert(monkeypatch, files.combined_plain, None)
    client = build(vault.url)
    with _tls_loads(files.encrypted) as seen:
        assert client.adapter.get(_PATH) == _REPLY
    assert seen == [(str(files.combined_plain), None)]
    assert vault.negotiated, "the listener saw no completed handshake"
