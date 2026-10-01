# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Vault and OpenBao reply read goes through ``bounded_read`` (BACKLOG #2053, ASVS 4.2.1).

The engine's Vault clients read every reply through ``hvac``, ``requests`` and ``urllib3``. Before
this change none of that stack went through ``transports/bounded_read.py``, so a misframed or
oversized Vault reply was read with no byte bound and with ``urllib3``'s own chunk decoder.

These tests drive a REAL ``hvac.Client``, built by the shipped ``_build_client``, against a local
socket server that sends scripted raw replies. So each refusal below is measured through the whole
stack the engine uses, not against a fake of it. The positive controls show that a plain
``requests`` session reads the same bytes without complaint, so each refusal is the adapter's doing.

Synthetic data only: the token and the secret value are made up.
"""

from __future__ import annotations

import socket
import ssl
import threading
from typing import Any

import pytest

from messagefoundry.transports.bounded_read import (
    AmbiguousFramingError,
    EgressReplyError,
    MalformedReplyHeadError,
    ResponseTooLargeError,
    StrictHTTPResponse,
    TruncatedResponseError,
)
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
_BODY = b'{"data": {"data": {"value": "synthetic"}}}'
_KV_PATH = "v1/secret/data/mefor/ad"


def _ok(body: bytes = _BODY, extra: bytes = b"") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + extra
        + b"Content-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )


class _ScriptedVault:
    """A socket server that answers each request with the next scripted raw reply.

    Each script entry is ``(reply_bytes, close_after)``. It records every request head and counts
    accepted connections, which is how connection reuse is measured.
    """

    def __init__(self, script: list[tuple[bytes, bool]]) -> None:
        self._script = list(script)
        self.requests: list[bytes] = []
        self.connections = 0
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        # So a test that stalls fails in seconds rather than hanging the serving thread.
        self._listener.settimeout(5)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while self._script:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            self.connections += 1
            conn.settimeout(5)
            with conn:
                while self._script:
                    head = b""
                    while b"\r\n\r\n" not in head:
                        data = conn.recv(4096)
                        if not data:
                            break
                        head += data
                    if not head:
                        break
                    head, _, body = head.partition(b"\r\n\r\n")
                    length = 0
                    for line in head.split(b"\r\n")[1:]:
                        name, _, value = line.partition(b":")
                        if name.strip().lower() == b"content-length":
                            length = int(value)
                    while len(body) < length:
                        data = conn.recv(4096)
                        if not data:
                            break
                        body += data
                    self.requests.append(head + b"\r\n\r\n")
                    reply, close_after = self._script.pop(0)
                    conn.sendall(reply)
                    if close_after:
                        break

    def __enter__(self) -> _ScriptedVault:
        return self

    def __exit__(self, *exc: object) -> None:
        self._listener.close()
        self._thread.join(timeout=5)


def _client(port: int) -> Any:
    from messagefoundry.config import secretprovider_vault

    return secretprovider_vault._build_client(f"http://127.0.0.1:{port}", _TOKEN)


def _get(client: Any) -> Any:
    return client.adapter.get(_KV_PATH)


# --- both construction points mount the strict reader --------------------------------------------


@pytest.mark.parametrize(
    ("module", "transit"),
    [
        ("messagefoundry.config.secretprovider_vault", False),
        ("messagefoundry.store.keyprovider_vault", True),
    ],
)
def test_both_vault_client_builders_mount_the_strict_reader(module: str, transit: bool) -> None:
    """Mutation: drop the mount call from either ``_build_client``, or the Transit client's larger
    ceiling. Red: that parameter."""
    import importlib

    from messagefoundry.transports.bounded_read import DEFAULT_MAX_RESPONSE_BYTES
    from messagefoundry.transports.strict_requests import MAX_VAULT_REPLY_BYTES, StrictReplyAdapter

    mod = importlib.import_module(module)
    client = mod._build_client("https://vault.example.test:8200", _TOKEN)
    session = client.adapter.session
    for url in ("https://vault.example.test:8200/v1/x", "http://vault.example.test:8200/v1/x"):
        adapter = session.get_adapter(url)
        assert isinstance(adapter, StrictReplyAdapter)
        assert adapter._limit == (MAX_VAULT_REPLY_BYTES if transit else DEFAULT_MAX_RESPONSE_BYTES)


def test_a_client_with_no_requests_session_fails_closed() -> None:
    from messagefoundry.transports.strict_requests import mount_strict_reply_adapter

    with pytest.raises(ValueError, match="no requests session"):
        mount_strict_reply_adapter(
            object(), connector="Vault test hop", ssl_context_factory=ssl.create_default_context
        )


# --- a clean reply, and connection reuse ---------------------------------------------------------


def _chunked(size: bytes, data: bytes, head: bytes = b"Transfer-Encoding: chunked\r\n") -> bytes:
    """A one-chunk reply whose chunk-size line is ``size``, as sent."""
    return b"HTTP/1.1 200 OK\r\n" + head + b"\r\n" + size + b"\r\n" + data + b"\r\n0\r\n\r\n"


_CLEAN_CHUNKED = _chunked(f"{len(_BODY):x}".encode(), _BODY)


@pytest.mark.parametrize(
    "first", [pytest.param(_ok(), id="content-length"), pytest.param(_CLEAN_CHUNKED, id="chunked")]
)
def test_a_clean_reply_is_read_and_the_connection_is_reused(first: bytes) -> None:
    """Two clean replies on one connection: the strict read leaves the stream at the next reply."""
    with _ScriptedVault([(first, False), (_ok(), False)]) as server:
        client = _client(server.port)
        assert _get(client) == {"data": {"data": {"value": "synthetic"}}}
        assert _get(client) == {"data": {"data": {"value": "synthetic"}}}
    assert server.connections == 1, (
        "a strictly complete read must return the connection to the pool"
    )
    assert all(b"accept-encoding: identity\r\n" in r.lower() for r in server.requests)


# --- the reported framing shapes are refused -----------------------------------------------------

_TE_WITH_SPACE = _chunked(
    f"{len(_BODY):x}".encode(), _BODY, head=b"Content-Length: 5\r\nTransfer-Encoding : chunked\r\n"
)
_LINE_WITH_NO_COLON = _ok(extra=b"X-Synthetic-No-Colon\r\n")


def _chunk_size(size: bytes) -> bytes:
    return _chunked(size, _BODY[:5])


@pytest.mark.parametrize(
    "reply",
    [
        pytest.param(_TE_WITH_SPACE, id="content-length-plus-TE-with-space-before-colon"),
        pytest.param(_LINE_WITH_NO_COLON, id="header-line-with-no-colon"),
        pytest.param(_chunk_size(b"-5"), id="negative-chunk-size"),
        pytest.param(_chunk_size(b"0x5"), id="0x-chunk-size"),
        pytest.param(_chunk_size(b"+5"), id="plus-chunk-size"),
        pytest.param(_chunk_size(b"1_0"), id="underscore-chunk-size"),
    ],
)
def test_a_misframed_vault_reply_is_refused(reply: bytes) -> None:
    """Each reported shape, through the real client. A refusal closes the connection, so the
    next request opens a second one. The server keeps its side open, so a pooled connection
    would be reused and the count would stay at one."""
    with _ScriptedVault([(reply, False), (_ok(), False)]) as server:
        client = _client(server.port)
        with pytest.raises(AmbiguousFramingError):
            _get(client)
        assert _get(client)["data"]["data"]["value"] == "synthetic"
    assert server.connections == 2, "a refused reply's connection must not go back to the pool"


@pytest.mark.parametrize(
    ("reply", "misread"),
    [
        pytest.param(
            _TE_WITH_SPACE,
            _TE_WITH_SPACE.split(b"\r\n\r\n", 1)[1][:5],
            id="content-length-plus-TE-with-space-before-colon",
        ),
        pytest.param(_chunk_size(b"0x5"), _BODY[:5], id="0x-chunk-size"),
    ],
)
def test_control_a_plain_requests_session_reads_the_same_bytes_leniently(
    reply: bytes, misread: bytes
) -> None:
    """Positive control: without the adapter the same reply comes back as an ordinary answer, so
    the refusals above are the strict reader's and not the server's or the test's. The first arm
    returns five bytes of raw chunk framing as the body."""
    import requests

    with _ScriptedVault([(reply, True)]) as server, requests.Session() as session:
        response = session.get(f"http://127.0.0.1:{server.port}/{_KV_PATH}", timeout=10)
        assert response.status_code == 200
        assert response.content == misread


# --- the byte bound, truncation and content coding -----------------------------------------------


def _session_with(limit: int) -> Any:
    import requests

    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    session = requests.Session()
    # A plain-http hop never calls the factory; it is required, so one is passed.
    adapter = StrictReplyAdapter(
        connector="Vault test hop", limit=limit, ssl_context_factory=ssl.create_default_context
    )
    session.mount("http://", adapter)
    return session


def test_a_reply_past_the_bound_is_refused_and_its_connection_closed() -> None:
    with _ScriptedVault([(_ok(), False), (_ok(b"{}"), False)]) as server:
        session = _session_with(limit=10)
        url = f"http://127.0.0.1:{server.port}/{_KV_PATH}"
        with pytest.raises(ResponseTooLargeError):
            session.get(url, timeout=10)
        assert session.get(url, timeout=10).content == b"{}"
    assert server.connections == 2


def test_a_truncated_reply_is_refused() -> None:
    short = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" + _BODY
    with _ScriptedVault([(short, True)]) as server, pytest.raises(TruncatedResponseError):
        _get(_client(server.port))


def test_a_content_coding_the_engine_did_not_ask_for_is_refused() -> None:
    gzipped = _ok(extra=b"Content-Encoding: gzip\r\n")
    with _ScriptedVault([(gzipped, False), (_ok(), False)]) as server:
        client = _client(server.port)
        with pytest.raises(EgressReplyError, match="content coding"):
            _get(client)
        assert _get(client)["data"]["data"]["value"] == "synthetic"
    assert server.connections == 2


def test_a_stall_mid_body_is_raised_as_a_requests_read_timeout() -> None:
    """requests reads the body outside its own error translation, so the adapter translates.
    Mutation: drop the TimeoutError arm in build_response. Red: the stall is raised as a
    ConnectionError instead. Drop both arms and a bare TimeoutError escapes."""
    import requests

    stalled = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"
    # The second entry keeps the server's side open: with the script spent it would close, and a
    # close is a truncation, not a stall.
    with _ScriptedVault([(stalled, False), (_ok(), False)]) as server:
        session = _session_with(limit=1000)
        with pytest.raises(requests.exceptions.ReadTimeout):
            session.get(f"http://127.0.0.1:{server.port}/{_KV_PATH}", timeout=1)


def test_the_vault_reply_bound_is_at_least_the_shared_egress_bound() -> None:
    """A Transit reply carries one cell as base64, 4/3 of the cell, so the Vault bound must not be
    the shared 16 MiB one or an honest reply for a large message would be refused."""
    from messagefoundry.transports.bounded_read import DEFAULT_MAX_RESPONSE_BYTES
    from messagefoundry.transports.strict_requests import MAX_VAULT_REPLY_BYTES

    assert MAX_VAULT_REPLY_BYTES >= DEFAULT_MAX_RESPONSE_BYTES * 4 // 3 + 1024


def test_the_transit_cipher_reads_through_the_strict_reader_and_reuses_its_connection() -> None:
    """The per-cell path: two Transit encrypts (POST with a JSON body) on one connection, then a
    misframed reply refused as the store's own CipherError."""
    from messagefoundry.store import keyprovider_vault
    from messagefoundry.store.crypto import CipherError
    from messagefoundry.store.crypto_transit import TransitCipher

    sealed = b'{"data": {"ciphertext": "vault:v1:c3ludGhldGlj"}}'
    with _ScriptedVault(
        [(_ok(sealed), False), (_ok(sealed), False), (_chunk_size(b"-5"), True)]
    ) as server:
        client = keyprovider_vault._build_client(f"http://127.0.0.1:{server.port}", _TOKEN)
        cipher = TransitCipher(client, "mefor-store-dek")
        assert cipher.encrypt("synthetic", aad=b"cell").endswith("vault:v1:c3ludGhldGlj")
        assert cipher.encrypt("synthetic", aad=b"cell").endswith("vault:v1:c3ludGhldGlj")
        assert server.connections == 1
        with pytest.raises(CipherError, match="AmbiguousFramingError"):
            cipher.encrypt("synthetic", aad=b"cell")
    assert all(r.startswith(b"POST /v1/transit/encrypt/mefor-store-dek ") for r in server.requests)


# --- a bare CR in the reply HEAD is refused (BACKLOG #2123) --------------------------------------
#
# The two shapes put a CR with no LF after it in the status line and in a header line. Neither
# trips a body-framing check, so only the head read can refuse them: the controls below read both
# as an ordinary answer, with a plain session and with the adapter's head check undone.

_CR_IN_STATUS_LINE = _ok().replace(b"200 OK\r\n", b"200 OK\rX-Synthetic: 1\r\n", 1)
_CR_IN_HEADER_LINE = _ok(extra=b"X-Synthetic: a\rX-Other: b\r\n")
_BARE_CR_SHAPES = [
    pytest.param(_CR_IN_STATUS_LINE, id="status-line"),
    pytest.param(_CR_IN_HEADER_LINE, id="header-line"),
]


@pytest.mark.parametrize("reply", _BARE_CR_SHAPES)
def test_a_bare_cr_in_a_kv_reply_head_is_refused_and_its_connection_closed(reply: bytes) -> None:
    """Through the real KV client. The server keeps its side open, so a pooled connection would be
    reused for the second request and the count would stay at one."""
    with _ScriptedVault([(reply, False), (_ok(), False)]) as server:
        client = _client(server.port)
        with pytest.raises(MalformedReplyHeadError, match="Vault KV secret provider") as caught:
            _get(client)
        assert isinstance(caught.value, AmbiguousFramingError)
        assert _get(client)["data"]["data"]["value"] == "synthetic"
    assert server.connections == 2, "a refused reply's connection must not go back to the pool"


@pytest.mark.parametrize("reply", _BARE_CR_SHAPES)
def test_a_bare_cr_in_a_transit_reply_head_is_refused_and_its_connection_closed(
    reply: bytes,
) -> None:
    """The per-cell Transit path: a clean encrypt, a refused one, then a clean one again. The
    refusal reaches the store as its own CipherError, naming the head refusal."""
    from messagefoundry.store import keyprovider_vault
    from messagefoundry.store.crypto import CipherError
    from messagefoundry.store.crypto_transit import TransitCipher

    sealed = _ok(b'{"data": {"ciphertext": "vault:v1:c3ludGhldGlj"}}')
    with _ScriptedVault([(sealed, False), (reply, False), (sealed, False)]) as server:
        client = keyprovider_vault._build_client(f"http://127.0.0.1:{server.port}", _TOKEN)
        cipher = TransitCipher(client, "mefor-store-dek")
        assert cipher.encrypt("synthetic", aad=b"cell").endswith("vault:v1:c3ludGhldGlj")
        with pytest.raises(CipherError, match="MalformedReplyHeadError"):
            cipher.encrypt("synthetic", aad=b"cell")
        assert cipher.encrypt("synthetic", aad=b"cell").endswith("vault:v1:c3ludGhldGlj")
    assert server.connections == 2, "the refused reply's connection must not go back to the pool"


def test_the_kv_secret_provider_fails_closed_on_a_bare_cr_in_the_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.config.secretprovider_vault import VaultSecretProvider
    from messagefoundry.config.settings import SecretsSettings

    with _ScriptedVault([(_CR_IN_HEADER_LINE, True)]) as server:
        monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", f"http://127.0.0.1:{server.port}")
        monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
        monkeypatch.delenv("MEFOR_SECRETS_VAULT_CA_FILE", raising=False)
        with pytest.raises(SecretProviderError, match="MalformedReplyHeadError"):
            VaultSecretProvider(SecretsSettings()).resolve("mefor/ad")


@pytest.mark.parametrize("reply", _BARE_CR_SHAPES)
def test_control_the_stock_response_class_reads_a_bare_cr_head_as_an_answer(
    reply: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation control: with the strict head read undone, the same client, adapter and body
    reader take each shape as an ordinary answer. So the refusals above are the head read's, and
    the body reader alone would miss them. Also run against a plain session, with no adapter."""
    import http.client

    import requests

    with _ScriptedVault([(reply, True)]) as server, requests.Session() as session:
        response = session.get(f"http://127.0.0.1:{server.port}/{_KV_PATH}", timeout=10)
        assert response.status_code == 200
        assert response.content == _BODY

    monkeypatch.setattr(StrictHTTPResponse, "begin", http.client.HTTPResponse.begin)
    with _ScriptedVault([(reply, True)]) as server:
        assert _get(_client(server.port))["data"]["data"]["value"] == "synthetic"


def test_a_bare_cr_head_is_refused_through_an_http_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """``requests`` builds a separate pool manager for a proxy, so the head check must reach it
    too. The scripted server stands in for the proxy: an ``http`` target through an ``http`` proxy
    is sent to the proxy, which answers it.

    Since BACKLOG #2317 the adapter refuses that request before sending, because the token would
    cross to the proxy in cleartext; tests/test_vault_cleartext_hop.py measures that refusal. So
    this test turns it off, to keep measuring the head check on the proxy's pools as a second
    layer under it. Shipped code no longer reaches this path; the layer is defence in depth."""
    from messagefoundry.transports import strict_requests

    monkeypatch.setattr(strict_requests, "_refuse_a_cleartext_vault_hop", lambda *a, **k: None)
    with _ScriptedVault([(_CR_IN_HEADER_LINE, False), (_ok(), False)]) as server:
        session = _session_with(limit=1000)
        proxies = {"http": f"http://127.0.0.1:{server.port}"}
        url = f"http://vault.example.test:8200/{_KV_PATH}"
        with pytest.raises(MalformedReplyHeadError):
            session.get(url, timeout=10, proxies=proxies)
        assert session.get(url, timeout=10, proxies=proxies).content == _BODY
    assert server.requests[0].startswith(b"GET http://vault.example.test:8200/")
    assert server.connections == 2


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_every_pool_the_adapter_builds_reads_the_head_strictly(scheme: str) -> None:
    """Both schemes, direct and through a proxy. The https pool's connection must still be
    urllib3's own class underneath. Since BACKLOG #300 the https connection is also the narrowed
    subclass, which must keep the strict head reader
    (``test_tls_cipher_assertion_sites`` measures its TLS context through this adapter)."""
    import urllib3.connection

    from messagefoundry.transports import strict_requests
    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    adapter = StrictReplyAdapter(
        connector="Vault test hop", ssl_context_factory=ssl.create_default_context
    )
    stock = {"http": urllib3.connection.HTTPConnection, "https": urllib3.connection.HTTPSConnection}
    managers = [adapter.poolmanager, adapter.proxy_manager_for("http://proxy.example.test:3128")]
    for manager in managers:
        pool = manager.connection_from_host("vault.example.test", 8200, scheme=scheme)
        assert issubclass(pool.ConnectionCls, stock[scheme])
        assert pool.ConnectionCls.response_class is StrictHTTPResponse
        if scheme == "https":
            assert getattr(type(pool), strict_requests._NARROWED_POOL_MARK, False)


def test_a_pool_that_would_read_the_head_leniently_is_refused_before_sending() -> None:
    """Mutation: hand the adapter's pool manager urllib3's stock pools. Nothing may be sent."""
    import urllib3.poolmanager

    with _ScriptedVault([(_ok(), True)]) as server:
        session = _session_with(limit=1000)
        adapter = session.get_adapter("http://")
        adapter.poolmanager.pool_classes_by_scheme = urllib3.poolmanager.pool_classes_by_scheme
        with pytest.raises(EgressReplyError, match="cannot make strict"):
            session.get(f"http://127.0.0.1:{server.port}/{_KV_PATH}", timeout=10)
    assert server.requests == []


def test_an_unrelated_connection_error_is_not_relabelled() -> None:
    """Only a head refusal is unwrapped. A refused connect stays the requests error it was."""
    import requests

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    with pytest.raises(requests.exceptions.ConnectionError):
        _session_with(limit=1000).get(f"http://127.0.0.1:{port}/{_KV_PATH}", timeout=5)

    # Sent while an earlier refusal is being handled, the failure carries that refusal as its
    # context. Mutation: walk __context__ in _head_refusal_in. Red: relabelled as a head refusal.
    try:
        raise MalformedReplyHeadError("an earlier refusal", reason="synthetic")
    except MalformedReplyHeadError:
        with pytest.raises(requests.exceptions.ConnectionError):
            _session_with(limit=1000).get(f"http://127.0.0.1:{port}/{_KV_PATH}", timeout=5)


def test_a_socks_proxy_pool_is_left_alone_and_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A SOCKS manager's pools open SOCKS connections, so swapping them would send around the
    proxy. The engine does not install PySocks, so a stand-in manager plays the part. Mutation: drop
    the ``type(manager) is ProxyManager`` filter. Red: the pools are swapped."""
    import requests.adapters
    import urllib3.poolmanager

    class _StandInSocksManager(urllib3.poolmanager.PoolManager):
        def __init__(self, proxy_url: str, **kwargs: Any) -> None:
            kwargs.pop("username", None)
            kwargs.pop("password", None)
            super().__init__(**kwargs)

    monkeypatch.setattr(requests.adapters, "SOCKSProxyManager", _StandInSocksManager)
    with _ScriptedVault([(_ok(), True)]) as server:
        session = _session_with(limit=1000)
        proxy = f"socks5://127.0.0.1:{server.port}"
        manager = session.get_adapter("http://").proxy_manager_for(proxy)
        assert manager.pool_classes_by_scheme is urllib3.poolmanager.pool_classes_by_scheme
        with pytest.raises(EgressReplyError, match="cannot make strict"):
            session.get(f"http://vault.example.test:8200/{_KV_PATH}", proxies={"http": proxy})
    assert server.requests == []


# --- the providers turn a refusal into their own fail-closed error -------------------------------


def test_the_kv_secret_provider_fails_closed_on_a_misframed_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.config.secretprovider import SecretProviderError
    from messagefoundry.config.secretprovider_vault import VaultSecretProvider
    from messagefoundry.config.settings import SecretsSettings

    with _ScriptedVault([(_LINE_WITH_NO_COLON, True)]) as server:
        monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", f"http://127.0.0.1:{server.port}")
        monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
        monkeypatch.delenv("MEFOR_SECRETS_VAULT_CA_FILE", raising=False)
        with pytest.raises(SecretProviderError, match="AmbiguousFramingError"):
            VaultSecretProvider(SecretsSettings()).resolve("mefor/ad")
