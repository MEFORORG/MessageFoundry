# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Vault address that would carry the token in cleartext is refused (BACKLOG #2317, ASVS 12.3.1).

The engine's three Vault clients (the KV secret provider, the store key provider and the Transit
cipher) send ``X-Vault-Token`` on every call. Before this change each one took an ``http://``
address with no scheme check, so on a first deployment with such an address the token would have
crossed the network in cleartext, directly or through an ``http://`` proxy. Engine PR 1752 (BACKLOG
#300) had refused only an ``http://`` Vault behind an ``https://`` proxy.

The rule follows the shared cleartext-hop authority, ``tls_policy.insecure_hop_disposition``: an
on-box hop is allowed, and nothing else is, because this hop has no declaration to accept the risk
and no posture in scope. On the box means an ``http://`` address whose host is proven loopback with
no DNS, reached with no proxy.

Each refusal is driven through the shipped entry point (``resolve``, ``active_key``,
``build_transit_cipher``) with a real ``hvac`` client, and a control shows the same entry point
going past the check with an ``https://`` address. The proxy cases count connections at a real
local listener, so "nothing was sent" is measured, not assumed.

Synthetic data only: the token, key names and host names are made up.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from messagefoundry.config.secretprovider import SecretProviderError
from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.store.keyprovider import KeyProviderError
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
_REMOTE_HTTP = "http://vault.synthetic.test:8200"

#: Every variable that can move the hop, cleared so only what a test sets applies.
_HOP_ENV = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "VAULT_ADDR",
    "MEFOR_SECRETS_VAULT_ADDR",
    "MEFOR_SECRETS_VAULT_CA_FILE",
    "MEFOR_STORE_VAULT_ADDR",
    "MEFOR_STORE_VAULT_CA_FILE",
)


@pytest.fixture(autouse=True)
def _hop_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _HOP_ENV:
        monkeypatch.delenv(name, raising=False)
    # With no *_proxy variable left, urllib falls back to the host's own system proxy (Windows
    # Internet Settings, or macOS's), which would move the hop under these tests.
    import urllib.request

    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    # hvac reads these once, at import, so unsetting the env vars would not undo them.
    import hvac.v1  # type: ignore[import-untyped]  # the [vault] extra ships no stubs

    for name in ("VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
        monkeypatch.setattr(hvac.v1, name, None, raising=False)
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "synthetic-data-key")


class _Listener:
    """A loopback socket that counts the connections it accepts and answers none of them."""

    def __init__(self) -> None:
        self.connections = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.05)  # how long close() can wait for the accept loop
        self.port = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._sock.close()


@pytest.fixture
def listener() -> Iterator[_Listener]:
    lst = _Listener()
    try:
        yield lst
    finally:
        lst.close()


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.close()
    return port


# --- the three shipped entry points ---------------------------------------------------------------


def _kv(monkeypatch: pytest.MonkeyPatch, addr: str | None) -> Any:
    from messagefoundry.config.secretprovider_vault import VaultSecretProvider
    from messagefoundry.config.settings import SecretsSettings

    if addr is not None:
        monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", addr)
    return VaultSecretProvider(SecretsSettings()).resolve("mefor/ad")


def _kek(monkeypatch: pytest.MonkeyPatch, addr: str | None) -> Any:
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.keyprovider_vault import VaultKeyProvider

    if addr is not None:
        monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", addr)
    return VaultKeyProvider(StoreSettings()).active_key()


def _transit(monkeypatch: pytest.MonkeyPatch, addr: str | None) -> Any:
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.crypto_transit import build_transit_cipher

    if addr is not None:
        monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", addr)
    return build_transit_cipher(StoreSettings())


#: Each entry point's own fail-closed type. Pinned per entry point, so a provider that raised the
#: other provider's type would go red.
_OWN_TYPE: dict[Any, type[Exception]] = {
    _kv: SecretProviderError,
    _kek: KeyProviderError,
    _transit: KeyProviderError,
}

_ENTRY_POINTS = pytest.mark.parametrize(
    "entry", [_kv, _kek, _transit], ids=["kv-secret", "store-key", "transit"]
)
EntryPoint = Callable[[pytest.MonkeyPatch, str | None], Any]

#: Each provider's own fail-closed type: the KV provider's, and the key provider's, which the
#: Transit cipher shares.
_FAIL_CLOSED = (SecretProviderError, KeyProviderError)


def _no_dial(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record every outbound dial urllib3 makes, so a refusal can be shown to send nothing."""
    import urllib3.util.connection

    dials: list[object] = []
    real = urllib3.util.connection.create_connection

    def record(address: object, *args: Any, **kwargs: Any) -> Any:
        dials.append(address)
        return real(address, *args, **kwargs)  # type: ignore[arg-type]

    # urllib3.connection calls it through this module, so one patch covers every pool.
    monkeypatch.setattr(urllib3.util.connection, "create_connection", record)
    return dials


def _assert_refused(caught: pytest.ExceptionInfo[Exception], entry: Any = _kv) -> None:
    """The provider raised its own fail-closed type, caused by the cleartext refusal, and kept the
    refusal's text whole."""
    assert type(caught.value) is _OWN_TYPE[entry]
    assert isinstance(caught.value.__cause__, InsecureHopRefused)
    assert str(caught.value) == str(caught.value.__cause__)


@_ENTRY_POINTS
def test_a_direct_http_address_is_refused_before_anything_is_sent(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED before the change: each entry point built its client and dialled the address. The
    refusal is the provider's own fail-closed type, so a caller that handles only that type, such
    as ``rotate-key``, still exits cleanly."""
    dials = _no_dial(monkeypatch)
    with pytest.raises(_FAIL_CLOSED, match="well-formed https://") as caught:
        entry(monkeypatch, _REMOTE_HTTP)
    _assert_refused(caught, entry)
    assert dials == []


@_ENTRY_POINTS
def test_hvacs_own_vault_addr_fallback_is_checked_too(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the MEFOR_* address unset, hvac reads ``VAULT_ADDR``. The check reads the address the
    client actually holds, so the fallback cannot route around it."""
    monkeypatch.setenv("VAULT_ADDR", _REMOTE_HTTP)
    with pytest.raises(_FAIL_CLOSED, match="well-formed https://") as caught:
        entry(monkeypatch, None)
    _assert_refused(caught, entry)


@_ENTRY_POINTS
@pytest.mark.parametrize(
    "address",
    [
        # urllib.parse reads the host as 127.0.0.1; urllib3, which dials, reads it as the name
        # before the backslash. The check must judge what is dialled.
        "http://vault.synthetic.test\\@127.0.0.1:8200",
        # A bracketed host that is no address: both parsers raise, and both quote the address.
        "http://[vault-secret-host.synthetic.test]:8200",
        # urllib3 accepts it and dials the name before the backslash; urllib rejects it, quoting
        # the bracketed part.
        "http://vault.synthetic.test\\@[vault-secret-host]:8200",
        # Same disagreement on an https address: the trust anchor would be resolved for one host
        # while urllib3 dials the other.
        "https://vault.synthetic.test\\@127.0.0.1:8200",
        # requests will not prepare it, and its error quotes the address.
        "https://[vault-secret-host]:8200",
    ],
    ids=[
        "backslash-userinfo",
        "bracketed-name",
        "backslash-then-bracket",
        "https-backslash",
        "https-bracketed-name",
    ],
)
def test_an_address_the_parsers_disagree_on_is_refused_at_construction(
    entry: EntryPoint, address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED before the round-1 repair: the first built cleanly and was refused only at send, and
    the second raised a plain ValueError quoting the host."""
    dials = _no_dial(monkeypatch)
    with pytest.raises(_FAIL_CLOSED, match="well-formed https://") as caught:
        entry(monkeypatch, address)
    _assert_refused(caught, entry)
    for fragment in ("synthetic.test", "secret-host", "127.0.0.1", "8200"):
        assert fragment not in str(caught.value)
    assert dials == []


@_ENTRY_POINTS
def test_control_an_https_address_passes_the_check(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The control arm. The same entry point goes past the check and dials the listener, which
    hangs up during the handshake, so it fails with its own fail-closed error, not the refusal."""
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, f"https://127.0.0.1:{listener.port}")
    assert not isinstance(caught.value.__cause__, InsecureHopRefused)
    assert "well-formed https://" not in str(caught.value)
    assert listener.connections >= 1


@_ENTRY_POINTS
def test_control_a_loopback_http_vault_with_no_proxy_passes_the_check(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The shared authority's on-box arm: a loopback hop reached directly is not a network
    exposure. The request reaches the listener, which hangs up, and the entry point fails closed on
    that with its own error."""
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, listener.url)
    assert not isinstance(caught.value.__cause__, InsecureHopRefused)
    assert listener.connections >= 1


def test_control_leading_whitespace_on_an_https_address_is_still_accepted() -> None:
    """requests strips it before sending, as it did before this check existed. An NSSM
    environment line can carry it."""
    from messagefoundry.config import secretprovider_vault

    secretprovider_vault._build_client("  https://vault.synthetic.test:8200", _TOKEN)


# --- the proxy cases ------------------------------------------------------------------------------


@_ENTRY_POINTS
@pytest.mark.parametrize("variable", ["HTTP_PROXY", "ALL_PROXY"])
def test_a_loopback_http_vault_behind_an_http_proxy_is_refused(
    entry: EntryPoint, variable: str, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """A loopback address sent through a proxy is not on the box: the proxy reads the request,
    token and all. RED before the change: the request reached the proxy."""
    monkeypatch.setenv(variable, listener.url)
    with pytest.raises(_FAIL_CLOSED, match="well-formed https://") as caught:
        entry(monkeypatch, f"http://127.0.0.1:{_closed_port()}")
    _assert_refused(caught, entry)
    assert listener.connections == 0, "a socket reached the proxy"


def test_a_remote_http_vault_behind_an_http_proxy_is_refused(
    monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    monkeypatch.setenv("HTTP_PROXY", listener.url)
    with pytest.raises(_FAIL_CLOSED, match="well-formed https://") as caught:
        _kv(monkeypatch, _REMOTE_HTTP)
    _assert_refused(caught)
    assert listener.connections == 0


@pytest.mark.parametrize("variable", ["HTTPS_PROXY", "ALL_PROXY"])
def test_control_an_https_vault_behind_an_http_proxy_is_built(
    variable: str, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The token rides inside the TLS tunnel to Vault, so the proxy sees only the ``CONNECT``
    target. Engine PR 1752 left this shape unchanged, and so does this check."""
    import requests

    from messagefoundry.config import secretprovider_vault

    monkeypatch.setenv(variable, listener.url)
    client = secretprovider_vault._build_client("https://vault.synthetic.test:8200", _TOKEN)
    # The send goes to the proxy, which hangs up on the CONNECT: a requests error, never the
    # refusal. Mutation: refuse any proxied hop at send time; red, InsecureHopRefused.
    with pytest.raises(requests.exceptions.RequestException):
        client.adapter.get("v1/secret/data/mefor/ad")
    assert listener.connections >= 1


def test_a_proxy_that_appears_after_construction_is_refused_before_sending(
    monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The construction check reads the proxy settings once. An environment changed later, or the
    Windows Internet Settings proxy, can still move the hop, so the adapter checks again before
    each send. Mutation: drop the send-time call; red, the request reaches the proxy."""
    from messagefoundry.config import secretprovider_vault

    client = secretprovider_vault._build_client(f"http://127.0.0.1:{_closed_port()}", _TOKEN)
    monkeypatch.setenv("HTTP_PROXY", listener.url)
    with pytest.raises(InsecureHopRefused, match="well-formed https://"):
        client.adapter.get("v1/secret/data/mefor/ad")
    assert listener.connections == 0, "a socket reached the proxy"


def test_an_http_vault_behind_an_https_proxy_still_names_that_leg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The BACKLOG #300 construction refusal keeps its own text, and reaches the provider's
    caller the same way this one does."""
    from messagefoundry.config import secretprovider_vault

    monkeypatch.setenv("HTTP_PROXY", "https://127.0.0.1:9")
    with pytest.raises(_FAIL_CLOSED, match=r"https:// proxy") as caught:
        secretprovider_vault._build_client("http://127.0.0.1:9", _TOKEN)
    _assert_refused(caught)


def test_a_client_whose_address_cannot_be_read_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A check that cannot read its input fails closed. Mutation: return early on a non-string
    address, as the pre-repair code did; red, the client builds."""
    import ssl

    import requests

    from messagefoundry.transports import strict_requests

    class _Adapter:
        session = requests.Session()
        base_uri = None

    class _Client:
        adapter = _Adapter()

    with pytest.raises(InsecureHopRefused, match="well-formed https://"):
        strict_requests.mount_strict_reply_adapter(
            _Client(), connector="Vault test hop", ssl_context_factory=ssl.create_default_context
        )


# --- the rule itself ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8200",
        "http://127.8.9.10:8200",
        "http://localhost:8200",
        "http://[::1]:8200",
        "HTTP://LOCALHOST:8200",
        "https://vault.synthetic.test:8200",
        "HTTPS://vault.synthetic.test",
    ],
)
def test_on_box_and_https_addresses_are_allowed(url: str) -> None:
    from messagefoundry.transports.strict_requests import _refuse_a_cleartext_vault_hop

    _refuse_a_cleartext_vault_hop(url, None, connector="Vault test hop")


@pytest.mark.parametrize(
    ("url", "proxy"),
    [
        (_REMOTE_HTTP, None),
        ("http://10.0.0.5:8200", None),
        # A name is never resolved, so one that only looks local is remote.
        ("http://localhost.synthetic.test:8200", None),
        # The host is after the @; the loopback-looking part is user information.
        ("http://127.0.0.1@vault.synthetic.test:8200", None),
        # Host-less: names no hop, so it is not counted as loopback.
        ("http://:8200", None),
        ("http://[::1", None),
        # Not http at all, and no scheme at all.
        ("ftp://127.0.0.1:8200", None),
        ("vault.synthetic.test:8200", None),
        ("127.0.0.1:8200", None),
        # Loopback, but through a proxy.
        ("http://127.0.0.1:8200", "http://proxy.synthetic.test:3128"),
    ],
)
def test_every_other_address_is_refused(url: str, proxy: str | None) -> None:
    from messagefoundry.transports.strict_requests import _refuse_a_cleartext_vault_hop

    with pytest.raises(InsecureHopRefused, match="well-formed https://"):
        _refuse_a_cleartext_vault_hop(url, proxy, connector="Vault test hop")


def test_the_refusal_is_fixed_text_that_echoes_no_part_of_the_address() -> None:
    """Two different addresses, one carrying user information, give the same text, and none of
    either address appears in it."""
    from messagefoundry.transports.strict_requests import _refuse_a_cleartext_vault_hop

    texts = []
    for url in ("http://operator:synthetic-pw@vault.synthetic.test:8201", "http://10.9.8.7:8299"):
        with pytest.raises(InsecureHopRefused) as caught:
            _refuse_a_cleartext_vault_hop(url, None, connector="Vault test hop")
        texts.append(str(caught.value))
    assert texts[0] == texts[1]
    for fragment in (
        "operator",
        "synthetic-pw",
        "vault.synthetic.test",
        "8201",
        "10.9.8.7",
        "8299",
    ):
        assert fragment not in texts[0]
    assert texts[0].startswith("Vault test hop: ")


def test_the_refusal_ignores_the_enforcement_dial(monkeypatch: pytest.MonkeyPatch) -> None:
    """No posture is in scope for this hop, so a non-enforcing posture stamped around it does not
    turn the refusal into a warning, and neither does the global insecure-TLS escape."""
    from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
    from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
    from messagefoundry.transports.strict_requests import _refuse_a_cleartext_vault_hop

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with (
        active_hop_posture(HopPosture(enforcing=False)),
        pytest.raises(InsecureHopRefused),
    ):
        _refuse_a_cleartext_vault_hop(_REMOTE_HTTP, None, connector="Vault test hop")


# --- a caller that maps the provider's type to its own message ---------------------------------


@pytest.mark.parametrize("cleartext", [True, False], ids=["cleartext-refusal", "control"])
def test_provision_admin_shows_the_cleartext_refusal_not_the_canned_text(
    cleartext: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """provision-admin turns a SecretProviderError into a canned 'check the reference' line. For
    the cleartext refusal it shows the refusal's own fixed text instead, which says what to fix.
    The control: any other SecretProviderError still gets the canned line."""
    import messagefoundry.__main__ as cli
    import messagefoundry.auth.service as service
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.tls_policy import HopPosture
    from messagefoundry.transports.strict_requests import _CLEARTEXT_VAULT_HOP

    def _raise(*args: object, **kwargs: object) -> None:
        if cleartext:
            refusal = InsecureHopRefused(f"Vault KV secret provider: {_CLEARTEXT_VAULT_HOP}")
            raise SecretProviderError(str(refusal)) from refusal
        raise SecretProviderError("synthetic: unresolved reference")

    monkeypatch.setattr(service, "AuthService", _raise)
    with pytest.raises(cli._ProvisionAuthRefused) as caught:
        cli._build_provision_auth_service(
            ServiceSettings(),
            object(),  # type: ignore[arg-type]
            posture=HopPosture(enforcing=True),
        )
    if cleartext:
        assert "well-formed https://" in str(caught.value)
    else:
        assert str(caught.value) == cli._PROVISION_AUTH_REFUSALS["reference"]


# --- vault BACKLOG #2547: a proxy URL that carries credentials ------------------------------------
#
# An https:// Vault behind an http:// proxy is allowed above, because the token rides inside the TLS
# tunnel. A user:password@ in that proxy's URL does not: requests sends it to the proxy itself, in
# the clear, in the Proxy-Authorization header of the CONNECT that opens the tunnel. So a proxy URL
# that carries credentials and is not https:// is refused, at construction and before each send.

_PROXY_USER = "synthetic-proxy-user"
_PROXY_PW = "synthetic-proxy-pw"  # nosec B105 - a made-up test value, not a credential
_PROXY_AUTH = f"{_PROXY_USER}:{_PROXY_PW}"
_HTTPS_VAULT = "https://vault.synthetic.test:8200"


def _assert_names_no_proxy_part(text: str, port: int) -> None:
    for fragment in (_PROXY_USER, _PROXY_PW, "127.0.0.1", str(port), "vault.synthetic.test"):
        assert fragment not in text


@_ENTRY_POINTS
@pytest.mark.parametrize(
    ("variable", "form"),
    [
        ("HTTPS_PROXY", "http://{auth}@127.0.0.1:{port}"),
        ("https_proxy", "http://{auth}@127.0.0.1:{port}"),
        ("ALL_PROXY", "http://{auth}@127.0.0.1:{port}"),
        ("all_proxy", "http://{auth}@127.0.0.1:{port}"),
        # No scheme: requests reads it as http://, so the credentials go in the clear the same way.
        ("HTTPS_PROXY", "{auth}@127.0.0.1:{port}"),
    ],
    ids=["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "no-scheme"],
)
def test_an_https_vault_behind_a_credentialed_http_proxy_is_refused(
    entry: EntryPoint,
    variable: str,
    form: str,
    monkeypatch: pytest.MonkeyPatch,
    listener: _Listener,
) -> None:
    """RED before the change: each entry point built its client and sent the CONNECT to the proxy,
    with the credentials in a cleartext Proxy-Authorization header. On Windows the lower- and
    upper-case names are one variable; both are kept so the case holds on POSIX too."""
    monkeypatch.setenv(variable, form.format(auth=_PROXY_AUTH, port=listener.port))
    dials = _no_dial(monkeypatch)
    with pytest.raises(_FAIL_CLOSED, match="carries credentials in its URL") as caught:
        entry(monkeypatch, _HTTPS_VAULT)
    _assert_refused(caught, entry)
    _assert_names_no_proxy_part(str(caught.value), listener.port)
    assert dials == []
    assert listener.connections == 0, "a socket reached the proxy"


@pytest.mark.parametrize(
    "form",
    ["https://{auth}@127.0.0.1:{port}", "http://127.0.0.1:{port}"],
    ids=["credentialed-https-proxy", "credential-free-http-proxy"],
)
def test_control_an_https_vault_behind_these_proxies_is_built_and_sent(
    form: str, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The two control arms. An https:// proxy carries its credentials inside TLS, and an http://
    proxy with none has nothing to leak. Each builds and sends to the proxy, which hangs up: a
    requests error, never the refusal. InsecureHopRefused is not a RequestException, so it would
    escape this ``raises``. Mutation: refuse every credentialed proxy, whatever its scheme; red on
    the first arm."""
    import requests

    from messagefoundry.config import secretprovider_vault

    monkeypatch.setenv("HTTPS_PROXY", form.format(auth=_PROXY_AUTH, port=listener.port))
    client = secretprovider_vault._build_client(_HTTPS_VAULT, _TOKEN)
    with pytest.raises(requests.exceptions.RequestException):
        client.adapter.get("v1/secret/data/mefor/ad")
    assert listener.connections >= 1


def test_a_credentialed_proxy_that_appears_after_construction_is_refused_before_sending(
    monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The construction check reads the proxy settings once, so the adapter checks again before
    each send. Mutation: drop the send-time call; red, the CONNECT reaches the proxy."""
    from messagefoundry.config import secretprovider_vault

    client = secretprovider_vault._build_client(_HTTPS_VAULT, _TOKEN)
    monkeypatch.setenv("HTTPS_PROXY", f"http://{_PROXY_AUTH}@127.0.0.1:{listener.port}")
    with pytest.raises(InsecureHopRefused, match="carries credentials in its URL") as caught:
        client.adapter.get("v1/secret/data/mefor/ad")
    _assert_names_no_proxy_part(str(caught.value), listener.port)
    assert listener.connections == 0, "a socket reached the proxy"


def test_a_configured_credentialed_proxy_is_refused_at_construction(
    listener: _Listener,
) -> None:
    """A proxy configured on the client, not in the environment: ``hvac.Client(proxies=...)``
    puts it on the session, and the construction check merges the session's proxies the way
    requests does. Mutation: drop the construction call; red, the client builds."""
    import ssl

    import hvac

    from messagefoundry.transports import strict_requests

    proxy = f"http://{_PROXY_AUTH}@127.0.0.1:{listener.port}"
    client = hvac.Client(url=_HTTPS_VAULT, token=_TOKEN, proxies={"https": proxy})
    with pytest.raises(InsecureHopRefused, match="carries credentials in its URL"):
        strict_requests.mount_strict_reply_adapter(
            client, connector="Vault test hop", ssl_context_factory=ssl.create_default_context
        )
    assert listener.connections == 0, "a socket reached the proxy"


def test_a_configured_credentialed_proxy_is_refused_before_sending(
    listener: _Listener,
) -> None:
    """hvac passes its configured proxies on every request too. The send-time check reads the
    proxies requests merged for that request, so a per-request proxy is covered."""
    from messagefoundry.config import secretprovider_vault

    client = secretprovider_vault._build_client(_HTTPS_VAULT, _TOKEN)
    # Where hvac.Client(proxies=...) keeps them for each request.
    client.adapter._kwargs["proxies"] = {"https": f"http://{_PROXY_AUTH}@127.0.0.1:{listener.port}"}
    with pytest.raises(InsecureHopRefused, match="carries credentials in its URL"):
        client.adapter.get("v1/secret/data/mefor/ad")
    assert listener.connections == 0, "a socket reached the proxy"


@pytest.mark.parametrize(
    "proxy",
    [
        "http://synthetic-user:synthetic-pw@proxy.synthetic.test:3128",
        "HTTP://synthetic-user:synthetic-pw@proxy.synthetic.test:3128",
        "http://synthetic-user@proxy.synthetic.test:3128",
        "http://:synthetic-pw@proxy.synthetic.test:3128",
        "synthetic-user:synthetic-pw@proxy.synthetic.test:3128",
        # SOCKS sends them in its greeting, also in the clear.
        "socks5://synthetic-user:synthetic-pw@proxy.synthetic.test:1080",
        # No loopback exception: the rule is about the URL, not where the proxy is.
        "http://synthetic-user:synthetic-pw@127.0.0.1:3128",
        # The parsers disagree on a backslash before the @; one reading finds credentials.
        "http://synthetic-user\\@proxy.synthetic.test:3128",
        # Will not parse, so its credentials cannot be ruled out.
        "http://synthetic-user:synthetic-pw@[proxy.synthetic.test:3128",
    ],
)
def test_a_proxy_url_with_cleartext_credentials_is_refused(proxy: str) -> None:
    from messagefoundry.transports.strict_requests import _refuse_cleartext_proxy_credentials

    with pytest.raises(InsecureHopRefused, match="carries credentials in its URL"):
        _refuse_cleartext_proxy_credentials(proxy, connector="Vault test hop")


@pytest.mark.parametrize(
    "proxy",
    [
        None,
        "",
        "http://proxy.synthetic.test:3128",
        "proxy.synthetic.test:3128",
        "https://synthetic-user:synthetic-pw@proxy.synthetic.test:3128",
        "HTTPS://synthetic-user:synthetic-pw@proxy.synthetic.test:3128",
    ],
)
def test_control_these_proxy_urls_pass(proxy: str | None) -> None:
    from messagefoundry.transports.strict_requests import _refuse_cleartext_proxy_credentials

    _refuse_cleartext_proxy_credentials(proxy, connector="Vault test hop")


def test_the_proxy_refusal_is_fixed_text_that_echoes_no_part_of_the_url() -> None:
    from messagefoundry.transports.strict_requests import _refuse_cleartext_proxy_credentials

    texts = []
    for proxy in (
        "http://operator:synthetic-pw@proxy.synthetic.test:3181",
        "http://other:another-pw@10.9.8.7:3999",
    ):
        with pytest.raises(InsecureHopRefused) as caught:
            _refuse_cleartext_proxy_credentials(proxy, connector="Vault test hop")
        texts.append(str(caught.value))
    assert texts[0] == texts[1]
    for fragment in ("operator", "synthetic-pw", "proxy.synthetic.test", "3181", "10.9.8.7"):
        assert fragment not in texts[0]
    assert texts[0].startswith("Vault test hop: ")


def test_the_proxy_refusal_ignores_the_enforcement_dial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refused, not warned, under a non-enforcing posture and the global insecure-TLS escape."""
    from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
    from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
    from messagefoundry.transports.strict_requests import _refuse_cleartext_proxy_credentials

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with (
        active_hop_posture(HopPosture(enforcing=False)),
        pytest.raises(InsecureHopRefused),
    ):
        _refuse_cleartext_proxy_credentials(
            "http://synthetic-user:synthetic-pw@proxy.synthetic.test:3128",
            connector="Vault test hop",
        )
