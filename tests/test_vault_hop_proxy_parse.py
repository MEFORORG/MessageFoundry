# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Vault hop refuses, with fixed text, a proxy URL requests cannot read or send (vault BACKLOG
#3454).

``_refuse_cleartext_proxy_credentials`` passes a credentialed ``https://`` proxy, so its URL went on
to requests. On some URLs requests' own reads at send time then failed, with an error whose text or
attributes held the proxy password. That error became the cause of the provider's own error, and
the privilege probe kept its text. The hop now makes the same reads first and refuses with fixed
text, at construction and before each send.

Synthetic data only: the token, password, user and host names are made up.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Iterator
from typing import Any

import pytest

from messagefoundry.config.tls_policy import InsecureHopRefused
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from tests._vault_hop_sockets import _closed_port, _Listener
from tests._vault_hop_sockets import listener as listener  # noqa: F401  (the fixture, re-exported)

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
_PW = "synthetic-proxy-pw"  # nosec B105 - a made-up test value, not a credential
_USER = "synthetic-proxy-user"
_HTTPS_VAULT = "https://vault.synthetic.test:8200"
_CONNECTOR = "Vault KV secret provider"

#: Proxy URLs requests cannot send. ``{port}`` is filled in with a local listener's port.
_UNSENDABLE = [
    "https://:" + _PW + "\u2100x@127.0.0.1:{port}",
    "https://" + _USER + ":" + _PW + "\u2100x@127.0.0.1:{port}",
    "https://" + _USER + "\u2100:" + _PW + "@127.0.0.1:{port}",
    "https://" + _USER + ":" + _PW + "\u0100@127.0.0.1:{port}",
]
_UNSENDABLE_IDS = ["a", "b", "c", "d"]

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
def _hop_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _HOP_ENV:
        monkeypatch.delenv(name, raising=False)
    import urllib.request

    # With no *_proxy variable left, urllib would fall back to the host's own system proxy.
    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    import hvac.v1  # type: ignore[import-untyped]  # the [vault] extra ships no stubs

    for name in ("VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
        monkeypatch.setattr(hvac.v1, name, None, raising=False)
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    yield


def _everything_said(exc: BaseException) -> str:
    """Every place an exception chain can carry text: each link's formatted traceback, its
    arguments' ``repr``, and its attributes' ``repr``. ``UnicodeEncodeError`` keeps the string it
    was encoding in ``object``, which ``str()`` does not show."""
    parts = ["".join(traceback.format_exception(exc))]
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    while pending:
        link = pending.pop()
        if id(link) in seen:
            continue
        seen.add(id(link))
        parts.append(repr(link.args))
        parts.extend(repr(value) for value in getattr(link, "__dict__", {}).values())
        parts.extend(repr(getattr(link, name, None)) for name in ("object", "reason", "msg"))
        pending.extend(nxt for nxt in (link.__cause__, link.__context__) if nxt is not None)
    return "\n".join(parts)


@pytest.mark.parametrize("form", _UNSENDABLE, ids=_UNSENDABLE_IDS)
def test_a_proxy_that_appears_after_construction_is_refused_with_fixed_text(
    form: str, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """RED before the change: the send raised requests' own ``ValueError`` or
    ``UnicodeEncodeError``, which held the password or the user name. Three hooks refuse on a
    send, so dropping any one of them leaves this green; each is pinned by a direct test below."""
    from messagefoundry.config import secretprovider_vault

    client = secretprovider_vault._build_client(_HTTPS_VAULT, _TOKEN, revocation_attested=True)
    monkeypatch.setenv("HTTPS_PROXY", form.format(port=listener.port))
    with pytest.raises(ValueError) as caught:
        client.adapter.get("v1/secret/data/mefor/ad")
    said = _everything_said(caught.value)
    assert _PW not in said and _USER not in said
    assert listener.connections == 0, "a socket reached the proxy"
    from messagefoundry.transports.strict_requests import _UNSENDABLE_PROXY_URL, VaultHopRefused

    assert type(caught.value) is VaultHopRefused
    assert str(caught.value) == f"{_CONNECTOR}: {_UNSENDABLE_PROXY_URL}"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize("form", _UNSENDABLE, ids=_UNSENDABLE_IDS)
def test_the_key_provider_keeps_no_password_anywhere_in_its_error(
    form: str, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    """The path the finding named: ``active_key`` on an attested store hop, with the proxy in the
    environment when it runs. RED before the change: the provider's error held requests' error as
    its cause, password included. Now the client build refuses, and the chain holds only the
    hop's fixed text."""
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.keyprovider import KeyProviderError
    from messagefoundry.store.keyprovider_vault import VaultKeyProvider

    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _HTTPS_VAULT)
    monkeypatch.setenv("HTTPS_PROXY", form.format(port=listener.port))
    settings = StoreSettings(
        vault_revocation_attested=True,
        vault_revocation_attested_reason="synthetic: covered outside the engine",
    )
    with pytest.raises(KeyProviderError) as caught:
        VaultKeyProvider(settings).active_key()
    said = _everything_said(caught.value)
    assert _PW not in said and _USER not in said
    assert listener.connections == 0, "a socket reached the proxy"
    from messagefoundry.transports.strict_requests import _UNSENDABLE_PROXY_URL, VaultHopRefused

    assert type(caught.value.__cause__) is VaultHopRefused
    assert str(caught.value).endswith(_UNSENDABLE_PROXY_URL)


@pytest.mark.parametrize("form", _UNSENDABLE, ids=_UNSENDABLE_IDS)
def test_the_privilege_probe_keeps_no_password_in_its_problems_or_log(
    form: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``check-privileges`` on a hop whose proxy appears after the client is built, so the
    send-time check is the one that fires. RED before the change: on the first shape the problem
    text and its WARNING line kept 200 characters of requests' error, password included; on the
    others the probe went on to a second read the same error refused."""
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.privilege_probes import read_vault_token

    proxy = form.format(port=_closed_port())

    def build(address: str, token: str) -> Any:
        client = secretprovider_vault.secrets_vault_client(address, token, revocation_attested=True)
        monkeypatch.setenv("HTTPS_PROXY", proxy)
        return client

    with caplog.at_level(logging.WARNING):
        reading = read_vault_token(
            lambda: _TOKEN, lambda: _HTTPS_VAULT, build, lambda: {"secret/data/ad": frozenset()}
        )
    for secret in (_PW, _USER):
        assert secret not in "\n".join(reading.problems)
        assert secret not in caplog.text
    from messagefoundry.transports.strict_requests import _UNSENDABLE_PROXY_URL

    # One problem: a refusal of the hop stops the probe before the capabilities read.
    assert reading.problems == (f"token lookup-self failed: {_CONNECTOR}: {_UNSENDABLE_PROXY_URL}",)


@pytest.mark.parametrize(
    "form",
    [
        *_UNSENDABLE,
        # The controls: requests reads and sends each of these.
        "https://" + _USER + ":" + _PW + "@127.0.0.1:{port}",
        "https://:" + _PW + "@127.0.0.1:{port}",
        "https://" + _USER + ":" + _PW + "\u00e9@127.0.0.1:{port}",
        "https://127.0.0.1:{port}",
        "http://127.0.0.1:{port}",
        "127.0.0.1:{port}",
    ],
)
def test_the_check_agrees_with_requests_own_reads(form: str) -> None:
    """On each row, the check refuses the URL exactly when a plain requests session fails on it
    before it dials. A plain session with the URL as its proxy, aimed at a closed port, fails on its
    own reads, or gets as far as the dial and gets a ``ConnectionError``. Not every shape agrees: a
    URL with no host fails requests' host check, whose error is fixed text, and passes the check.
    Mutation: drop the Latin-1 encode from the check; red on the last unsendable row. Drop the raw
    ``urlsplit``; red on the first, the only row where that read decides. Read on requests 2.34.2; a requests that reads these URLs
    differently goes red here rather than leaving the check out of step."""
    import requests

    from messagefoundry.transports.strict_requests import _proxy_url_requests_cannot_send

    proxy = form.format(port=_closed_port())
    with requests.Session() as session:
        session.trust_env = False  # only the proxy passed below applies
        try:
            session.get(_HTTPS_VAULT, proxies={"https": proxy}, timeout=5)
        except requests.exceptions.ConnectionError:
            dialled = True
        except (ValueError, TypeError, requests.exceptions.RequestException):
            dialled = False
        else:
            pytest.fail("a closed port answered")
    assert _proxy_url_requests_cannot_send(proxy) is not dialled


@pytest.mark.parametrize(
    ("proxy", "expected"),
    [
        # An https:// proxy in front of an http:// Vault: the unverifiable-leg check would refuse
        # it too, so this pins the new check ahead of that one.
        (_UNSENDABLE[0], "_UNSENDABLE_PROXY_URL"),
        # The same URL as an http:// proxy: the cleartext-credential check comes first.
        ("http" + _UNSENDABLE[0].removeprefix("https"), "_CLEARTEXT_PROXY_CREDENTIALS"),
    ],
    ids=["before-the-leg-check", "after-the-credential-check"],
)
def test_the_build_runs_the_check_in_the_send_time_order(proxy: str, expected: str) -> None:
    """At construction the check runs where it runs on a send: after the cleartext-credential
    check, before the https-proxy-for-an-http-Vault check. So a hop gets one refusal at both
    points. The Vault is loopback http, which every one of the three checks would refuse.
    Mutation: move the new check below the leg check; red on the first row. Move it above the
    credential check; red on the second."""
    import requests

    from messagefoundry.transports import strict_requests

    with requests.Session() as session:
        session.trust_env = False
        with pytest.raises(strict_requests.VaultHopRefused) as caught:
            strict_requests._refuse_an_insecure_vault_hop(
                session,
                "http://127.0.0.1:8200",
                connector="Vault test hop",
                request_proxies={"http": proxy.format(port=_closed_port())},
            )
    assert str(caught.value) == f"Vault test hop: {getattr(strict_requests, expected)}"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def _adapter() -> Any:
    import ssl

    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    return StrictReplyAdapter(
        connector="Vault test hop",
        ssl_context_factory=ssl.create_default_context,
        revocation_attested=True,
        attestation_section="secrets",
    )


def test_proxy_manager_for_refuses_it_on_its_own() -> None:
    """A send-time check for a requests too old to call the hook. Mutation: drop it; red."""
    from messagefoundry.transports.strict_requests import _UNSENDABLE_PROXY_URL

    adapter = _adapter()
    with pytest.raises(InsecureHopRefused) as caught:
        adapter.proxy_manager_for(_UNSENDABLE[3].format(port=3128))
    assert str(caught.value) == f"Vault test hop: {_UNSENDABLE_PROXY_URL}"
    assert adapter.proxy_manager == {}, "a manager was built for the refused proxy"


def test_get_connection_with_tls_context_refuses_it_first() -> None:
    """The hook requests calls first on a send, before it reads the proxy URL. On the first row
    only the raw read fails, and ``proxy_manager_for`` gets the URL percent-encoded, so without
    this check a manager is built and the call returns. Mutation: drop it; red."""
    import requests

    from messagefoundry.transports.strict_requests import _UNSENDABLE_PROXY_URL

    adapter = _adapter()
    prepared = requests.Request("GET", _HTTPS_VAULT + "/v1/sys/health").prepare()
    proxies = {"https": _UNSENDABLE[0].format(port=3128)}
    with pytest.raises(InsecureHopRefused) as caught:
        adapter.get_connection_with_tls_context(prepared, True, proxies=proxies)
    assert str(caught.value) == f"Vault test hop: {_UNSENDABLE_PROXY_URL}"
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert adapter.proxy_manager == {}, "a manager was built for the refused proxy"


def test_request_url_refuses_it_on_its_own() -> None:
    """requests reads the raw proxy URL in ``request_url``, after the pool is built, and only that
    read fails on the first row: ``proxy_manager_for`` gets the URL with that character already
    percent-encoded. Mutation: drop the check in ``request_url``; red, requests' error quotes the
    password."""
    import requests

    from messagefoundry.transports.strict_requests import _UNSENDABLE_PROXY_URL

    prepared = requests.Request("GET", _HTTPS_VAULT + "/v1/sys/health").prepare()
    with pytest.raises(InsecureHopRefused) as caught:
        _adapter().request_url(prepared, {"https": _UNSENDABLE[0].format(port=3128)})
    assert str(caught.value) == f"Vault test hop: {_UNSENDABLE_PROXY_URL}"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_the_check_leaves_no_proxy_url_in_the_url_parser_cache() -> None:
    """The check reads the raw URL with ``urlsplit`` minus its ``lru_cache``, so a refused proxy's
    password is not kept process-wide. RED with the public, cached ``urlsplit`` in its place: the
    refused URL is then a cache key. Skipped where the interpreter does not cache ``urlsplit``."""
    import urllib.parse

    from messagefoundry.transports.strict_requests import _proxy_url_requests_cannot_send

    cache_info = getattr(urllib.parse.urlsplit, "cache_info", None)
    if cache_info is None:
        pytest.skip("urllib.parse.urlsplit is not cached on this interpreter")
    proxy = _UNSENDABLE[3].format(port=3128)  # passes urlsplit, refused by the Latin-1 encode
    urllib.parse.urlsplit.cache_clear()  # type: ignore[attr-defined]
    assert _proxy_url_requests_cannot_send(proxy) is True
    assert cache_info().currsize == 0, "the check put the proxy URL in urlsplit's cache"
