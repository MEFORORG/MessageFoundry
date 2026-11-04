# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``rest._split_or_refuse`` splits uncached, so a refused credential is no urlsplit cache key
(vault BACKLOG #5287).

``urllib.parse.urlsplit`` keeps a process-wide ``lru_cache`` keyed on the string it splits.
``proxy_config_from_settings`` and the ``[egress].allowed_proxy`` gate read a proxy URL's scheme
through ``rest.url_scheme``, so a credential-bearing value the build then refuses stayed in that
cache as a key. Most tests here empty the cache, run one reader, and count the keys: a
process-wide count, so the reader cannot add a key by a path a per-URL spy would not see. The
control is a cached split of the same value, which does add one, so a zero is not a cache that
never counts. The whole-connector test cannot count keys, since the endpoint URL is a key; it
asks whether the proxy value is one. Every value is synthetic.
"""

from __future__ import annotations

import contextlib
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import messagefoundry.transports  # noqa: F401  registers the destination connectors
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.config.wiring import WiringError
from messagefoundry.transports.base import build_destination
from messagefoundry.transports.egress import _check_forward_proxy_egress
from messagefoundry.transports.rest import (
    proxy_config_from_settings,
    refuse_url_credentials,
    url_scheme,
)

#: Synthetic proxy values. Each holds a made-up password the build refuses.
_CREDENTIAL_PROXIES = (
    "http://svc:SYNTHPW@proxy.example.org:3128",  # a user and a password urllib would send
    "http://svc@proxy.example.org:3128",  # a user alone
    "http://:SYNTHPW@proxy.example.org:3128",  # a password alone
)
#: A synthetic endpoint URL with a password, which refuse_url_credentials refuses.
_CREDENTIAL_ENDPOINT = "https://svc:SYNTHPW@partner.example.org/api"
#: The build's refusal for a credential in proxy_url, so a case cannot pass on another one.
_BUILD_REFUSAL = "web-proxy URL credentials"


@pytest.fixture
def urlsplit_cache() -> Iterator[Callable[[], Any]]:
    """Empties urlsplit's cache, yields its ``cache_info``, and empties it again whatever failed, since
    the control leaves a synthetic password in it."""
    cache_info = getattr(urllib.parse.urlsplit, "cache_info", None)
    cache_clear = getattr(urllib.parse.urlsplit, "cache_clear", None)
    if cache_info is None or cache_clear is None:
        pytest.skip("urllib.parse.urlsplit is not cached on this interpreter")
    # Emptied first, so a full cache evicting as it inserts cannot hide an insert.
    cache_clear()
    try:
        yield cache_info
    finally:
        cache_clear()


def _build(proxy: str) -> None:
    proxy_config_from_settings({"proxy_url": proxy}, dest_scheme="https", connection="OB_SYNTH")


def _gate(proxy: str) -> None:
    _check_forward_proxy_egress("outbound 'OB_SYNTH'", {"proxy_url": proxy}, ["proxy.example.org"])


def _scheme(url: str) -> None:
    url_scheme(url, "url")


def _refuse(url: str) -> None:
    refuse_url_credentials(url, "url")


_CASES = [
    *((_build, proxy, (InsecureHopRefused, _BUILD_REFUSAL)) for proxy in _CREDENTIAL_PROXIES),
    # The gate judges the host and leaves the credential to the build, so these values pass it.
    *((_gate, proxy, None) for proxy in _CREDENTIAL_PROXIES),
    # An unencoded '/' in the password reads as a path, which the one proxy parse refuses.
    (_gate, "http://svc:SYNTH/PW@proxy.example.org:3128", (WiringError, "refused before the")),
    # The endpoint readers share the split.
    (_scheme, _CREDENTIAL_ENDPOINT, None),
    (_refuse, _CREDENTIAL_ENDPOINT, (ValueError, "must not carry credentials")),
]


@pytest.mark.parametrize(("read", "url", "refusal"), _CASES)
def test_a_credential_is_read_with_no_urlsplit_cache_key(
    read: Callable[[str], None],
    url: str,
    refusal: tuple[type[Exception], str] | None,
    urlsplit_cache: Callable[[], Any],
) -> None:
    # The refusal's text is matched, so the zero is measured on the path that refuses for the
    # credential and not on one that refuses earlier for something else.
    with pytest.raises(refusal[0], match=refusal[1]) if refusal else contextlib.nullcontext():
        read(url)
    assert urlsplit_cache().currsize == 0, url
    # Control: the cached split of the same value is a key, so the zero above was measured.
    urllib.parse.urlsplit(url)
    assert urlsplit_cache().currsize == 1, url


@pytest.mark.parametrize("proxy", _CREDENTIAL_PROXIES)
@pytest.mark.parametrize(
    "kind",
    [ConnectorType.REST, ConnectorType.SOAP, ConnectorType.FHIR, ConnectorType.DICOMWEB],
)
def test_a_whole_connector_build_leaves_no_key_for_a_refused_proxy_credential(
    kind: ConnectorType, proxy: str, urlsplit_cache: Callable[[], Any]
) -> None:
    """``build_destination`` runs the egress gate and the connector's constructor, and splits the
    endpoint URL cached on the way, so the key count is not zero. The question is whether the proxy
    value is a key: a split of it after the build is then a hit. That finds only a key made by
    the one-argument ``urlsplit(proxy)``; a split with other arguments, or of a string derived
    from the value, is a different key and is not seen here."""
    dest = Destination(
        name="OB_SYNTH",
        type=kind,
        settings={"url": "https://partner.example.org/api", "proxy_url": proxy},
    )
    egress = EgressSettings(
        allowed_http=["partner.example.org"], allowed_proxy=["proxy.example.org"]
    )
    with pytest.raises(InsecureHopRefused, match=_BUILD_REFUSAL):
        build_destination(dest, egress=egress)
    hits = urlsplit_cache().hits
    urllib.parse.urlsplit(proxy)
    assert urlsplit_cache().hits == hits, kind
    # Control: the split just made is a key, so a second one is a hit.
    urllib.parse.urlsplit(proxy)
    assert urlsplit_cache().hits == hits + 1, kind


def test_an_unparseable_url_is_still_refused_with_nothing_of_it_on_the_chain() -> None:
    """The uncached split raises the same NFKC ValueError, so the refusal still fires, and it is
    raised outside the handler, so the ValueError quoting the netloc is not its context (#1796)."""
    # U+FF03 FULLWIDTH NUMBER SIGN normalises under NFKC to '#', which urlsplit refuses in a netloc.
    url = "https://svc:SYNTH\uff03PW@host.example.org/path"
    for call in (_scheme, _refuse):
        with pytest.raises(ValueError, match="url is not a URL that can be parsed") as caught:
            call(url)
        assert caught.value.__context__ is None
        assert caught.value.__cause__ is None
        assert "SYNTH" not in str(caught.value)
    # The cached function refuses the same value, so the uncached one is not a looser reader.
    with pytest.raises(ValueError, match="NFKC"):
        urllib.parse.urlsplit(url)
