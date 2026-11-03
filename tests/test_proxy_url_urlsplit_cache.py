# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A per-connection ``proxy_url`` is read with no urlsplit cache key (vault BACKLOG #5287).

``urllib.parse.urlsplit`` keeps a process-wide ``lru_cache`` keyed on the string it splits. The
connector build and the ``[egress].allowed_proxy`` gate read a proxy URL's scheme through
``rest.url_scheme``, so a credential-bearing value the build then refuses stayed in that cache as a
key. Each test here empties the cache, runs one reader, and counts the keys: a process-wide count,
so no reader can add a key by a path a per-URL spy would not see. The control is a cached split of
the same value, which does add one, so a zero is not a cache that never counts. Every value is
synthetic.
"""

from __future__ import annotations

import contextlib
import urllib.parse
from collections.abc import Callable, Iterator

import pytest

from messagefoundry.config.tls_policy import InsecureHopRefused
from messagefoundry.config.wiring import WiringError
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


@pytest.fixture
def cache_count() -> Iterator[Callable[[], int]]:
    """Empties urlsplit's cache, yields its key count, and empties it again whatever failed, since
    the control leaves a synthetic password in it."""
    cache_info = getattr(urllib.parse.urlsplit, "cache_info", None)
    cache_clear = getattr(urllib.parse.urlsplit, "cache_clear", None)
    if cache_info is None or cache_clear is None:
        pytest.skip("urllib.parse.urlsplit is not cached on this interpreter")
    # Emptied first, so a full cache evicting as it inserts cannot hide an insert.
    cache_clear()
    try:
        yield lambda: int(cache_info().currsize)
    finally:
        cache_clear()


def _build(proxy: str) -> None:
    proxy_config_from_settings({"proxy_url": proxy}, dest_scheme="https", connection="OB_SYNTH")


def _gate(proxy: str) -> None:
    _check_forward_proxy_egress("outbound 'OB_SYNTH'", {"proxy_url": proxy}, ["proxy.example.org"])


_CASES = [
    *((_build, proxy, InsecureHopRefused) for proxy in _CREDENTIAL_PROXIES),
    # The gate judges the host and leaves the credential to the build, so these values pass it.
    *((_gate, proxy, None) for proxy in _CREDENTIAL_PROXIES),
    # An unencoded '/' in the password reads as a path, which the one proxy parse refuses.
    (_gate, "http://svc:SYNTH/PW@proxy.example.org:3128", WiringError),
]


@pytest.mark.parametrize(("read", "proxy", "refusal"), _CASES)
def test_a_proxy_credential_is_read_with_no_urlsplit_cache_key(
    read: Callable[[str], None],
    proxy: str,
    refusal: type[Exception] | None,
    cache_count: Callable[[], int],
) -> None:
    with pytest.raises(refusal) if refusal else contextlib.nullcontext():
        read(proxy)
    assert cache_count() == 0, proxy
    # Control: the cached split of the same value is a key, so the zero above was measured.
    urllib.parse.urlsplit(proxy)
    assert cache_count() == 1, proxy


def test_an_unparseable_url_is_still_refused_with_nothing_of_it_on_the_chain(
    cache_count: Callable[[], int],
) -> None:
    """The uncached split raises the same NFKC ValueError, so the refusal still fires, and it is
    raised outside the handler, so the ValueError quoting the netloc is not its context (#1796)."""
    # U+FF03 FULLWIDTH NUMBER SIGN normalises under NFKC to '#', which urlsplit refuses in a netloc.
    url = "https://svc:SYNTH＃PW@host.example.org/path"
    for call in (
        lambda: url_scheme(url, "url"),
        lambda: refuse_url_credentials(url, "url"),
    ):
        with pytest.raises(ValueError, match="url is not a URL that can be parsed") as caught:
            call()
        assert caught.value.__context__ is None
        assert caught.value.__cause__ is None
        assert "SYNTH" not in str(caught.value)
    # The cached function refuses the same value, so the uncached one is not a looser reader.
    with pytest.raises(ValueError):
        urllib.parse.urlsplit(url)
    assert cache_count() == 0
