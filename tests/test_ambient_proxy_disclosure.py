# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An environment web proxy is disclosed at start, never silent (BACKLOG #1125, ASVS 4.2.1).

Owner ruling 2026-10-11: an ambient proxy must not attach silently, or must be disclosed. The
engine's urllib openers follow ``HTTP_PROXY``, ``HTTPS_PROXY`` and the system proxy, and its Vault
clients follow those and ``ALL_PROXY`` too. So ``serve`` and ``supervise`` name that proxy, and
the hops that follow it, in one WARNING per process.
Both polarities are tested: with a proxy in the environment the warning names its host and no
credential; with none, nothing is logged.
"""

from __future__ import annotations

import contextlib
import logging
import os
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from requests.utils import get_environ_proxies, select_proxy

from messagefoundry.transports.ambient_proxy import ambient_proxy_warning, environment_proxy_hosts

_SECRET = "s3cretpw"
_PROXY = f"http://alice:{_SECRET}@proxy.example:3128"


@pytest.fixture
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Clear every proxy source ``urllib.request.getproxies()`` reads, so the box's own settings
    cannot decide a test. The system readers are stubbed on the platforms that have them."""
    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("REQUEST_METHOD", raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    assert urllib.request.getproxies() == {}, "a proxy source survived the fixture"
    return monkeypatch


def test_hosts_drop_credentials_and_keys_no_http_hop_reads() -> None:
    hosts = environment_proxy_hosts(
        {
            "http": _PROXY,
            "https": "bob:pw@proxy.example:3129",
            "all": "",
            "no": "localhost",
            "ftp": "http://ftp-proxy.example:21",
            "socks": "socks5://socks.example:1080",
        }
    )
    assert hosts == {"http": "http://proxy.example:3128", "https": "http://proxy.example:3129"}


def test_only_requests_reads_an_all_proxy() -> None:
    """The premise behind listing only the Vault clients for ``ALL_PROXY``: urllib's handler
    gets no opener method for it, and requests selects it for any scheme."""
    handler = urllib.request.ProxyHandler({"all": "http://p.example:1"})
    assert not hasattr(handler, "http_open") and not hasattr(handler, "https_open")
    assert select_proxy("https://vault.example", {"all": "http://p.example:1"}) == (
        "http://p.example:1"
    )
    text = ambient_proxy_warning(proxies={"all": _PROXY})
    assert text is not None and "all targets via http://proxy.example:3128" in text
    assert "Vault and OpenBao" in text
    for hop in ("HTTP-family", "alert webhook", "OIDC", "AI broker"):
        assert hop not in text, hop


@pytest.mark.parametrize(
    "value",
    [
        "http://",
        "http://proxy.example\nWARNING forged:1",
        "http://pro xy.example:3128",
        # A userinfo percent-encoded into what a looser parser would read as the host.
        f"http://alice%3A{_SECRET}%40proxy.example:3128",
    ],
)
def test_an_unreadable_proxy_value_is_not_echoed(value: str) -> None:
    assert environment_proxy_hosts({"http": value}) == {"http": "an unreadable value"}


def test_an_ipv6_proxy_is_named_with_its_brackets() -> None:
    assert environment_proxy_hosts({"https": "http://u:p@[2001:db8::1]:3128"}) == {
        "https": "http://[2001:db8::1]:3128"
    }


def test_no_proxy_means_no_warning() -> None:
    assert ambient_proxy_warning(proxies={}) is None
    assert ambient_proxy_warning(proxies={"no": "localhost"}) is None


def test_the_warning_names_every_hop_and_no_credential() -> None:
    text = ambient_proxy_warning(proxies={"https": _PROXY})
    assert text is not None
    assert "https targets via http://proxy.example:3128" in text
    assert _SECRET not in text and "alice" not in text
    for hop in ("HTTP-family", "alert webhook", "OIDC", "AI broker", "Vault and OpenBao"):
        assert hop in text, hop


def test_a_no_proxy_of_star_means_no_warning() -> None:
    """``NO_PROXY=*`` sends every hop direct in urllib and in requests, so nothing is disclosed."""
    assert ambient_proxy_warning(proxies={"https": _PROXY, "no": "*"}) is None
    assert ambient_proxy_warning(proxies={"https": _PROXY, "no": "intranet.example"}) is not None
    # urllib compares the raw value, so a padded star bypasses nothing and must still warn.
    assert ambient_proxy_warning(proxies={"https": _PROXY, "no": " *"}) is not None


def test_the_proxy_scheme_is_named_as_the_libraries_read_it() -> None:
    """The scheme is named as written, and a value with none as ``http``, which both read it as."""
    assert environment_proxy_hosts({"https": "https://proxy.example:443"}) == {
        "https": "https://proxy.example:443"
    }
    assert environment_proxy_hosts({"https": "proxy.example:3128"}) == {
        "https": "http://proxy.example:3128"
    }


def test_the_warning_does_not_claim_a_tls_proxy_leg_for_the_urllib_hops() -> None:
    """Naming ``https://proxy`` must not read as an encrypted leg (SDS-3.7).

    For an https target, urllib reaches even an ``https://`` proxy over plain TCP, and sends
    ``CONNECT`` and any proxy credential in cleartext. ``tests/test_proxy_url_credentials_refused.py``
    measures that on the wire. Only the Vault clients get a TLS leg, so only they are said to."""
    text = ambient_proxy_warning(proxies={"https": "https://u:pw@proxy.example:443"})
    assert text is not None and "https targets via https://proxy.example:443" in text
    assert "An https:// one is not refused, and is not safe either." in text
    assert "the urllib hops reach any proxy over plain TCP" in text
    assert "and any credential from the proxy URL, in cleartext" in text
    assert "The Vault and OpenBao clients do open TLS to an https:// proxy" in text
    for claim in ("is TLS", "encrypted", "is safe"):
        assert claim not in text, claim
    # With only an http entry, no Vault hop follows the proxy, so no TLS leg is claimed at all.
    http_only = ambient_proxy_warning(proxies={"http": "https://proxy.example:443"})
    assert http_only is not None and "open TLS" not in http_only
    # With only an all entry, no urllib hop follows it, so their sentences are left out.
    all_only = ambient_proxy_warning(proxies={"all": "https://proxy.example:443"})
    assert all_only is not None and "urllib" not in all_only and "open TLS" in all_only


def test_an_http_only_proxy_does_not_list_the_vault_clients() -> None:
    """requests picks no ``http`` entry for an ``https://`` Vault, and ``strict_requests`` refuses an
    ``http://`` Vault behind any proxy. So an ``http``-only proxy carries no Vault hop."""
    assert select_proxy("https://vault.example:8200", {"http": "http://p.example:1"}) is None
    text = ambient_proxy_warning(proxies={"http": _PROXY})
    assert text is not None and "http targets via http://proxy.example:3128" in text
    assert "Vault" not in text
    for hop in ("HTTP-family", "alert webhook", "OIDC", "AI broker"):
        assert hop in text, hop


def test_the_remedy_says_proxy_url_does_not_stop_the_warning() -> None:
    """``[egress].proxy_url`` moves only the HTTP family, and the warning reads no settings."""
    text = ambient_proxy_warning(proxies={"https": _PROXY})
    assert text is not None
    assert "[egress].proxy_url to an address names a proxy for the HTTP family only" in text
    assert "The other hops keep this proxy, and this warning still logs" in text


def test_the_warning_does_not_promise_the_vault_a_loopback_bypass(
    no_ambient_proxy: pytest.MonkeyPatch,
) -> None:
    """requests has no loopback-direct rule, so an https Vault on 127.0.0.1 is proxied.

    ``get_environ_proxies`` runs requests' own bypass check, which ``select_proxy`` never does."""
    no_ambient_proxy.setenv("HTTPS_PROXY", "http://p.example:1")
    assert get_environ_proxies("https://127.0.0.1:8200").get("https") == "http://p.example:1"
    # Control: the same call does honour a bypass rule when one names the host.
    no_ambient_proxy.setenv("NO_PROXY", "127.0.0.1")
    assert "https" not in get_environ_proxies("https://127.0.0.1:8200")
    text = ambient_proxy_warning(proxies={"https": _PROXY})
    assert text is not None
    assert "Vault and OpenBao clients, loopback addresses included" in text
    assert "The urllib hops dial a loopback host direct" in text


class _Keep(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@contextlib.contextmanager
def _kept(logger: logging.Logger) -> Iterator[list[logging.LogRecord]]:
    """The records ``logger`` handles inside the block, on the logger itself: serve's
    configure_logging replaces the root handlers that caplog uses."""
    handler = _Keep()
    logger.addHandler(handler)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)


def _serve_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str = "serve"
) -> list[str]:
    """Run ``serve`` to the point it hands uvicorn the app, and return the ambient-proxy warnings
    as an operator reads them. Read at the end, because serve's own handlers redact the record."""
    from tests.test_header_floor_wire import _serve_captured

    with _kept(logging.getLogger("messagefoundry.__main__")) as records:
        rc, _, _ = _serve_captured(tmp_path, monkeypatch, command=command)
    assert rc == 0
    return [
        r.getMessage()
        for r in records
        if r.levelno == logging.WARNING and "web proxy from the environment" in r.getMessage()
    ]


def test_serve_discloses_an_environment_proxy(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    no_ambient_proxy.setenv("HTTPS_PROXY", _PROXY)
    warnings = _serve_warnings(tmp_path, no_ambient_proxy)
    assert len(warnings) == 1, warnings
    assert "https targets via http://proxy.example:3128" in warnings[0], warnings
    assert _SECRET not in warnings[0]


def test_serve_without_an_environment_proxy_warns_of_none(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    assert _serve_warnings(tmp_path, no_ambient_proxy) == []


def test_supervise_discloses_an_environment_proxy_before_spawning(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    """The supervisor's own store open and TLS pair renewal can use the proxy, so it names it too."""

    async def _no_fleet(*args: object, **kwargs: object) -> int:
        return 0

    no_ambient_proxy.setattr("messagefoundry.pipeline.supervisor.supervise", _no_fleet)
    no_ambient_proxy.setenv("HTTPS_PROXY", _PROXY)
    warnings = _serve_warnings(tmp_path, no_ambient_proxy, command="supervise")
    assert len(warnings) == 1, warnings
    assert "https targets via http://proxy.example:3128" in warnings[0], warnings
