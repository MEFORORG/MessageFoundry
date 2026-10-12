# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An environment web proxy is disclosed at start, never silent (BACKLOG #1125, ASVS 4.2.1).

Owner ruling 2026-10-11: an ambient proxy must not attach silently, or must be disclosed. The
engine's urllib openers follow ``HTTP_PROXY``, ``HTTPS_PROXY`` and the system proxy, and its Vault
clients follow those and ``ALL_PROXY``. So ``serve`` and ``supervise`` name each proxy entry in
force, and the hops that may read one, in one WARNING per process.

The warning is static: it names entries and a fixed list of hops, and claims nothing about which
hop uses which entry or what the leg to the proxy protects. So no warning may use a word that makes
such a claim. Both polarities are tested: with a proxy in the environment the warning names its
host and no credential; with none, or with ``NO_PROXY=*``, nothing logs.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import logging
import os
import random
import sys
import types
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.transports.ambient_proxy import (
    ambient_proxy_warning,
    environment_proxy_hosts,
    warn_ambient_proxy,
)

_SECRET = "s3cretpw"
_SECRET2 = "hunter2pw"
_PROXY = f"http://alice:{_SECRET}@proxy.example:3128"
_P = "http://proxy.example:3128"
_Q = "http://other.example:8080"
_UNREADABLE = "an unreadable value"
_HOPS = "The hops that may read an environment proxy include at least HTTP-family connections"
_VAULT = "the Vault and OpenBao clients"
_POINTER = '[egress], "serve names an environment proxy at start"'
#: Words that would make the warning claim use, refusal or protection rather than disclose.
_CLAIM_WORDS = (
    "tls",
    "encrypt",
    "secure",
    "safe",
    "protected",
    "refuse",
    "use it",
    "uses",
    "used",
    "through",
    "in force",
)
#: Every user or password fragment a test below puts in a proxy URL.
_CREDENTIALS = ("alice", _SECRET, "bob", _SECRET2)


@pytest.fixture(autouse=True)
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


def _assert_claims_nothing(text: str) -> None:
    assert "@" not in text, text
    for fragment in _CREDENTIALS:
        assert fragment not in text, (fragment, text)
    for word in _CLAIM_WORDS:
        assert word not in text.lower(), (word, text)


@pytest.mark.parametrize(
    ("proxies", "labels"),
    [
        pytest.param({"https": _P}, {"https": _P}, id="https"),
        pytest.param({"http": _P}, {"http": _P}, id="http"),
        pytest.param({"all": _P}, {"all": _P}, id="all"),
        pytest.param({"http": _P, "all": _Q}, {"http": _P, "all": _Q}, id="http-and-all"),
        pytest.param({"http": _P, "https": _Q}, {"http": _P, "https": _Q}, id="two-hosts"),
        pytest.param(
            {"https": _PROXY, "all": f"bob:{_SECRET2}@other.example:8080"},
            {"https": _P, "all": _Q},
            id="credentialed",
        ),
        pytest.param(
            {"http": f"http://bob:{_SECRET2}@pro xy.example:3128"},
            {"http": _UNREADABLE},
            id="unparseable",
        ),
        pytest.param({"https": "   "}, {"https": _UNREADABLE}, id="whitespace-only"),
    ],
)
def test_the_warning_names_each_entry_once_and_the_hops_that_may_read_one(
    proxies: dict[str, str], labels: dict[str, str]
) -> None:
    text = ambient_proxy_warning(proxies=proxies)
    assert text is not None
    for key, label in labels.items():
        assert text.count(f"The {key} proxy is {label}. ") == 1, (key, label, text)
    assert text.count(" proxy is ") == len(labels), text
    assert text.count(_HOPS) == 1, text
    assert text.count(_POINTER) == 1, text
    _assert_claims_nothing(text)


def _hide_hvac(monkeypatch: pytest.MonkeyPatch) -> None:
    """``import hvac`` raises ImportError while ``sys.modules`` holds ``None`` for it."""
    monkeypatch.setitem(sys.modules, "hvac", None)


def _provide_hvac(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stand-in ``hvac`` the import system finds, so the test does not need the extra."""
    stub = types.ModuleType("hvac")
    stub.__spec__ = importlib.machinery.ModuleSpec("hvac", None)
    monkeypatch.setitem(sys.modules, "hvac", stub)


@pytest.mark.parametrize("proxies", [{"https": _P}, {"all": _P}, {"http": _P, "all": _Q}])
def test_the_vault_clients_are_named_only_when_hvac_is_importable(
    monkeypatch: pytest.MonkeyPatch, proxies: dict[str, str]
) -> None:
    _provide_hvac(monkeypatch)
    text = ambient_proxy_warning(proxies=proxies)
    assert text is not None and text.count(_VAULT) == 1, text
    _hide_hvac(monkeypatch)
    text = ambient_proxy_warning(proxies=proxies)
    assert text is not None and "Vault" not in text, text
    # The entry is still in force, so it is still named.
    assert text.count(" proxy is ") == len(proxies), text


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


@pytest.mark.parametrize(
    "value",
    [
        "http://",
        "http://proxy.example\nWARNING forged:1",
        "http://pro xy.example:3128",
        # A userinfo percent-encoded into what a looser parser would read as the host.
        f"http://alice%3A{_SECRET}%40proxy.example:3128",
        # urllib reads the raw value, so a padded one is not named as the address it strips to.
        " http://proxy.example:3128",
    ],
)
def test_an_unreadable_proxy_value_is_not_echoed(value: str) -> None:
    assert environment_proxy_hosts({"http": value}) == {"http": _UNREADABLE}
    text = ambient_proxy_warning(proxies={"http": value})
    assert text is not None and f"The http proxy is {_UNREADABLE}. " in text
    assert "forged" not in text and "pro xy" not in text
    _assert_claims_nothing(text)


def test_an_ipv6_proxy_is_named_with_its_brackets() -> None:
    assert environment_proxy_hosts({"https": "http://u:p@[2001:db8::1]:3128"}) == {
        "https": "http://[2001:db8::1]:3128"
    }


def test_the_proxy_scheme_is_named_as_the_libraries_read_it() -> None:
    """The scheme is named as written, and a value with none as ``http``, which both read it as."""
    assert environment_proxy_hosts({"https": "https://proxy.example:443"}) == {
        "https": "https://proxy.example:443"
    }
    assert environment_proxy_hosts({"https": "proxy.example:3128"}) == {
        "https": "http://proxy.example:3128"
    }


def test_no_proxy_means_no_warning() -> None:
    assert ambient_proxy_warning(proxies={}) is None
    assert ambient_proxy_warning(proxies={"no": "localhost"}) is None
    assert ambient_proxy_warning(proxies={"ftp": _P, "socks": _Q, "https": ""}) is None


def test_a_no_proxy_of_star_means_no_warning() -> None:
    """``NO_PROXY=*`` sends every hop direct in urllib and in requests, so nothing is disclosed."""
    assert ambient_proxy_warning(proxies={"https": _P, "all": _Q, "no": "*"}) is None
    # Any other bypass list depends on the host, so it is not evaluated and the warning stands.
    assert ambient_proxy_warning(proxies={"https": _P, "no": "intranet.example"}) is not None
    assert ambient_proxy_warning(proxies={"https": _P, "no": "proxy.example,*.example"}) is not None
    # urllib compares the raw value, so a padded star bypasses nothing and must still warn.
    assert ambient_proxy_warning(proxies={"https": _P, "no": " *"}) is not None


def test_the_warning_points_at_one_doc_section_and_gives_the_remedy() -> None:
    """``[egress].proxy_url`` changes only the HTTP family, and the warning reads no settings."""
    for proxies in ({"https": _P}, {"all": _P}):
        text = ambient_proxy_warning(proxies=proxies)
        assert text is not None
        assert "To stop it, clear http_proxy, https_proxy and all_proxy" in text
        assert "[egress].proxy_url to an address changes only the HTTP-family connections" in text
        assert "Every other hop is unchanged, and this warning still logs" in text
    doc = (Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md").read_text("utf-8")
    assert "#### `serve` names an environment proxy at start" in doc


_FUZZ_ALPHABET = "abcxyz019.-_:/@[]%?#*, \t\r\n\x00\x07\x1b\x7féİ​‮ ﻿．\U0001f600\ud800"


def test_the_warning_never_raises_on_garbage_values() -> None:
    """400 random values under random keys, seeded so a failure reproduces."""
    rng = random.Random(1125)
    keys = ("http", "https", "all", "no", "HTTPS", "All", "ftp", "")
    for _ in range(400):
        proxies = {
            rng.choice(keys): "".join(rng.choices(_FUZZ_ALPHABET, k=rng.randint(0, 40)))
            for _ in range(rng.randint(1, 4))
        }
        text = ambient_proxy_warning(proxies=proxies)
        assert text is None or isinstance(text, str)
        if text is not None:
            assert "@" not in text, (proxies, text)


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
    old = logger.level
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old)


def test_a_failure_to_build_the_warning_logs_one_debug_line_and_no_value(
    no_ambient_proxy: pytest.MonkeyPatch,
) -> None:
    def _broken() -> dict[str, object]:
        return {"https": object(), "http": _PROXY}

    # The module reads urllib.request.getproxies at call time, so this is the reader it calls.
    no_ambient_proxy.setattr(urllib.request, "getproxies", _broken)
    logger = logging.getLogger("tests.ambient_proxy.broken")
    with _kept(logger) as records:
        logger.setLevel(logging.DEBUG)
        warn_ambient_proxy(logger)
    assert [r.levelno for r in records] == [logging.DEBUG], records
    message = records[0].getMessage()
    assert "proxy.example" not in message and _SECRET not in message and not records[0].args


def _serve_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str = "serve"
) -> list[str]:
    """Run ``serve`` to the point it hands uvicorn the app, and return the ambient-proxy warnings
    as an operator reads them. Read at the end, because serve's own handlers redact the record."""
    from tests.test_header_floor_wire import _serve_captured

    logger = logging.getLogger("messagefoundry.__main__")
    handler = _Keep()
    logger.addHandler(handler)
    try:
        rc, _, _ = _serve_captured(tmp_path, monkeypatch, command=command)
    finally:
        logger.removeHandler(handler)
    assert rc == 0
    return [
        r.getMessage()
        for r in handler.records
        if r.levelno == logging.WARNING and "web proxy from the environment" in r.getMessage()
    ]


def test_serve_discloses_an_environment_proxy_once(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    no_ambient_proxy.setenv("HTTPS_PROXY", _PROXY)
    warnings = _serve_warnings(tmp_path, no_ambient_proxy)
    assert len(warnings) == 1, warnings
    assert "The https proxy is http://proxy.example:3128. " in warnings[0], warnings
    _assert_claims_nothing(warnings[0])


def test_serve_without_an_environment_proxy_warns_of_none(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    assert _serve_warnings(tmp_path, no_ambient_proxy) == []


def test_serve_with_no_proxy_star_warns_of_none(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    no_ambient_proxy.setenv("HTTPS_PROXY", _P)
    no_ambient_proxy.setenv("NO_PROXY", "*")
    assert _serve_warnings(tmp_path, no_ambient_proxy) == []


def test_supervise_discloses_an_environment_proxy_once_before_spawning(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    """The supervisor's own store open and pair renewal can read the proxy, so it names it too."""

    async def _no_fleet(*args: object, **kwargs: object) -> int:
        return 0

    no_ambient_proxy.setattr("messagefoundry.pipeline.supervisor.supervise", _no_fleet)
    no_ambient_proxy.setenv("HTTPS_PROXY", _PROXY)
    warnings = _serve_warnings(tmp_path, no_ambient_proxy, command="supervise")
    assert len(warnings) == 1, warnings
    assert "The https proxy is http://proxy.example:3128. " in warnings[0], warnings
    _assert_claims_nothing(warnings[0])
