# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An environment web proxy is disclosed at start, never silent (BACKLOG #1125, ASVS 4.2.1).

Owner ruling 2026-10-11: an ambient proxy must not attach silently, or must be disclosed. The
engine's urllib openers follow ``HTTP_PROXY``, ``HTTPS_PROXY`` and the system proxy, and its Vault
clients follow those and ``ALL_PROXY``. So ``serve`` and ``supervise`` name each proxy, and the
hops that use it or refuse it, in one WARNING per process.

The warning discloses and does not reason about what the leg to the proxy protects; that is in
``docs/CONFIGURATION.md``. So the hop table below is the expected disclosure for each proxy set,
and no warning may use a word that claims or denies protection. Both polarities are tested: with a
proxy in the environment the warning names its host and no credential; with none, nothing logs.
"""

from __future__ import annotations

import contextlib
import logging
import os
import socket
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from requests.utils import select_proxy

from messagefoundry.transports.ambient_proxy import ambient_proxy_warning, environment_proxy_hosts

_SECRET = "s3cretpw"
_PROXY = f"http://alice:{_SECRET}@proxy.example:3128"
_P = "http://proxy.example:3128"
_Q = "http://other.example:8080"
_URLLIB = "the urllib hops"
_VAULT = "the Vault and OpenBao clients"
#: Words that would make the warning reason about protection rather than disclose (SDS-3.5).
_NO_SAFETY_WORDS = ("tls", "encrypt", "secure", "safe", "protected")


@pytest.fixture(autouse=True)
def no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Clear every proxy source ``urllib.request.getproxies()`` reads, so the box's own settings
    cannot decide a test. The system readers are stubbed on the platforms that have them, and so
    are the system bypass readers, which the probe's handlers consult through ``proxy_bypass``."""
    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("REQUEST_METHOD", raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    for reader in ("proxy_bypass_registry", "proxy_bypass_macosx_sysconf"):
        monkeypatch.setattr(urllib.request, reader, lambda host: False, raising=False)
    assert urllib.request.getproxies() == {}, "a proxy source survived the fixture"
    return monkeypatch


def _line(key: str, address: str, *clauses: str) -> str:
    return f"The {key} proxy is {address}: " + "; ".join(clauses) + "."


@pytest.mark.parametrize(
    ("proxies", "lines"),
    [
        pytest.param(
            {"https": _P},
            [
                _line(
                    "https",
                    _P,
                    f"{_URLLIB} use it for https targets",
                    f"{_VAULT} use it for an https:// Vault",
                )
            ],
            id="https",
        ),
        pytest.param(
            {"http": _P},
            [
                _line(
                    "http",
                    _P,
                    f"{_URLLIB} use it for http targets",
                    f"{_VAULT} refuse it for an http:// Vault",
                )
            ],
            id="http",
        ),
        pytest.param(
            {"all": _P},
            [
                _line(
                    "all",
                    _P,
                    f"{_VAULT} use it for an https:// Vault and refuse it for an http:// Vault",
                )
            ],
            id="all",
        ),
        pytest.param(
            {"http": _P, "all": _Q},
            [
                _line("all", _Q, f"{_VAULT} use it for an https:// Vault"),
                _line(
                    "http",
                    _P,
                    f"{_URLLIB} use it for http targets",
                    f"{_VAULT} refuse it for an http:// Vault",
                ),
            ],
            id="http-and-all",
        ),
        pytest.param(
            {"https": _P, "all": _Q},
            [
                _line("all", _Q, f"{_VAULT} refuse it for an http:// Vault"),
                _line(
                    "https",
                    _P,
                    f"{_URLLIB} use it for https targets",
                    f"{_VAULT} use it for an https:// Vault",
                ),
            ],
            id="https-and-all",
        ),
        pytest.param(
            {"all": _PROXY},
            [_line("all", _P, f"{_VAULT} refuse it for an http:// or https:// Vault")],
            id="all-with-credentials",
        ),
        pytest.param(
            {"https": _PROXY},
            [
                _line(
                    "https",
                    _P,
                    f"{_URLLIB} refuse it for https targets",
                    f"{_VAULT} refuse it for an https:// Vault",
                )
            ],
            id="https-with-credentials-over-http",
        ),
        pytest.param(
            {"http": _P, "https": _Q},
            [
                _line(
                    "http",
                    _P,
                    f"{_URLLIB} use it for http targets",
                    f"{_VAULT} refuse it for an http:// Vault",
                ),
                _line(
                    "https",
                    _Q,
                    f"{_URLLIB} use it for https targets",
                    f"{_VAULT} use it for an https:// Vault",
                ),
            ],
            id="two-hosts",
        ),
        pytest.param(
            # urllib re-sends an http target whose proxy is written https:// through the https
            # entry, so that entry carries http targets too.
            {"http": "https://proxy.example:443", "https": _Q},
            [
                _line(
                    "http",
                    "https://proxy.example:443",
                    f"{_URLLIB} use it for http targets",
                    f"{_VAULT} refuse it for an http:// Vault",
                ),
                _line(
                    "https",
                    _Q,
                    f"{_URLLIB} use it for http and https targets",
                    f"{_VAULT} use it for an https:// Vault",
                ),
            ],
            id="two-hosts-http-entry-written-https",
        ),
    ],
)
def test_the_warning_lists_the_hops_the_code_would_send_through_each_proxy(
    proxies: dict[str, str], lines: list[str]
) -> None:
    text = ambient_proxy_warning(proxies=proxies)
    assert text is not None
    for line in lines:
        assert line in text, (line, text)
    assert text.count(" proxy is ") == len(lines), text
    assert ("The urllib hops include" in text) == any(_URLLIB in line for line in lines)
    assert _SECRET not in text and "alice" not in text and "@" not in text
    for word in _NO_SAFETY_WORDS:
        assert word not in text.lower(), word


@pytest.mark.parametrize("vault", ["https://vault.example:8200", "http://vault.example:8200"])
@pytest.mark.parametrize(
    "proxies", [{"https": _P}, {"http": _P}, {"all": _P}, {"http": _P, "all": _Q}]
)
def test_the_vault_clients_are_named_for_the_entry_requests_selects(
    proxies: dict[str, str], vault: str
) -> None:
    """The control for the table: requests' own selection names the same entry the warning does."""
    scheme = vault.split(":", 1)[0]
    text = ambient_proxy_warning(proxies=proxies)
    assert text is not None
    # requests' selection run on a map of each key to itself returns the key it would pick.
    key = select_proxy(vault, {k: k for k in proxies})
    naming = [s for s in text.split(". ") if f"{scheme}:// " in s and "Vault" in s]
    assert [s.split(" proxy is ")[0] for s in naming] == ([f"The {key}"] if key else []), text


def test_without_the_vault_extra_the_vault_clients_are_not_named(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Vault clients cannot run without hvac, so no proxy reaches them."""
    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name, *a: None if name == "hvac" else real(name, *a)
    )
    # Nothing reads an all-only proxy then, so it attaches to nothing and is not disclosed.
    assert ambient_proxy_warning(proxies={"all": _P}) is None
    text = ambient_proxy_warning(proxies={"all": _Q, "https": _P})
    assert text is not None and "Vault" not in text
    assert _line("all", _Q, "no engine hop reads it") in text
    assert _line("https", _P, f"{_URLLIB} use it for https targets") in text


def test_a_refusal_is_pinned_on_the_entry_that_refused() -> None:
    """An http target passes the clean http entry, then fails on the https entry's credentials.
    Only the https entry is said to be refused."""
    text = ambient_proxy_warning(
        proxies={"http": "https://proxy.example:443", "https": "http://u:pw@other.example:3128"}
    )
    assert text is not None
    assert "The http proxy is https://proxy.example:443: the Vault" in text, text
    assert f"{_URLLIB} refuse it for http and https targets" in text, text


@pytest.mark.parametrize(
    ("proxies", "line"),
    [
        pytest.param(
            {"http": "socks5h://socks.example:1080"},
            _line(
                "http",
                "socks5h://socks.example:1080",
                f"{_URLLIB} refuse it for http targets",
                f"{_VAULT} refuse it for an http:// Vault",
            ),
            id="a-scheme-urllib-cannot-open",
        ),
        pytest.param(
            # urllib re-types the request between the two entries until the stack runs out, in the
            # engine's own opener as in the probe. The warning must still log, not stop serve, and
            # both entries in the loop are said to be refused.
            {"http": "all://proxy.example:1", "all": _Q},
            _line(
                "http",
                "all://proxy.example:1",
                f"{_URLLIB} refuse it for http targets",
                f"{_VAULT} refuse it for an http:// Vault",
            ),
            id="a-proxy-that-loops",
        ),
    ],
)
def test_a_proxy_a_real_send_would_fail_on_is_refused_not_used(
    proxies: dict[str, str], line: str
) -> None:
    text = ambient_proxy_warning(proxies=proxies)
    assert text is not None and line in text, text
    if "all" in proxies:
        assert f"The all proxy is {_Q}: {_URLLIB} refuse it for http targets;" in text, text


def test_the_probe_dials_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hops are found by running the real handlers, which must stop before any socket."""

    def _refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the probe opened a socket")

    monkeypatch.setattr(socket, "create_connection", _refuse)
    monkeypatch.setattr(socket.socket, "connect", _refuse)
    proxies = {"http": "https://proxy.example:443", "https": _Q, "all": _PROXY}
    assert ambient_proxy_warning(proxies=proxies) is not None


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
    ],
)
def test_an_unreadable_proxy_value_is_not_echoed(value: str) -> None:
    assert environment_proxy_hosts({"http": value}) == {"http": "an unreadable value"}
    text = ambient_proxy_warning(proxies={"http": value})
    assert text is not None and "The http proxy is an unreadable value: " in text
    assert _SECRET not in text and "forged" not in text and "pro xy" not in text


def test_an_ipv6_proxy_is_named_with_its_brackets() -> None:
    assert environment_proxy_hosts({"https": "http://u:p@[2001:db8::1]:3128"}) == {
        "https": "http://[2001:db8::1]:3128"
    }


def test_no_proxy_means_no_warning() -> None:
    assert ambient_proxy_warning(proxies={}) is None
    assert ambient_proxy_warning(proxies={"no": "localhost"}) is None
    assert ambient_proxy_warning(proxies={"ftp": _P, "https": "  "}) is None


def test_a_no_proxy_of_star_means_no_warning() -> None:
    """``NO_PROXY=*`` sends every hop direct in urllib and in requests, so nothing is disclosed."""
    assert ambient_proxy_warning(proxies={"https": _P, "no": "*"}) is None
    assert ambient_proxy_warning(proxies={"https": _P, "no": "intranet.example"}) is not None
    # urllib compares the raw value, so a padded star bypasses nothing and must still warn.
    assert ambient_proxy_warning(proxies={"https": _P, "no": " *"}) is not None


def test_the_proxy_scheme_is_named_as_the_libraries_read_it() -> None:
    """The scheme is named as written, and a value with none as ``http``, which both read it as."""
    assert environment_proxy_hosts({"https": "https://proxy.example:443"}) == {
        "https": "https://proxy.example:443"
    }
    assert environment_proxy_hosts({"https": "proxy.example:3128"}) == {
        "https": "http://proxy.example:3128"
    }


def test_the_warning_points_at_one_doc_section_and_gives_the_remedy() -> None:
    """``[egress].proxy_url`` changes only the HTTP family, and the warning reads no settings."""
    for proxies in ({"https": _P}, {"all": _P}):
        text = ambient_proxy_warning(proxies=proxies)
        assert text is not None
        assert '[egress], "serve names an environment proxy at start"' in text
        assert "To stop it, clear http_proxy, https_proxy and all_proxy" in text
        assert "[egress].proxy_url to an address changes only the HTTP-family connections" in text
        assert "Every other hop keeps this proxy, and this warning still logs" in text
    doc = (Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md").read_text("utf-8")
    assert "#### `serve` names an environment proxy at start" in doc


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
    assert "The https proxy is http://proxy.example:3128: " in warnings[0], warnings
    assert _SECRET not in warnings[0]


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


def test_supervise_discloses_an_environment_proxy_before_spawning(
    tmp_path: Path, no_ambient_proxy: pytest.MonkeyPatch
) -> None:
    """The supervisor's own store open and pair renewal can use the proxy, so it names it too."""

    async def _no_fleet(*args: object, **kwargs: object) -> int:
        return 0

    no_ambient_proxy.setattr("messagefoundry.pipeline.supervisor.supervise", _no_fleet)
    no_ambient_proxy.setenv("HTTPS_PROXY", _PROXY)
    warnings = _serve_warnings(tmp_path, no_ambient_proxy, command="supervise")
    assert len(warnings) == 1, warnings
    assert "The https proxy is http://proxy.example:3128: " in warnings[0], warnings
