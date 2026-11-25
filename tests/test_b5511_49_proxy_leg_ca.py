# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ``http://`` url behind an ``https://`` forward proxy reads its ``tls_ca_file`` on the proxy
leg, so that CA takes the anchor checks and its pin is honoured (vault BACKLOG #5511 item 49).

urllib's ``Request.set_proxy`` turns an ``http`` request sent to an ``https://`` proxy into an
``https`` one, and the opener's https handler, built from the trust anchor, dials the proxy. Before
this, the unread-CA rule read every ``http://`` url as a hop with no TLS: the CA was never put
through ``evaluate_anchor``, and a ``tls_ca_pin`` beside it was refused in text saying the hop never
reads the file.

The controls keep the rule where no such leg exists: no proxy, an ``http://`` proxy, a host
``proxy_no_proxy`` or urllib's bypass list names, a loopback host, and a proxy setting not yet
resolved, which leaves the decision to the check after resolution.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.trust_anchors import AUDIT_ACTION, TrustAnchorError
from messagefoundry.config import wiring
from messagefoundry.config.wiring import EnvRef, Registry, WiringError, load_config
from messagefoundry.store import MessageStore
from messagefoundry.transports import rest
from tests.test_trust_anchors import _block, _path_ok

_URL = "http://partner.example.org/api"
_TLS_PROXY = "https://proxy.example.org:3128"
_CLEAR_PROXY = "http://proxy.example.org:3128"
_UNREAD_TEXT = "the check finds no hop that reads its tls_ca_file"
_PIN_MISMATCH = "does not match its configured SHA-256 pin"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _no_ambient_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """No proxy from the environment or the system, and no urllib bypass, so each test sets the
    route it is about. A fresh registry, since a graph module registers into the active one."""
    monkeypatch.setattr(urllib.request, "getproxies", dict)
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _host: False)
    monkeypatch.setattr(wiring, "_active", Registry())


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only what it is about."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


def _ca(tmp_path: Path, body: bytes = b"proxy-ca") -> Path:
    p = tmp_path / "proxy-ca.pem"
    p.write_bytes(_block(body))
    return p


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _settings(ca: Path, *, proxy: object = _TLS_PROXY, pin: str | None = None) -> dict[str, Any]:
    s: dict[str, Any] = {"url": _URL, "tls_ca_file": str(ca), "proxy_url": proxy}
    if pin is not None:
        s["tls_ca_pin"] = pin
    return s


def _graph(cfg: Path, rest_kw: str) -> Path:
    cfg.mkdir()
    (cfg.parent / "in").mkdir(exist_ok=True)
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, Rest, Send, handler, inbound, outbound, router\n"
        f"inbound('IB_IN', File(directory={str(cfg.parent / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        f"outbound('OUT', Rest(url={_URL!r}{rest_kw}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OUT', msg)\n",
        encoding="utf-8",
    )
    return cfg


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    return [d for r in rows if (d := json.loads(r["detail"])).get("label") == "outbound:OUT"]


# --- the route -----------------------------------------------------------------------------------


def test_the_route_reads_the_proxy_as_the_opener_does(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a request that goes to an ``https://`` proxy meets a TLS leg."""
    base = {"url": _URL}
    assert rest.http_url_reaches_a_tls_proxy({**base, "proxy_url": _TLS_PROXY}) is True
    assert (
        rest.http_url_reaches_a_tls_proxy({**base, "proxy_url": " HTTPS://p.example.org "}) is True
    )
    assert rest.http_url_reaches_a_tls_proxy({**base, "proxy_url": _CLEAR_PROXY}) is False
    assert rest.http_url_reaches_a_tls_proxy(base) is False
    assert rest.http_url_reaches_a_tls_proxy({**base, "proxy_url": "default"}) is False
    bypassed = {**base, "proxy_url": _TLS_PROXY, "proxy_no_proxy": ["partner.example.org"]}
    assert rest.http_url_reaches_a_tls_proxy(bypassed) is False
    loopback = {"url": "http://127.0.0.1:8080/api", "proxy_url": _TLS_PROXY}
    assert rest.http_url_reaches_a_tls_proxy(loopback) is False
    ech = {**base, "proxy_url": _TLS_PROXY, "ech_egress": True}
    assert rest.http_url_reaches_a_tls_proxy(ech) is False
    # The opener's default proxy, from the environment or the system, is read as it reads it.
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"http": _TLS_PROXY})
    assert rest.http_url_reaches_a_tls_proxy(base) is True
    assert rest.http_url_reaches_a_tls_proxy({**base, "proxy_url": "default"}) is True
    assert rest.http_url_reaches_a_tls_proxy(bypassed) is True  # skips this proxy, not the default
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda _host: True)
    assert rest.http_url_reaches_a_tls_proxy({**base, "proxy_url": _TLS_PROXY}) is False
    assert rest.http_url_reaches_a_tls_proxy(base) is False
    assert rest.http_url_reaches_a_tls_proxy(bypassed) is False  # urllib's list, on the default


def test_a_proxy_setting_not_yet_resolved_is_unknown() -> None:
    """The load passes an ``env()`` proxy, and the check after resolution decides."""
    unresolved = {"url": _URL, "proxy_url": EnvRef("proxy")}
    assert rest.http_url_reaches_a_tls_proxy(unresolved) is None
    assert ta.unread_ca_reason({**unresolved, "tls_ca_file": "ca.pem"}) is None
    no_proxy = {"url": _URL, "proxy_url": _TLS_PROXY, "proxy_no_proxy": EnvRef("hosts")}
    assert rest.http_url_reaches_a_tls_proxy(no_proxy) is None


# --- the load ------------------------------------------------------------------------------------


def test_an_https_proxy_leg_honours_the_pin_at_load(tmp_path: Path) -> None:
    """Red before this change: the load refused the pin, saying the hop never reads the CA. Now
    the CA is collected with its pin, so the anchor checks run on it."""
    ca = _ca(tmp_path)
    cfg = _graph(
        tmp_path / "cfg",
        f", tls_ca_file={str(ca)!r}, tls_ca_pin={_sha(ca)!r}, proxy={_TLS_PROXY!r}",
    )
    (spec,) = ta.registry_anchor_specs(load_config(cfg), {})
    assert (spec.label, spec.path, spec.pin) == ("outbound:OUT", str(ca), _sha(ca))


@pytest.mark.parametrize(
    "proxy_kw",
    [
        "",
        f", proxy={_CLEAR_PROXY!r}",
        f", proxy={_TLS_PROXY!r}, proxy_no_proxy=['partner.example.org']",
    ],
    ids=["no-proxy", "http-proxy", "bypassed"],
)
def test_without_a_tls_proxy_leg_the_pin_is_still_refused(tmp_path: Path, proxy_kw: str) -> None:
    """The negative control: no proxy, an ``http://`` proxy and a bypassed host keep the CA unread,
    so it is not collected and its pin is refused, in text that names what the check found."""
    gone = str(tmp_path / "gone.pem")
    bare = _graph(tmp_path / "bare", f", tls_ca_file={gone!r}{proxy_kw}")
    assert ta.registry_anchor_specs(load_config(bare), {}) == []
    wiring._active = Registry()
    pinned = _graph(
        tmp_path / "pinned", f", tls_ca_file={gone!r}, tls_ca_pin={'ab' * 32!r}{proxy_kw}"
    )
    with pytest.raises(WiringError, match=_UNREAD_TEXT) as err:
        load_config(pinned)
    assert "https:// forward proxy" in str(err.value)


# --- the lane check, on resolved settings --------------------------------------------------------


async def test_the_lane_check_runs_the_pin_on_the_proxy_leg_ca(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A wrong pin refuses, the right one passes, as on an https url."""
    ca = _ca(tmp_path)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH):
        await check("outbound", "OUT", _settings(ca, pin="00" * 32))
    await check("outbound", "OUT", _settings(ca, pin=_sha(ca)))
    assert "pin_mismatch" in {r["event"] for r in await _rows(store)}


async def test_the_lane_check_runs_the_acl_check_on_the_proxy_leg_ca(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A proxy-leg CA another account can write refuses at enforce."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(TrustAnchorError, match="is writable by a non-owner"):
        await check("outbound", "OUT", _settings(_ca(tmp_path)))
    assert "acl_insecure" in {r["event"] for r in await _rows(store)}


async def test_the_lane_check_audits_the_proxy_leg_cas_fingerprint(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The first check writes the baseline, and a swapped file writes ``changed``."""
    ca = _ca(tmp_path)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    await check("outbound", "OUT", _settings(ca))
    before = _sha(ca)
    ca.write_bytes(_block(b"another-proxy-ca"))
    await check("outbound", "OUT", _settings(ca))
    rows = await _rows(store)
    assert [r["event"] for r in rows] == ["changed", "observed"]
    assert rows[0]["previous"] == before and rows[0]["fingerprint"] == _sha(ca)


@pytest.mark.parametrize("proxy", [None, _CLEAR_PROXY], ids=["no-proxy", "http-proxy"])
async def test_the_lane_check_refuses_a_pin_with_no_tls_proxy_leg(
    store: MessageStore, tmp_path: Path, judged: None, proxy: str | None
) -> None:
    """After resolution, a proxy inherited from ``[egress].proxy_url`` is merged in, so the same
    rule decides there. With no TLS leg the pin is refused, unread, before any row is written."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(ta.AnchorSettingRefused, match=_UNREAD_TEXT):
        await check("outbound", "OUT", _settings(_ca(tmp_path), proxy=proxy, pin="ab" * 32))
    assert await _rows(store) == []
