# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The outbound ``tls_ca_file`` gets the inbound CA's integrity checks (vault BACKLOG #2371).

Before this, an outbound connection's ``tls_ca_file`` had no SHA-256 pin, no ACL or path preflight
and no change audit. Whoever could replace the file would choose which CA the hop trusts. The graph
preflight now checks it at load and at every reload, as it checks an inbound CA. Each test goes
through a public factory, at least one HTTP-family factory and ``Ftp``, then through the same
preflight ``serve`` hands the engine.

One difference from the inbound CA is deliberate. These hops still build their context from the
path, so a matching pin is not the escape for a CA whose permissions could not be read.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import textwrap
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.trust_anchors import AUDIT_ACTION, TrustAnchorError
from messagefoundry.config import wiring
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    FHIR,
    DICOMweb,
    Direct,
    Email,
    FhirLookup,
    Ftp,
    Registry,
    Rest,
    Soap,
    WiringError,
    env,
    load_config,
)
from messagefoundry.store import MessageStore
from tests.test_trust_anchors import _block, _path_ok

_GRAPH_TAIL = (
    "@router('r')\n"
    "def route(msg):\n"
    "    return ['h']\n"
    "@handler('h')\n"
    "def handle(msg):\n"
    "    return Send('OUT', msg)\n"
)

#: One HTTP-family factory and Ftp, as the row asks, spelled as a graph module writes them.
_DESTINATIONS: dict[str, str] = {
    "rest": "Rest(url='https://partner.example.org/api'{kw})",
    "ftp": "Ftp(host='ftp.internal.example.org', tls=True, remote_dir='/in'{kw})",
}


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    # FhirLookup self-registers into the active registry; give every test its own.
    monkeypatch.setattr(wiring, "_active", Registry())


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only what it is about. The real
    answers depend on the host's temp directory, not on the test."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


def _ca(tmp_path: Path, body: bytes = b"partner-ca", name: str = "partner-ca.pem") -> Path:
    p = tmp_path / name
    p.write_bytes(_block(body))
    return p


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _graph(cfg: Path, dest: str, *, deployed: bool = True) -> None:
    cfg.mkdir()
    (cfg.parent / "in").mkdir(exist_ok=True)
    tail = "" if deployed else ", deployed=False"
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, Ftp, Rest, Send, env, handler, inbound, outbound\n"
        "from messagefoundry import router\n"
        f"inbound('IB_IN', File(directory={str(cfg.parent / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        f"outbound('OUT', {dest}{tail})\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )


def _dest(kind: str, ca: Path | str, pin: str | None = None) -> str:
    kw = f", tls_ca_file={str(ca)!r}"
    if pin is not None:
        kw += f", tls_ca_pin={pin!r}"
    return _DESTINATIONS[kind].format(kw=kw)


async def _rows(store: MessageStore, label: str) -> list[dict[str, Any]]:
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    out = [json.loads(r["detail"]) for r in rows]
    return [d for d in out if d.get("label") == label]


async def _preflight(store: MessageStore, cfg: Path, *, enforcing: bool = True) -> None:
    await ta.make_registry_anchor_preflight(store, enforcing=enforcing)(load_config(cfg), {})


# --- the spec ------------------------------------------------------------------------------------


def test_the_outbound_spec_names_the_connection_and_reads_by_path(tmp_path: Path) -> None:
    """The label is prefixed, so an outbound named ``ad`` cannot share the AD anchor's baseline.
    ``loads_verified_bytes`` is False: the hop reads ``cafile=`` after the preflight."""
    ca = str(tmp_path / "ca.pem")
    spec = ta.outbound_anchor_spec("OUT", {"tls_ca_file": ca, "tls_ca_pin": "ab" * 32})
    assert spec == ta.AnchorSpec(
        "outbound:OUT",
        "outbound connection 'OUT' tls_ca_file",
        ca,
        "ab" * 32,
        "outbound connection 'OUT' tls_ca_pin",
        loads_verified_bytes=False,
    )
    assert ta.outbound_anchor_spec("ad", {"tls_ca_file": ca}).label == "outbound:ad"  # type: ignore[union-attr]
    assert ta.outbound_anchor_spec("x", {"tls": True, "tls_ca_file": ca}) is not None
    assert ta.outbound_anchor_spec("x", {"tls": False, "tls_ca_file": ca}) is None  # no TLS
    assert ta.outbound_anchor_spec("x", {"tls_ca_file": ""}) is None
    assert ta.outbound_anchor_spec("x", {}) is None
    with pytest.raises(ValueError, match="outbound connection 'x' tls_ca_pin is set but empty"):
        ta.outbound_anchor_spec("x", {"tls_ca_file": ca, "tls_ca_pin": " "})


def test_the_registry_collects_outbound_and_lookup_cas(tmp_path: Path) -> None:
    """A deployed outbound and a FhirLookup with a CA are collected, next to an inbound CA. One with
    no CA, and one not deployed, are not. An env() CA resolves first."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (tmp_path / "in").mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import FhirLookup, File, Ftp, Rest, Send, env, handler, inbound\n"
        "from messagefoundry import outbound, router\n"
        f"CA = {str(ca)!r}\n"
        f"inbound('IB_IN', File(directory={str(tmp_path / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        "outbound('OUT', Rest(url='https://partner.example.org/api', tls_ca_file=CA, "
        "tls_ca_pin='00' * 32))\n"
        "outbound('OB_FTPS', Ftp(host='ftp.example.org', tls=True, remote_dir='/in', "
        "tls_ca_file=env('ftps_ca')))\n"
        "outbound('OB_PLAIN', Rest(url='https://partner.example.org/api'))\n"
        "outbound('OB_PARKED', Rest(url='https://partner.example.org/api', tls_ca_file=CA), "
        "deployed=False)\n"
        "FhirLookup('EPIC', url='https://fhir.example.org/fhir', tls_ca_file=CA)\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )
    specs = ta.registry_anchor_specs(load_config(cfg), {"ftps_ca": str(ca)})
    assert {s.label: (s.setting, s.pin) for s in specs} == {
        "outbound:OUT": ("outbound connection 'OUT' tls_ca_file", "00" * 32),
        "outbound:OB_FTPS": ("outbound connection 'OB_FTPS' tls_ca_file", None),
        "fhir_lookup:EPIC": ("fhir lookup 'EPIC' tls_ca_file", None),
    }
    assert all(s.path == str(ca) and not s.loads_verified_bytes for s in specs)


# --- the pin -------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(_DESTINATIONS))
async def test_a_pin_mismatch_refuses_the_load(
    store: MessageStore, tmp_path: Path, judged: None, kind: str
) -> None:
    """The pin is optional, and a set pin that does not match refuses at every dial. The refusal
    names the outbound connection and quotes the path. The control: the right pin loads."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest(kind, ca, pin="00" * 32))
    for enforcing in (True, False):
        with pytest.raises(WiringError, match="a connection trust anchor was refused") as err:
            await _preflight(store, cfg, enforcing=enforcing)
        assert isinstance(err.value.__cause__, TrustAnchorError)
        text = str(err.value)
        assert f"outbound connection 'OUT' tls_ca_file: the trust anchor {str(ca)!r}" in text
        assert "does not match its configured SHA-256 pin" in text
    assert "pin_mismatch" in {r["event"] for r in await _rows(store, "outbound:OUT")}

    good = tmp_path / "good"
    _graph(good, _dest(kind, ca, pin=_sha(ca)))
    await _preflight(store, good)


@pytest.mark.parametrize("kind", sorted(_DESTINATIONS))
async def test_an_unset_pin_keeps_the_load(
    store: MessageStore, tmp_path: Path, judged: None, kind: str
) -> None:
    """No pin, an owner-only CA: the load goes ahead as before, and writes only the baseline row."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest(kind, ca))
    await _preflight(store, cfg)
    rows = await _rows(store, "outbound:OUT")
    assert [r["event"] for r in rows] == ["observed"]
    assert rows[0]["fingerprint"] == _sha(ca)


# --- the ACL and path preflight -------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(_DESTINATIONS))
async def test_a_writable_outbound_ca_refuses_at_enforce_and_warns_at_warn(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """A CA another account can write lets that account choose which CA the hop trusts."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest(kind, ca))
    with pytest.raises(WiringError, match="is writable by a non-owner") as err:
        await _preflight(store, cfg, enforcing=True)
    assert "outbound connection 'OUT' tls_ca_file" in str(err.value)
    await _preflight(store, cfg, enforcing=False)
    events = [r for r in await _rows(store, "outbound:OUT") if r["event"] == "acl_insecure"]
    assert [r["enforcing"] for r in events] == [False, True]  # most recent first


@pytest.mark.parametrize("kind", sorted(_DESTINATIONS))
async def test_a_matching_pin_is_not_the_escape_for_an_unjudged_outbound_ca(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """The hop reads the file again by path, so a pin cannot vouch for the bytes it loads. An
    unjudged CA refuses at enforce even with a matching pin, and the refusal says so. The control:
    an inbound CA's matching pin lets the same file load."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest(kind, ca, pin=_sha(ca)))
    with pytest.raises(WiringError, match="A pin does not help here"):
        await _preflight(store, cfg, enforcing=True)
    (row,) = [r for r in await _rows(store, "outbound:OUT") if r["event"] == "acl_indeterminate"]
    assert row["pinned"] is True

    inbound = ta.connection_anchor_spec(
        "IB", {"tls": True, "tls_ca_file": str(ca), "tls_ca_pin": _sha(ca)}
    )
    assert inbound is not None
    await ta.run_anchor_preflight([inbound], store, enforcing=True)


async def test_the_outbound_preflight_does_not_refuse_what_cafile_loads(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The PEM shape checks model ``cadata=``, and this hop loads ``cafile=``, which reads a
    ``TRUSTED CERTIFICATE`` block. Refusing one here would refuse what the build accepts."""
    ca = tmp_path / "trusted.pem"
    ca.write_bytes(
        b"-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n-----END TRUSTED CERTIFICATE-----\n"
    )
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest("rest", ca))
    await _preflight(store, cfg)
    assert "pem_refused" not in {r["event"] for r in await _rows(store, "outbound:OUT")}


# --- the change audit ----------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(_DESTINATIONS))
async def test_a_changed_outbound_ca_is_audited(
    store: MessageStore, tmp_path: Path, judged: None, kind: str
) -> None:
    """The first load writes the baseline; a swapped file writes ``changed`` with both digests."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest(kind, ca))
    await _preflight(store, cfg)
    before = _sha(ca)
    ca.write_bytes(_block(b"another-ca"))
    await _preflight(store, cfg)
    rows = await _rows(store, "outbound:OUT")
    assert [r["event"] for r in rows] == ["changed", "observed"]
    assert rows[0]["previous"] == before and rows[0]["fingerprint"] == _sha(ca)


async def test_an_undeployed_outbound_is_not_checked(store: MessageStore, tmp_path: Path) -> None:
    """ADR 0111: a not-deployed connection is never built, so its CA is never read or audited."""
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest("rest", tmp_path / "gone.pem"), deployed=False)
    await _preflight(store, cfg)
    assert await _rows(store, "outbound:OUT") == []


async def test_an_engine_reload_refuses_a_substituted_outbound_ca(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The reload twin: the engine runs the same preflight, so a substituted outbound CA refuses
    the reload and nothing goes live."""
    from messagefoundry.pipeline import Engine

    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest("rest", ca, pin=_sha(ca)))
    ca.write_bytes(_block(b"substitute"))
    engine = Engine(
        store,
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        with pytest.raises(WiringError, match="outbound connection 'OUT' tls_ca_file"):
            await engine.reload_detail(cfg)
        assert engine.registry_runner is None
    finally:
        await engine.stop()


# --- the factories -------------------------------------------------------------------------------

_LOOKUP_NAMES = itertools.count()

_FACTORIES: dict[str, Callable[..., Any]] = {
    "Rest": lambda **kw: Rest(url="https://partner.example.org/api", **kw),
    "FHIR": lambda **kw: FHIR(url="https://fhir.example.org/fhir", **kw),
    "Soap": lambda **kw: Soap(url="https://partner.example.org/svc", soap_action="Send", **kw),
    "DICOMweb": lambda **kw: DICOMweb(url="https://pacs.example.org/dicom-web", **kw),
    "Ftp": lambda **kw: Ftp(host="ftp.example.org", tls=True, remote_dir="/in", **kw),
    # A fresh name per call: a lookup self-registers, and one test makes three.
    "FhirLookup": lambda **kw: FhirLookup(
        f"L{next(_LOOKUP_NAMES)}", url="https://fhir.example.org/fhir", **kw
    ),
    "Email": lambda **kw: Email(
        host="smtp.example.org", sender="a@example.org", recipients=["b@example.org"], **kw
    ),
    "Direct": lambda **kw: Direct(
        host="hisp.example.org",
        sender="a@direct.example.org",
        recipients=["b@direct.example.org"],
        signing_cert="s.pem",
        signing_key="k.pem",
        recipient_cert="r.pem",
        trust_anchor="t.pem",
        **kw,
    ),
}


@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_every_factory_that_takes_the_ca_takes_the_pin(factory: str) -> None:
    """Wherever ``tls_ca_file`` is accepted, ``tls_ca_pin`` is too, as a literal or an env()."""
    pin = "ab" * 32
    made = _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin=pin)
    assert made.settings["tls_ca_pin"] == pin
    ref = _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin=env("ca_pin"))
    assert ref.settings["tls_ca_pin"] == env("ca_pin")
    assert _FACTORIES[factory]().settings["tls_ca_pin"] is None


@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_a_pin_with_no_ca_or_a_blank_pin_is_refused(factory: str) -> None:
    """A pin nothing checks would read as pinned while nothing is."""
    errors = (ValueError, WiringError)
    with pytest.raises(errors, match=f"{factory} tls_ca_pin is set without a tls_ca_file"):
        _FACTORIES[factory](tls_ca_pin="ab" * 32)
    with pytest.raises(errors, match=f"{factory} tls_ca_pin is set but empty"):
        _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin="  ")


def test_the_pin_loads_from_connections_toml(tmp_path: Path) -> None:
    """``connections.toml`` inherits the key, because the factory is its schema."""
    (tmp_path / "logic.py").write_text("", encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            f"""
            [[outbound]]
            name = "OB_REST"
            transport = "rest"
              [outbound.settings]
              url = "https://partner.example.org/api"
              tls_ca_file = "/org/partner-ca.pem"
              tls_ca_pin = "{"ab" * 32}"
            """
        ),
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert reg.outbound["OB_REST"].spec.settings["tls_ca_pin"] == "ab" * 32


def test_an_mllp_and_a_dicom_destination_build_with_a_pin(tmp_path: Path) -> None:
    """Their builders refused any outbound pin before vault BACKLOG #2371. A pin beside tls and a
    tls_ca_file now builds; the graph preflight is what checks it."""
    from messagefoundry.transports.dicom import _client_ssl_context
    from messagefoundry.transports.mllp import _mllp_ssl_context

    ca = _ca(tmp_path)
    pinned = {"tls": True, "host": "partner.example.org", "tls_ca_file": str(ca)}
    pinned["tls_ca_pin"] = _sha(ca)
    assert _mllp_ssl_context(dict(pinned), server=False) is not None
    assert _client_ssl_context(dict(pinned)) is not None
