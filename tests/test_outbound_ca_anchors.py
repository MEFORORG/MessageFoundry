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
import ssl
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
    """Every CA in the graph through the shared check and its refusal, lanes included. In
    production the lanes are checked one by one as the runner builds them; this exercises the
    checks themselves."""
    preflight = ta.make_registry_anchor_preflight(store, enforcing=enforcing)
    await preflight(load_config(cfg), {}, lanes=True)


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
    unjudged CA refuses at enforce even with a matching pin, and the refusal says so. Its row says
    ``pinned: False``, since the pin let nothing through (review R6). The control: an inbound CA's
    matching pin lets the same file load, and its row says ``pinned: True``."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest(kind, ca, pin=_sha(ca)))
    with pytest.raises(WiringError, match="A pin does not help here"):
        await _preflight(store, cfg, enforcing=True)
    (row,) = [r for r in await _rows(store, "outbound:OUT") if r["event"] == "acl_indeterminate"]
    assert row["pinned"] is False

    inbound = ta.connection_anchor_spec(
        "IB", {"tls": True, "tls_ca_file": str(ca), "tls_ca_pin": _sha(ca)}
    )
    assert inbound is not None
    await ta.run_anchor_preflight([inbound], store, enforcing=True)
    (row,) = [r for r in await _rows(store, "inbound:IB") if r["event"] == "acl_indeterminate"]
    assert row["pinned"] is True


async def test_the_outbound_preflight_does_not_refuse_what_cafile_loads(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The PEM shape checks model ``cadata=``, and this hop loads ``cafile=``, which reads a
    ``TRUSTED CERTIFICATE`` block. Refusing one here would refuse what the build accepts."""
    ca = tmp_path / "trusted.pem"
    ca.write_bytes(_block(b"trusted").replace(b"CERTIFICATE-----", b"TRUSTED CERTIFICATE-----"))
    # The premise: cafile= loads this file, so the build accepts it.
    assert len(ssl.create_default_context(cafile=str(ca)).get_ca_certs()) == 1
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest("rest", ca))
    await _preflight(store, cfg)
    assert "pem_refused" not in {r["event"] for r in await _rows(store, "outbound:OUT")}


async def test_an_inbound_ftps_pollers_ca_takes_the_checks(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """An inbound Ftp poller dials out and reads its CA by path, as an outbound does. Its pin is
    checked under its inbound name, so a pin there is not one that nothing reads."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, Ftp, Send, handler, inbound, outbound, router\n"
        "inbound('IB_FTPS', Ftp(host='ftp.example.org', tls=True, remote_dir='/out', "
        f"tls_ca_file={str(ca)!r}, tls_ca_pin={'00' * 32!r}), router='r')\n"
        f"outbound('OUT', File(directory={str(tmp_path / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )
    (spec,) = ta.registry_anchor_specs(load_config(cfg), {})
    assert (spec.label, spec.setting) == (
        "inbound:IB_FTPS",
        "inbound connection 'IB_FTPS' tls_ca_file",
    )
    assert not spec.loads_verified_bytes
    with pytest.raises(WiringError, match="does not match its configured SHA-256 pin"):
        await _preflight(store, cfg)


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
    """The reload twin: a running lane is one the reload keeps, so its substituted CA refuses
    the reload and the running graph stays. The first load is the start, so it comes first.
    Review round 3, finding 1: a retried reload is refused again, not let through because the
    first refusal marked the lane failed. Restoring the file lets the reload through."""
    good = _block(b"partner-ca")
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest("rest", ca, pin=_sha(ca)))
    engine = _engine(store)
    try:
        await engine.reload_detail(cfg)
        runner = engine.registry_runner
        assert runner is not None
        running = runner.registry
        ca.write_bytes(_block(b"substitute"))
        for _ in range(2):
            with pytest.raises(WiringError, match="outbound connection 'OUT' tls_ca_file"):
                await engine.reload_detail(cfg)
            assert runner.registry is running
        ca.write_bytes(good)
        await engine.reload_detail(cfg)
        assert not runner.degraded_outbound()
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
    # A blank CA pins nothing, so every factory refuses it, Email and Direct included (review R4).
    with pytest.raises(errors, match=f"{factory} tls_ca_file is blank"):
        _FACTORIES[factory](tls_ca_file=" ")


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


# --- review round 2: where a refusal lands (ADR 0031, as amended 2026-10-06) ----------------------

_PIN_MISMATCH = "does not match its configured SHA-256 pin"
#: How a lane failed by its CA reads in its status. ``safe_exc`` shortens the rest of the reason,
#: so the audit row is what proves it was the pin.
_REFUSED_OUT = "TrustAnchorError: outbound connection 'OUT': its tls_ca_file was refused"
#: The fixed line a refused lane raises; the refusal text itself goes to the server log only.
_LANE_REFUSED = "its tls_ca_file was refused"


def _engine(store: MessageStore) -> Any:
    """An engine with the two checks ``serve`` hands it, and nothing else."""
    from messagefoundry.pipeline import Engine

    return Engine(
        store,
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def _start_like_serve(engine: Any, cfg: Path) -> Any:
    """The managed app's first load: the registry preflight, then the start."""
    reg = load_config(cfg)
    await engine.preflight_registry(reg)
    engine.add_registry(reg)
    await engine.start()
    return engine.registry_runner


def _two_outbound_graph(cfg: Path, out: str) -> None:
    """``OUT`` as given, beside a plain File outbound ``OB_OK`` that must come up regardless."""
    cfg.mkdir()
    for d in ("in", "ok"):
        (cfg.parent / d).mkdir(exist_ok=True)
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, Rest, Send, handler, inbound, outbound, router\n"
        "from messagefoundry.config.models import Priority\n"
        f"inbound('IB_IN', File(directory={str(cfg.parent / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        f"outbound('OUT', {out})\n"
        f"outbound('OB_OK', File(directory={str(cfg.parent / 'ok')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )


async def test_a_refused_outbound_ca_fails_its_lane_and_a_reload_rebuilds_it_only_on_change(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """ADR 0031: the start comes up with ``OUT`` failed and named, ``OB_OK`` and the inbound live,
    and the audit row written. A reload that does not change ``OUT`` leaves it failed and reads no
    CA for it, so it goes through. A reload that changes ``OUT`` rebuilds it, so it checks it and is
    refused. Red under: the start check removed, the registry preflight checking lanes, the reload
    rebuilding an unchanged refused lane, or the reload check skipped."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32))
    engine = _engine(store)
    try:
        runner = await _start_like_serve(engine, cfg)
        degraded = runner.degraded_outbound()
        assert set(degraded) == {"OUT"}, degraded
        assert degraded["OUT"].startswith(_REFUSED_OUT), degraded
        assert not runner.degraded_inbound()
        rows = await _rows(store, "outbound:OUT")
        assert "pin_mismatch" in {r["event"] for r in rows}
        await engine.reload_detail(cfg)
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        assert len(await _rows(store, "outbound:OUT")) == len(rows)

        feed = cfg / "feed.py"
        old = "https://partner.example.org/api"
        feed.write_text(feed.read_text(encoding="utf-8").replace(old, old + "/v2"), "utf-8")
        with pytest.raises(WiringError, match=_PIN_MISMATCH) as err:
            await engine.reload_detail(cfg)
        assert isinstance(err.value.__cause__, TrustAnchorError)
    finally:
        await engine.stop()


async def test_an_operator_start_checks_a_lane_the_boot_gate_left_unbuilt(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review R1: an ``auto_start=False`` lane is built at its operator start, and the CA is
    checked then. The start reads nothing for it, and neither does a reload while it is not
    running. Red under: the check removed from ``_ensure_destination_built``, or the reload check
    reading a lane it does not start."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32) + ", auto_start=False")
    engine = _engine(store)
    try:
        runner = await _start_like_serve(engine, cfg)
        assert not runner.degraded_outbound()
        await engine.reload_detail(cfg)
        assert await _rows(store, "outbound:OUT") == []
        await runner.start_outbound("OUT")
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        assert "pin_mismatch" in {r["event"] for r in await _rows(store, "outbound:OUT")}
    finally:
        await engine.stop()


async def test_a_refused_ftps_poller_ca_fails_that_inbound_at_start(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The inbound twin: an ``Ftp`` poller is checked before it binds, at start and at an operator
    start, and only it fails. A reload that does not change it leaves it down and reads nothing
    for it. Red under: either call removed from the runner, or the reload rebinding it."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import File, Ftp, Send, handler, inbound, outbound, router\n"
        "inbound('IB_FTPS', Ftp(host='127.0.0.1', port=9, tls=True, remote_dir='/out', "
        f"tls_ca_file={str(ca)!r}, tls_ca_pin={'00' * 32!r}), router='r')\n"
        f"outbound('OUT', File(directory={str(tmp_path / 'out')!r}))\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )
    engine = _engine(store)
    try:
        runner = await _start_like_serve(engine, cfg)
        refused = "TrustAnchorError: inbound connection 'IB_FTPS': its tls_ca_file was refused"
        assert runner.degraded_inbound()["IB_FTPS"].startswith(refused)
        assert not runner.degraded_outbound()
        rows = await _rows(store, "inbound:IB_FTPS")
        assert "pin_mismatch" in {r["event"] for r in rows}
        await engine.reload_detail(cfg)
        assert runner.degraded_inbound()["IB_FTPS"].startswith(refused)
        assert not runner.inbound_running("IB_FTPS")
        assert len(await _rows(store, "inbound:IB_FTPS")) == len(rows)
        # Review round 3, finding 8: an operator start refused by the CA records the failure, so
        # the poller reads failed and not stopped. Cleared first, to see it written again.
        runner._failed.pop(("inbound", "IB_FTPS"))
        with pytest.raises(TrustAnchorError, match=_LANE_REFUSED):
            await runner.start_inbound("IB_FTPS")
        assert runner.degraded_inbound()["IB_FTPS"].startswith(refused)
    finally:
        await engine.stop()


async def test_a_refused_lane_parked_and_unparked_is_checked_again(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review round 3, finding 2: parking a lane its CA refused clears its failed record, so the
    reload that brings it back must check it, not keep a failure it no longer records. Red under:
    the kept failure ignoring the failed record."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32))
    engine = _engine(store)
    feed = cfg / "feed.py"
    on = feed.read_text(encoding="utf-8")
    try:
        runner = await _start_like_serve(engine, cfg)
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        off = on.replace("))\noutbound('OB_OK'", "), auto_start=False)\noutbound('OB_OK'")
        assert off != on
        feed.write_text(off, encoding="utf-8")
        await engine.reload_detail(cfg)
        assert "OUT" not in runner.degraded_outbound()
        feed.write_text(on, encoding="utf-8")
        with pytest.raises(WiringError, match=_PIN_MISMATCH):
            await engine.reload_detail(cfg)
    finally:
        await engine.stop()


async def test_the_registry_preflight_keeps_the_lookup_and_leaves_the_lanes(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A ``FhirLookup`` has no lane to fail, so its refused CA still refuses the start and the
    reload. An outbound's does not: the runner checks each lane it builds. ``lanes=True`` is the
    control that the same graph does carry a refused lane CA."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32))
    reg = load_config(cfg)
    preflight = ta.make_registry_anchor_preflight(store, enforcing=True)
    await preflight(reg, {})
    with pytest.raises(WiringError, match="outbound connection 'OUT'"):
        await preflight(reg, {}, lanes=True)

    wiring._active = Registry()
    lookup = tmp_path / "lookup"
    _graph(lookup, _dest("rest", ca))
    (lookup / "lookup.py").write_text(
        "from messagefoundry import FhirLookup\n"
        f"FhirLookup('EPIC', url='https://fhir.example.org/fhir', tls_ca_file={str(ca)!r}, "
        f"tls_ca_pin={'00' * 32!r})\n",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="fhir lookup 'EPIC' tls_ca_file"):
        await preflight(load_config(lookup), {})


async def test_a_missing_outbound_ca_names_the_connection(
    store: MessageStore, tmp_path: Path
) -> None:
    """Review D2: the refusal names the connection, at the lane and at a reload. Red under: the
    ``OSError`` reaching the caller unwrapped."""
    gone = str(tmp_path / "gone.pem")
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(TrustAnchorError, match="outbound connection 'OUT' tls_ca_file: could not"):
        await check("outbound", "OUT", {"tls_ca_file": gone})
    cfg = tmp_path / "cfg"
    _graph(cfg, _dest("rest", gone))
    with pytest.raises(WiringError, match="outbound connection 'OUT' tls_ca_file: could not"):
        await _preflight(store, cfg)


# --- review round 2: a CA the hop never reads, and the pin's format --------------------------------

_MAIL_KW = "host='smtp.example.org', sender='a@example.org', recipients=['b@example.org']"
_DIRECT_KW = (
    "host='hisp.example.org', sender='a@direct.example.org', "
    "recipients=['b@direct.example.org'], signing_cert='s.pem', signing_key='k.pem', "
    "recipient_cert='r.pem', trust_anchor='t.pem'"
)

#: Each hop builds no context that verifies a server against ``tls_ca_file``.
_UNREAD: dict[str, str] = {
    "email-no-tls": "Email(" + _MAIL_KW + ", use_tls=False{kw})",
    "direct-no-tls": "Direct(" + _DIRECT_KW + ", use_tls=False{kw})",
    "email-no-verify": "Email(" + _MAIL_KW + ", tls_verify=False{kw})",
    "rest-http": "Rest(url='http://partner.example.org/api'{kw})",
    "rest-verify-off": "Rest(url='https://partner.example.org/api', verify_tls=False{kw})",
    "mllp-verify-off": "MLLP(host='partner.example.org', port=2575, tls=True, tls_verify=False{kw})",
}


def _unread_graph(cfg: Path, dest: str) -> None:
    cfg.mkdir()
    (cfg.parent / "in").mkdir(exist_ok=True)
    (cfg / "feed.py").write_text(
        "from messagefoundry import MLLP, Direct, Email, File, Rest, Send, env, handler\n"
        "from messagefoundry import inbound, outbound, router\n"
        "from messagefoundry.transports.http_auth import with_oauth2_client_credentials\n"
        f"inbound('IB_IN', File(directory={str(cfg.parent / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        f"outbound('OUT', {dest})\n" + _GRAPH_TAIL,
        encoding="utf-8",
    )


@pytest.mark.parametrize("case", sorted(_UNREAD))
def test_a_ca_the_hop_never_reads_is_not_checked_and_its_pin_is_refused(
    tmp_path: Path, case: str
) -> None:
    """Reviews D3 and R5, through a loaded graph. With no pin the CA is not collected, so a missing
    file refuses nothing. With a pin the load refuses, naming the reason. Red under: ``use_tls`` or
    ``tls_verify`` dropped from ``_CONNECTION_ANCHOR_KEYS``, or the unread rule removed."""
    gone = str(tmp_path / "gone.pem")
    bare = tmp_path / "bare"
    _unread_graph(bare, _UNREAD[case].format(kw=f", tls_ca_file={gone!r}"))
    assert ta.registry_anchor_specs(load_config(bare), {}) == []
    wiring._active = Registry()
    pinned = tmp_path / "pinned"
    kw = f", tls_ca_file={gone!r}, tls_ca_pin={'ab' * 32!r}"
    _unread_graph(pinned, _UNREAD[case].format(kw=kw))
    with pytest.raises(WiringError, match="tls_ca_pin is set, but the hop never reads"):
        load_config(pinned)


def test_a_token_hop_reads_the_ca_on_an_http_url(tmp_path: Path) -> None:
    """The control for the case above: an OAuth2 token hop reads ``tls_ca_file`` whatever the data
    url says, so the CA is collected and its pin is not refused."""
    gone = str(tmp_path / "gone.pem")
    cfg = tmp_path / "cfg"
    rest = (
        f"Rest(url='http://partner.example.org/api', tls_ca_file={gone!r}, "
        f"tls_ca_pin={'ab' * 32!r})"
    )
    _unread_graph(
        cfg,
        f"with_oauth2_client_credentials({rest}, token_url='https://auth.example.org/token', "
        "client_id='c', client_secret=env('secret'))",
    )
    (spec,) = ta.registry_anchor_specs(load_config(cfg), {"secret": "s"})
    assert (spec.label, spec.pin) == ("outbound:OUT", "ab" * 32)


@pytest.mark.parametrize("factory", sorted(_FACTORIES))
@pytest.mark.parametrize("pin", ["ab" * 31, "zz" * 32])
def test_a_malformed_pin_is_refused_at_load(factory: str, pin: str) -> None:
    """Review R3: a pin of the wrong length or not hex is refused by the factory, so ``check`` and a
    dry run catch it, not only a real reload. An ``env()`` pin is checked once it resolves."""
    with pytest.raises((ValueError, WiringError), match="must be a SHA-256 hex digest"):
        _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin=pin)
    _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin=env("ca_pin"))


# --- code review, round 2 repairs ----------------------------------------------------------------


async def test_a_repeated_lane_refusal_writes_no_new_rows(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A scheduled poller retries its bind every tick. The same refusal again is raised from memory,
    so the audit table does not grow and push a quiet anchor's baseline out of the look-back. A
    changed file is checked and audited again. Red under: the memory removed."""
    ca = _ca(tmp_path)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    settings = {"tls": True, "tls_ca_file": str(ca), "tls_ca_pin": "00" * 32}
    for _ in range(3):
        with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH):
            await check("inbound", "IB_FTPS", settings)
    events = [r["event"] for r in await _rows(store, "inbound:IB_FTPS")]
    assert events.count("pin_mismatch") == 1, events
    ca.write_bytes(_block(b"swapped"))
    with pytest.raises(TrustAnchorError, match=_PIN_MISMATCH):
        await check("inbound", "IB_FTPS", settings)
    events = [r["event"] for r in await _rows(store, "inbound:IB_FTPS")]
    assert events.count("pin_mismatch") == 2 and "changed" in events, events


async def test_a_connection_test_checks_the_ca_before_it_dials(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding 3: the Test Connection route builds a fresh connector and dials it, so it must
    check the CA first, or a lane failed by its pin would test as reachable. Red under: the route's
    ``check_test_anchor`` call removed."""
    from messagefoundry.api.app import _ANCHOR_REFUSED_DETAIL, _run_connection_test
    from messagefoundry.transports.rest import RestDestination

    async def reachable(_self: Any) -> None:
        return None

    monkeypatch.setattr(RestDestination, "test_connection", reachable)
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32))
    engine = _engine(store)
    try:
        runner = await _start_like_serve(engine, cfg)
        result = await _run_connection_test(runner, "OUT", "outbound")
        assert (result.success, result.detail) == (False, _ANCHOR_REFUSED_DETAIL)
        good = await _run_connection_test(runner, "OB_OK", "outbound")
        assert good.detail != _ANCHOR_REFUSED_DETAIL
    finally:
        await engine.stop()


def test_a_ca_behind_an_http_ech_sidecar_is_unread() -> None:
    """Review finding 4: an ECH sidecar on http:// takes both hops over cleartext loopback and does
    the TLS itself, so the CA verifies nothing. An https:// sidecar is a TLS hop, so it may read it."""
    base = {"url": "https://partner.example.org/api", "ech_egress": True}
    assert ta.unread_ca_reason({**base, "ech_sidecar": "http://127.0.0.1:8123"}) is not None
    assert ta.unread_ca_reason({**base, "ech_sidecar": "https://127.0.0.1:8123"}) is None
    assert ta.unread_ca_reason({**base, "ech_egress": False}) is None


async def test_a_first_load_by_reload_leaves_the_lanes_to_the_runner(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review finding 5: an engine started with no graph takes its first one by reload. That load is
    the start, so a refused outbound CA fails its lane rather than the load, and is audited once.
    Red under: that path calling the preflight with the reload scope."""
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32))
    engine = _engine(store)
    try:
        await engine.reload_detail(cfg)
        runner = engine.registry_runner
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        events = [r["event"] for r in await _rows(store, "outbound:OUT")]
        assert events.count("pin_mismatch") == 1, events
    finally:
        await engine.stop()


async def test_a_reload_does_not_read_a_lane_below_the_dr_threshold(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Manager decision Q1: a DR-parked lane is not built, so a bad CA there must not refuse a reload
    or a DR activation. Its CA is read when the lane is built. Red under: the reload check
    ignoring the DR threshold."""
    from messagefoundry.config.models import Priority
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin="00" * 32) + ", priority=Priority.LOW")
    runner = RegistryRunner(
        load_config(cfg),
        store,
        egress=EgressSettings(deny_by_default=False),
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
        dr_threshold=Priority.NORMAL,
    )
    await runner.start()
    try:
        assert not runner.degraded_outbound()
        await runner.reload(load_config(cfg))
        assert await _rows(store, "outbound:OUT") == []
    finally:
        await runner.stop()


# --- round 4: the Lander's hold on PR 2108 --------------------------------------------------------


class _CountingSink:
    """Counts ``connection_stopped`` alerts per connection; every other alert is a no-op."""

    def __init__(self) -> None:
        from messagefoundry.pipeline.alerts import LoggingAlertSink

        self._base = LoggingAlertSink()
        self.stopped: list[str] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append(name)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._base, attr)


def _ftps_poller_registry(ca: Path, *, pin: str | None = None, schedule: Any = None) -> Registry:
    """One inbound ``Ftp`` poller on a dead loopback port, routed nowhere, and no outbound."""
    from messagefoundry.config.wiring import build_inbound_connection

    kw: dict[str, Any] = {"tls_ca_file": str(ca)}
    if pin is not None:
        kw["tls_ca_pin"] = pin
    reg = Registry()
    spec = Ftp(host="127.0.0.1", port=9, tls=True, remote_dir="/out", **kw)
    reg.add_inbound(build_inbound_connection("IB_FTPS", spec, router="r", schedule=schedule))
    reg.add_router("r", lambda m: [])
    return reg


def _real_ca(tmp_path: Path) -> Path:
    """A CA file an FTPS context loads, so a poller can bind for real."""
    from tests.test_alert_smtp_tls import _self_signed_ca_pem

    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "real-ca.pem"
    p.write_bytes(_self_signed_ca_pem())
    return p


def _runner(store: MessageStore, reg: Registry, **kw: Any) -> Any:
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    return RegistryRunner(
        reg,
        store,
        egress=EgressSettings(deny_by_default=False),
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
        **kw,
    )


async def test_a_refused_scheduled_poller_alerts_once_over_three_ticks(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Lander hold, blocking: each in-window tick retries the start. The refusal is recorded once,
    so three ticks give one ``connection_stopped`` alert, not one per tick. Red under: the operator
    start path recording every refusal (35bc01e080)."""
    from datetime import UTC, datetime, time

    from messagefoundry.config.models import ActiveWindow, Schedule

    schedule = Schedule(
        windows=[
            ActiveWindow(
                days=frozenset(range(7)), start=time(0, 0), end=time(23, 59), timezone="UTC"
            )
        ]
    )
    reg = _ftps_poller_registry(_ca(tmp_path), pin="00" * 32, schedule=schedule)
    sink = _CountingSink()
    noon = datetime(2026, 7, 13, 12, tzinfo=UTC)
    runner = _runner(store, reg, alert_sink=sink, schedule_clock=lambda: noon)
    await runner.start()
    try:
        for _ in range(3):
            await runner._reconcile_schedule("IB_FTPS", "inbound", schedule)
        assert sink.stopped == ["IB_FTPS"], sink.stopped
        assert not runner.inbound_running("IB_FTPS")
    finally:
        await runner.stop()


async def test_a_refused_check_on_a_failed_lane_does_not_let_the_next_reload_skip_it(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 1, in isolation. ``OUT`` fails its start for a reason that is not its CA, so it is
    recorded failed but not marked. Its CA is then swapped. A connection test and a refused reload
    each check it, and neither may mark it, or the next reload would keep the failure and skip the
    check. Red under either ``fails_lane=False`` call reverted."""
    from messagefoundry.api.app import _run_connection_test
    from messagefoundry.pipeline import wiring_runner
    from messagefoundry.transports import build_destination as real

    calls = {"OUT": 0}

    def flaky(dest: Any, **kw: Any) -> Any:
        if dest.name == "OUT" and calls["OUT"] == 0:
            calls["OUT"] += 1
            raise RuntimeError("partner endpoint not ready")
        return real(dest, **kw)

    monkeypatch.setattr(wiring_runner, "build_destination", flaky)
    ca = _ca(tmp_path)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin=_sha(ca)))
    engine = _engine(store)
    try:
        runner = await _start_like_serve(engine, cfg)
        assert "partner endpoint not ready" in runner.degraded_outbound()["OUT"]
        ca.write_bytes(_block(b"substitute"))
        await _run_connection_test(runner, "OUT", "outbound")
        for _ in range(2):
            with pytest.raises(WiringError, match=_PIN_MISMATCH):
                await engine.reload_detail(cfg)
    finally:
        await engine.stop()


async def test_a_marked_lane_with_a_live_connector_is_still_checked(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Fix 2, the ``_destinations`` clause. A lane with a live connector is running, so a reload
    keeps it and must check it, whatever an old mark says. The mark and failure are planted, since
    no path today leaves them on a live lane. Red under: the clause removed."""
    ca = _ca(tmp_path)
    pin = _sha(ca)
    cfg = tmp_path / "cfg"
    _two_outbound_graph(cfg, _dest("rest", ca, pin=pin))
    engine = _engine(store)
    try:
        runner = await _start_like_serve(engine, cfg)
        assert "OUT" in runner._destinations
        runner._anchor_refused[("outbound", "OUT")] = (str(ca), pin)
        runner._failed[("outbound", "OUT")] = "planted"
        ca.write_bytes(_block(b"substitute"))
        with pytest.raises(WiringError, match=_PIN_MISMATCH):
            await engine.reload_detail(cfg)
    finally:
        await engine.stop()


async def test_a_marked_poller_that_is_bound_is_still_checked(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Fix 2, the ``bound`` clause. A poller listening before the reload is kept running, so the
    reload must check it, whatever an old mark says. Planted as above. Red under: the clause
    removed."""
    ca = _real_ca(tmp_path)
    pin = _sha(ca)
    runner = _runner(store, _ftps_poller_registry(ca, pin=pin))
    await runner.start()
    try:
        assert runner.inbound_running("IB_FTPS")
        runner._anchor_refused[("inbound", "IB_FTPS")] = (str(ca), pin)
        runner._failed[("inbound", "IB_FTPS")] = "planted"
        ca.write_bytes(_block(b"substitute"))
        with pytest.raises(WiringError, match=_PIN_MISMATCH):
            await runner.reload(_ftps_poller_registry(ca, pin=pin))
    finally:
        await runner.stop()


async def test_a_reload_rollback_does_not_rebind_a_poller_whose_ca_was_swapped(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fix 4. A reload that fails after its quiesce restarts the old pollers. One whose CA was
    swapped since is checked first: it stays down and reads failed, with one alert. Red under: the
    rollback binding it unchecked."""
    ca = _real_ca(tmp_path)
    sink = _CountingSink()
    runner = _runner(store, _ftps_poller_registry(ca, pin=_sha(ca)), alert_sink=sink)
    await runner.start()
    try:
        assert runner.inbound_running("IB_FTPS")

        other = _real_ca(tmp_path / "other").read_bytes()

        async def swap_then_fail(old: Registry, new: Registry) -> None:
            ca.write_bytes(other)  # loadable, so only the check keeps it down
            raise RuntimeError("reconcile failed")

        monkeypatch.setattr(runner, "_reconcile_outbounds", swap_then_fail)
        with pytest.raises(RuntimeError, match="reconcile failed"):
            await runner.reload(_ftps_poller_registry(ca, pin=_sha(ca)))
        assert not runner.inbound_running("IB_FTPS")
        assert "IB_FTPS" in runner.degraded_inbound()
        assert sink.stopped == ["IB_FTPS"]
    finally:
        await runner.stop()


async def test_a_poller_whose_ca_was_removed_drops_its_old_refusal(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Lander Low: a poller that no longer names a CA has nothing to check, so its old refusal
    must not stand. Red under: the early return leaving the mark."""
    runner = _runner(store, _ftps_poller_registry(_ca(tmp_path), pin="00" * 32))
    await runner.start()
    try:
        assert ("inbound", "IB_FTPS") in runner._anchor_refused
        no_ca = Registry()
        from messagefoundry.config.wiring import build_inbound_connection

        spec = Ftp(host="127.0.0.1", port=9, tls=True, remote_dir="/out")
        no_ca.add_inbound(build_inbound_connection("IB_FTPS", spec, router="r"))
        no_ca.add_router("r", lambda m: [])
        runner.registry = no_ca
        await runner._check_inbound_lane_anchor("IB_FTPS")
        assert ("inbound", "IB_FTPS") not in runner._anchor_refused
    finally:
        await runner.stop()


# --- round 4, code-review repair --------------------------------------------------------------------


async def test_a_fixed_env_pin_ends_a_kept_failure(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review finding 1: the spec holds the same ``env()`` reference after the operator fixes its
    value, so "config unchanged" must compare the resolved CA path and pin. A reload with the fixed
    value rebuilds the lane. Red under: the kept failure ignoring the resolved pair."""
    ca = _ca(tmp_path)
    reg_text = (
        "from messagefoundry import File, Rest, Send, env, handler, inbound, outbound, router\n"
        f"inbound('IB_IN', File(directory={str(tmp_path / 'in')!r}, poll_seconds=1.0), "
        "router='r')\n"
        "outbound('OUT', Rest(url='https://partner.example.org/api', "
        f"tls_ca_file={str(ca)!r}, tls_ca_pin=env('pin')))\n" + _GRAPH_TAIL
    )
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (tmp_path / "in").mkdir()
    (cfg / "feed.py").write_text(reg_text, encoding="utf-8")
    runner = _runner(store, load_config(cfg), env_values={"pin": "00" * 32})
    await runner.start()
    try:
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        runner.set_env_values({"pin": _sha(ca)})
        await runner.reload(load_config(cfg))
        assert "OUT" not in runner.degraded_outbound()
        assert "OUT" in runner._destinations
    finally:
        await runner.stop()


async def test_the_control_route_audits_a_refused_poller_start(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review finding 3: an operator start of a poller refused by its CA answers 409 with the fixed
    line, never a 500, and its control audit row is written. Red under: the route not catching the
    refusal."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.pipeline import Engine

    engine = Engine(
        store,
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_ftps_poller_registry(_ca(tmp_path), pin="00" * 32))
    await engine.start()
    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            r = await client.post("/connections/IB_FTPS/start")
        assert r.status_code == 409, r.text
        assert "trust anchor refused" in r.text
        rows = await store.list_audit(action="connection_control", limit=10)
        assert [json.loads(row["detail"])["connection"] for row in rows] == ["IB_FTPS"]
    finally:
        await engine.stop()


# --- round 5: review #10 and #13 -------------------------------------------------------------------


def _outbound_registry(ca: Path, pin: str, **kw: Any) -> Registry:
    """One Rest outbound ``OUT`` with a CA and pin, plus any ``outbound()`` keywords."""
    from messagefoundry.config.wiring import build_outbound_connection

    reg = Registry()
    spec = Rest(url="https://partner.example.org/api", tls_ca_file=str(ca), tls_ca_pin=pin)
    reg.add_outbound(build_outbound_connection("OUT", spec, **kw))
    return reg


def _day_schedule() -> Any:
    """08:00 to 17:00 UTC, every day."""
    from datetime import time

    from messagefoundry.config.models import ActiveWindow, Schedule

    window = ActiveWindow(
        days=frozenset(range(7)), start=time(8, 0), end=time(17, 0), timezone="UTC"
    )
    return Schedule(windows=[window])


def _at(hour: int) -> Any:
    from datetime import UTC, datetime

    return datetime(2026, 7, 13, hour, tzinfo=UTC)


async def test_removing_the_schedule_of_a_ca_refused_lane_does_not_resume_it(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review round 5, finding 10. The calendar parked ``OUT`` while its refused CA kept it failed.
    A reload that only removes the schedule leaves it failed and paused, with no connector and no
    second alert. The positive arm: a reload that also changes its config, with the file fixed,
    checks it, and the lane resumes. Red under the resume path ignoring the kept failure, the code
    before this fix; and under the hold firing on every lane."""
    good = _block(b"partner-ca")
    ca = _ca(tmp_path)
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    schedule = _day_schedule()
    now = [_at(9)]
    sink = _CountingSink()
    runner = _runner(
        store,
        _outbound_registry(ca, pin, schedule=schedule),
        alert_sink=sink,
        schedule_clock=lambda: now[0],
    )
    await runner.start()
    try:
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        now[0] = _at(18)  # the window closes: the calendar parks it
        await runner._reconcile_schedule("OUT", "outbound", schedule)
        assert "OUT" in runner._schedule_parked
        await runner.reload(_outbound_registry(ca, pin))  # the schedule alone is removed
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        assert "OUT" in runner._outbound_paused
        assert "OUT" not in runner._destinations
        assert sink.stopped == ["OUT"], sink.stopped

        ca.write_bytes(good)
        from messagefoundry.config.wiring import build_outbound_connection

        changed = Registry()
        spec = Rest(url="https://partner.example.org/v2", tls_ca_file=str(ca), tls_ca_pin=pin)
        changed.add_outbound(build_outbound_connection("OUT", spec))
        await runner.reload(changed)
        assert "OUT" not in runner._outbound_paused
        assert "OUT" in runner._destinations
        assert "OUT" not in runner.degraded_outbound()
    finally:
        await runner.stop()


async def test_a_window_open_on_a_ca_refused_lane_does_not_alert_again(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review round 5, finding 1. Each window open starts the lane, which rebuilds it and reads
    the CA again. The refusal was alerted when the lane first failed, so a later window adds no
    alert. Red under the operator-start build recording every refusal."""
    schedule = _day_schedule()
    now = [_at(9)]
    sink = _CountingSink()
    runner = _runner(
        store,
        _outbound_registry(_ca(tmp_path), "00" * 32, schedule=schedule),
        alert_sink=sink,
        schedule_clock=lambda: now[0],
    )
    await runner.start()
    try:
        for hour in (18, 9, 18, 9):  # two closes and two opens
            now[0] = _at(hour)
            await runner._reconcile_schedule("OUT", "outbound", schedule)
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        assert sink.stopped == ["OUT"], sink.stopped
    finally:
        await runner.stop()


async def test_a_dr_release_checks_a_lane_whose_ca_failure_the_park_ended(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review round 4, finding 2, pinned as built. A DR park clears the lane's failed record, so
    it no longer keeps its CA failure. The park's own reload reads nothing for it. The first
    reload after the release builds it, so it checks it, and a CA still refused refuses that
    reload (the ADR 0031 amendment's Consequences). Recovery: fix the file and start the lane, and
    the same graph reloads."""
    from messagefoundry.config.models import Priority

    good = _block(b"partner-ca")
    ca = _ca(tmp_path)
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    runner = _runner(store, _outbound_registry(ca, pin, priority=Priority.LOW))
    await runner.start()
    try:
        assert runner.degraded_outbound()["OUT"].startswith(_REFUSED_OUT)
        runner.set_dr_threshold(Priority.NORMAL)
        await runner.reload(_outbound_registry(ca, pin, priority=Priority.LOW))
        assert "OUT" not in runner.degraded_outbound()  # parked, and its failed record cleared
        runner.set_dr_threshold(None)
        with pytest.raises(WiringError, match=_PIN_MISMATCH):
            await runner.reload(_outbound_registry(ca, pin, priority=Priority.LOW))

        ca.write_bytes(good)
        await runner.start_outbound("OUT")
        assert "OUT" in runner._destinations
        await runner.reload(_outbound_registry(ca, pin, priority=Priority.LOW))
        assert "OUT" not in runner.degraded_outbound()
    finally:
        await runner.stop()


async def test_a_lane_mark_clears_at_an_operator_start_whose_check_passes(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review round 4, finding 13. A lane its CA refused at start is marked. Once the file is
    fixed, an operator start checks it, builds it, and clears the mark. Red under the pass not
    clearing it."""
    good = _block(b"partner-ca")
    ca = _ca(tmp_path)
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    runner = _runner(store, _outbound_registry(ca, pin))
    await runner.start()
    try:
        assert ("outbound", "OUT") in runner._anchor_refused
        ca.write_bytes(good)
        await runner.start_outbound("OUT")
        assert ("outbound", "OUT") not in runner._anchor_refused
        assert "OUT" in runner._destinations
    finally:
        await runner.stop()


async def test_a_lane_mark_clears_when_a_changed_reload_passes_its_check(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Review round 4, finding 13. A lane its CA refused at start is marked. A reload that
    changes its config, with the file fixed, checks it, rebuilds it, and clears the mark once it
    commits. Red under the commit not clearing it."""
    from messagefoundry.config.wiring import build_outbound_connection

    good = _block(b"partner-ca")
    ca = _ca(tmp_path)
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    runner = _runner(store, _outbound_registry(ca, pin))
    await runner.start()
    try:
        assert ("outbound", "OUT") in runner._anchor_refused
        ca.write_bytes(good)
        changed = Registry()
        spec = Rest(url="https://partner.example.org/v2", tls_ca_file=str(ca), tls_ca_pin=pin)
        changed.add_outbound(build_outbound_connection("OUT", spec))
        await runner.reload(changed)
        assert ("outbound", "OUT") not in runner._anchor_refused
        assert "OUT" in runner._destinations
    finally:
        await runner.stop()
