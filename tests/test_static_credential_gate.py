# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The opt-in static-credential refusal (BACKLOG #1182, ASVS 13.2.1).

``[security].require_nonstatic_credentials`` ships OFF (owner decision 2026-09-23, "Opt-in, off").
When on, every backend hop that presents an unchanging credential or none must be named in
``[security].static_credential_accepted`` with a reason, or serve refuses. Each direction is pinned:

* OFF: nothing is refused, whatever the hops;
* ON with no opt-out: the hop is refused, at the settings pass and at the graph guard;
* ON with an opt-out: the hop runs, and the opt-out is logged by name with its reason, never a secret;
* a hop that presents a compliant credential is never listed, so it never needs an opt-out.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecretRotationSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.config.static_credentials import (
    apply_static_credential_gate,
    make_static_credential_guard,
    static_credential_hops,
)
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline import Engine

_LOG = logging.getLogger("test_static_credential_gate")

#: A secret value that must never appear in any log line or message.
_SECRET = "hunter2-static-SECRET"

_STATIC_STORE = {
    "backend": "sqlserver",
    "server": "db.example.invalid",
    "database": "mf",
    "username": "svc",
    "password": _SECRET,
}


def _settings(*, gate: bool, accepted: dict[str, str] | None = None) -> ServiceSettings:
    return ServiceSettings.model_validate(
        {
            "store": _STATIC_STORE,
            "security": {
                "require_nonstatic_credentials": gate,
                "static_credential_accepted": accepted or {},
            },
        }
    )


def _run(settings: ServiceSettings) -> str | None:
    return apply_static_credential_gate(settings, registry=None, log=_LOG)


# --- the settings half ----------------------------------------------------------------------------


def test_the_gate_ships_off() -> None:
    assert SecuritySettings().require_nonstatic_credentials is False
    assert SecuritySettings().static_credential_accepted == {}


def test_off_refuses_nothing_even_over_a_static_hop(caplog: pytest.LogCaptureFixture) -> None:
    settings = _settings(gate=False)
    # The control: the hop IS in the inventory, so "nothing refused" is the gate being off.
    assert [h.name for h in static_credential_hops(registry=None, settings=settings)] == [
        "settings:store"
    ]
    with caplog.at_level(logging.WARNING):
        assert _run(settings) is None
    assert caplog.records == []


def test_on_without_an_opt_out_refuses_and_names_the_hop() -> None:
    reason = _run(_settings(gate=True))
    assert reason is not None
    assert "settings:store" in reason
    assert _SECRET not in reason


def test_on_with_an_opt_out_runs_and_logs_the_opt_out(caplog: pytest.LogCaptureFixture) -> None:
    settings = _settings(gate=True, accepted={"settings:store": "DBA has no gMSA yet"})
    with caplog.at_level(logging.WARNING):
        assert _run(settings) is None
    text = caplog.text
    assert "settings:store" in text and "DBA has no gMSA yet" in text
    assert _SECRET not in text


def test_an_opt_out_naming_no_hop_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    settings = _settings(
        gate=True, accepted={"settings:store": "r", "settings:alerts.webhook": "stale"}
    )
    with caplog.at_level(logging.WARNING):
        assert _run(settings) is None
    assert "settings:alerts.webhook" in caplog.text and "does nothing" in caplog.text


def test_a_blank_reason_is_refused_at_load() -> None:
    with pytest.raises(ValidationError, match="needs a reason"):
        SecuritySettings(static_credential_accepted={"OB_X": "  "})


def test_a_compliant_store_needs_no_opt_out() -> None:
    settings = ServiceSettings.model_validate(
        {
            "store": {**_STATIC_STORE, "auth": "integrated", "password": None, "username": None},
            "security": {"require_nonstatic_credentials": True},
        }
    )
    assert static_credential_hops(registry=None, settings=settings) == []
    assert _run(settings) is None


# --- the loosening report -------------------------------------------------------------------------


def _loosening_names(sec: SecuritySettings) -> list[str]:
    return [
        name
        for name, _ in security_loosenings(
            sec,
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            (),
            (),
            (),
            None,
        )
    ]


def test_an_honoured_opt_out_is_a_loosening_and_an_inert_one_is_not() -> None:
    accepted = {"OB_X": "partner offers Basic only"}
    on = SecuritySettings(require_nonstatic_credentials=True, static_credential_accepted=accepted)
    off = SecuritySettings(static_credential_accepted=accepted)
    assert "static_credential_accepted" in _loosening_names(on)
    assert "static_credential_accepted" not in _loosening_names(off)
    assert "require_nonstatic_credentials" not in _loosening_names(on)  # it tightens


# --- the graph half: the engine's registry guard --------------------------------------------------


def _write_graph(cfg: Path, *, basic: bool) -> None:
    cfg.mkdir()
    auth = ', basic_user="u", basic_password=env("pw")' if basic else ""
    (cfg / "feed.py").write_text(
        "from messagefoundry import Rest, Send, File, env, handler, inbound, outbound, router\n"
        "from messagefoundry.transports.smart import with_smart_backend\n"
        f"inbound('IB', File(directory={str(cfg.parent / 'in')!r}, pattern='*.hl7'), router='r')\n"
        f"outbound('OB_REST', Rest(url='https://p.example.invalid/x'{auth}))\n"
        "outbound('OB_SMART', with_smart_backend(Rest(url='https://q.example.invalid/x'),\n"
        "    token_url='https://q.example.invalid/t', client_id='c', private_key=env('k')))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OB_REST', msg)\n",
        encoding="utf-8",
    )


def _guard(settings: ServiceSettings, *, enforcing: bool = True) -> Callable[[Registry], None]:
    """The guard ``serve`` builds, from the same factory."""
    guard = make_static_credential_guard(settings, enforcing=enforcing, log=_LOG)
    assert guard is not None
    return guard


async def test_a_reload_carrying_an_unaccepted_static_hop_is_refused(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=True)
    eng = await Engine.create(
        tmp_path / "e.db", poll_interval=0.02, registry_guard=_guard(_settings(gate=True))
    )
    try:
        with pytest.raises(WiringError, match="OB_REST") as exc:
            await eng.reload_detail(cfg, dry_run=True)
        # The SMART hop presents a compliant credential and is never listed.
        assert "OB_SMART" not in str(exc.value)
        assert eng.registry_runner is None  # nothing went live
    finally:
        await eng.stop()


async def test_the_same_graph_passes_the_guard_with_an_opt_out(tmp_path: Path) -> None:
    """The allow direction, through the engine's own guard. Not a full reload: a dry run also
    build-checks every connector, which needs real environment values and key material this test
    is not about."""
    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=True)
    settings = _settings(gate=True, accepted={"OB_REST": "partner offers HTTP Basic only"})
    eng = await Engine.create(
        tmp_path / "e.db", poll_interval=0.02, registry_guard=_guard(settings)
    )
    try:
        eng.guard_registry(load_config(cfg))
    finally:
        await eng.stop()


async def test_with_the_gate_off_there_is_no_guard_and_the_graph_passes(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=True)
    guard = make_static_credential_guard(_settings(gate=False), enforcing=True, log=_LOG)
    assert guard is None
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02, registry_guard=guard)
    try:
        eng.guard_registry(load_config(cfg))
    finally:
        await eng.stop()


def test_under_warn_enforcement_the_guard_warns_instead_of_refusing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=True)
    with caplog.at_level(logging.WARNING):
        _guard(_settings(gate=True), enforcing=False)(load_config(cfg))
    assert "OB_REST" in caplog.text


def test_the_guard_judges_only_graph_hops(tmp_path: Path) -> None:
    """The settings pass has already judged ``settings:store``; the graph guard must not refuse it a
    second time, and must not call its opt-out unmatched."""
    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=False)
    reg = load_config(cfg)
    settings = _settings(gate=True, accepted={"OB_REST": "no auth offered by the partner"})
    # OB_REST presents nothing (credential "none") and is opted out; settings:store is not in scope.
    _guard(settings)(reg)


# --- the check and the posture surface ------------------------------------------------------------


def test_the_check_says_when_the_gate_is_on_and_marks_opt_outs(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    cfg = tmp_path / "config"
    _write_graph(cfg, basic=True)
    (tmp_path / "messagefoundry.toml").write_text(
        '[store]\nbackend = "sqlite"\n\n[ai]\nenvironment = "dev"\n\n'
        "[security]\nblock_unlisted_outbound = true\nallow_unencrypted_phi = true\n"
        "allow_unencrypted_phi_under_strict_enforcement = true\n"
        "require_nonstatic_credentials = true\n"
        'static_credential_accepted = { OB_REST = "partner offers HTTP Basic only" }\n',
        encoding="utf-8",
    )
    result = next(
        r for r in run_checks(cfg, run_lint=False).results if r.name == "static-credentials"
    )
    assert result.ok and not result.required and not result.skipped
    detail = str(result.detail)
    assert "OB_REST" in detail and "[opted out]" in detail
    assert "is ON" in detail
    assert "OB_SMART" not in detail


async def test_the_posture_view_carries_the_inventory_and_its_scope(tmp_path: Path) -> None:
    import httpx

    from messagefoundry.api.app import create_app

    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=True)
    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02)
    eng.add_registry(load_config(cfg))
    app = create_app(eng, allow_no_auth=True)
    app.state.static_credential_settings = _settings(gate=True, accepted={"OB_REST": "r"})
    app.state.security = app.state.static_credential_settings.security
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            body = (await client.get("/security/posture")).json()
    finally:
        await eng.stop()
    hops = {h["name"]: h for h in body["static_credential_hops"]}
    assert hops["OB_REST"]["accepted"] is True
    assert hops["OB_REST"]["credential"] == "static"
    assert hops["settings:store"]["accepted"] is False
    assert "OB_SMART" not in hops
    assert body["static_credential_hops_scope"] is None
    assert _SECRET not in str(body)


def test_the_check_does_not_claim_the_gate_is_off_when_it_read_no_settings(
    tmp_path: Path,
) -> None:
    from messagefoundry.checks import run_checks

    cfg = tmp_path / "config"
    _write_graph(cfg, basic=True)
    result = next(
        r
        for r in run_checks(cfg, run_lint=False, suppress_service_toml_search=True).results
        if r.name == "static-credentials"
    )
    detail = str(result.detail)
    assert "unknown" in detail and "is off" not in detail
    assert "graph only" in detail


def test_the_posture_does_not_mark_an_inert_opt_out_as_accepted() -> None:
    """With the refusal off an opt-out does nothing, and security_loosenings() says so; the posture
    view's ``accepted`` must agree."""
    from messagefoundry.api.models import StaticCredentialHopView

    # The model carries the flag; the route decides it. Pin the rule the route applies.
    settings = _settings(gate=False, accepted={"settings:store": "r"})
    sec = settings.security
    opt_outs = sec.static_credential_accepted if sec.require_nonstatic_credentials else {}
    views = [
        StaticCredentialHopView(**asdict(hop), accepted=hop.name in opt_outs)
        for hop in static_credential_hops(registry=None, settings=settings)
    ]
    assert [(v.name, v.accepted) for v in views] == [("settings:store", False)]


async def test_a_first_load_refusal_closes_the_store(tmp_path: Path) -> None:
    """The first graph load runs after the store is open and before the teardown span, so a refusal
    there must close the store itself. aiosqlite's worker thread is non-daemon: left open, it keeps
    the process from exiting."""
    import threading

    from messagefoundry.api.app import create_managed_app

    cfg = tmp_path / "cfg"
    _write_graph(cfg, basic=True)
    before = {t.ident for t in threading.enumerate()}
    app = create_managed_app(
        db_path=tmp_path / "m.db",
        config_dir=cfg,
        registry_guard=_guard(_settings(gate=True)),
    )
    with pytest.raises(WiringError, match="OB_REST"):
        async with app.router.lifespan_context(app):
            pass
    leaked = [
        t for t in threading.enumerate() if t.ident not in before and not t.daemon and t.is_alive()
    ]
    assert leaked == []
