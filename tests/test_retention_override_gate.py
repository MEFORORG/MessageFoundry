# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A connection's own keep-forever retention override meets the body-window gate (vault BACKLOG #2368).

An inbound ``messages_days = 0`` or an outbound ``dead_letter_days = 0`` keeps that connection's PHI
bodies forever. The ``serve`` gate read only the global windows, so the override needed no
acknowledgement and wrote no AUDIT line. The overrides live in the graph, so a registry guard judges
them: refuse under enforce, warn under warn, AUDIT once acknowledged.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.__main__ import _chain_registry_guards, main
from messagefoundry.config.retention_classification import (
    auto_bounded_windows,
    keep_forever_overrides,
    make_retention_override_guard,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry, WiringError, load_config
from messagefoundry.pipeline.engine import Engine
from tests.test_cli import _SECURE_ALERTS, _SECURE_RETENTION, _run_secure_serve

_LOG = logging.getLogger("tests.retention_override_gate")
_ACK = "[security].allow_keeping_phi_indefinitely"


def _graph(cfg: Path, *, inbound_days: int | None, outbound_days: int | None) -> Registry:
    """A two-connection graph; ``None`` leaves that connection's override unset (inherit)."""
    cfg.mkdir()
    ib = "" if inbound_days is None else f", messages_days={inbound_days}"
    ob = "" if outbound_days is None else f", dead_letter_days={outbound_days}"
    (cfg / "feed.py").write_text(
        "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
        f"inbound('IB_FEED', MLLP(port=2611), router='r'{ib})\n"
        f"outbound('OB_FEED', MLLP(host='127.0.0.1', port=2612){ob})\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OB_FEED', msg)\n",
        encoding="utf-8",
    )
    return load_config(cfg)


def _guard(*, acknowledged: bool, enforcing: bool) -> Callable[[Registry], None]:
    return make_retention_override_guard(
        acknowledged=acknowledged, enforcing=enforcing, env_name="prod", log=_LOG
    )


def _guard_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The guard's own records. ``caplog`` holds every WARNING of the test, graph load included."""
    return [r for r in caplog.records if r.name == _LOG.name]


def test_only_a_zero_override_is_found(tmp_path: Path) -> None:
    both = _graph(tmp_path / "both", inbound_days=0, outbound_days=0)
    assert keep_forever_overrides(both) == (
        "inbound 'IB_FEED' (messages_days = 0)",
        "outbound 'OB_FEED' (dead_letter_days = 0)",
    )
    # A positive window bounds the connection, and an unset one inherits the global window, which
    # the serve gate already judges. Neither is this guard's business.
    assert keep_forever_overrides(_graph(tmp_path / "set", inbound_days=7, outbound_days=90)) == ()
    assert (
        keep_forever_overrides(_graph(tmp_path / "unset", inbound_days=None, outbound_days=None))
        == ()
    )


@pytest.mark.parametrize(
    ("inbound_days", "outbound_days", "named", "unnamed"),
    [(0, None, "IB_FEED", "OB_FEED"), (None, 0, "OB_FEED", "IB_FEED")],
)
def test_enforce_refuses_an_unacknowledged_override_and_names_the_connection(
    tmp_path: Path, inbound_days: int | None, outbound_days: int | None, named: str, unnamed: str
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=inbound_days, outbound_days=outbound_days)
    with pytest.raises(WiringError, match=named) as exc:
        _guard(acknowledged=False, enforcing=True)(registry)
    assert unnamed not in str(exc.value)
    assert f"{_ACK}=true" in str(exc.value)


def test_warn_enforcement_warns_instead_of_refusing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=0, outbound_days=0)
    capsys.readouterr()
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        _guard(acknowledged=False, enforcing=False)(registry)
    (record,) = _guard_records(caplog)
    text = record.getMessage()
    assert "IB_FEED" in text and "OB_FEED" in text and not text.startswith("AUDIT:")
    # The remedy names the switch and says how far it reaches.
    assert f"{_ACK}=true" in text and "covers the whole instance" in text
    # Only the auto-bounded windows lose a default, and the remedy names each of them.
    named = [w.setting for w in auto_bounded_windows()]
    assert named and all(setting in text for setting in named)
    assert "[retention].state_max_age_days" not in text
    # On stderr too, which no [logging].level can filter.
    assert f"warning: {text}" in capsys.readouterr().err


@pytest.mark.parametrize("enforcing", [True, False])
def test_an_acknowledged_override_loads_and_is_audited_by_name(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    enforcing: bool,
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=0, outbound_days=0)
    capsys.readouterr()
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        _guard(acknowledged=True, enforcing=enforcing)(registry)
    (record,) = _guard_records(caplog)
    text = record.getMessage()
    assert record.levelno == logging.WARNING and text.startswith("AUDIT:")
    assert "IB_FEED" in text and "OB_FEED" in text and f"{_ACK}=true" in text
    assert f"warning: {text}" in capsys.readouterr().err


@pytest.mark.parametrize("acknowledged", [True, False])
def test_a_graph_with_no_keep_forever_override_is_silent(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, acknowledged: bool
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=7, outbound_days=None)
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        _guard(acknowledged=acknowledged, enforcing=True)(registry)
    assert _guard_records(caplog) == []


def test_chained_guards_run_in_order_and_the_first_refusal_wins() -> None:
    # serve hands the engine ONE guard built from several. A guard dropped from the chain would
    # stop refusing with every other test still green, so the chain itself is pinned here.
    calls: list[str] = []

    def first(_: Registry) -> None:
        calls.append("first")

    def refuses(_: Registry) -> None:
        calls.append("refuses")
        raise WiringError("refused")

    def never(_: Registry) -> None:
        calls.append("never")

    registry = Registry()
    _chain_registry_guards(None, first, None)(registry)
    assert calls == ["first"]
    calls.clear()
    with pytest.raises(WiringError, match="refused"):
        _chain_registry_guards(first, refuses, never)(registry)
    assert calls == ["first", "refuses"]


def test_a_negative_override_built_past_the_factories_is_found(tmp_path: Path) -> None:
    # The factories refuse a negative window, but the purge reads any value <= 0 as keep-forever,
    # so a registry assembled without them must not slip past the guard.
    registry = _graph(tmp_path / "cfg", inbound_days=7, outbound_days=None)
    registry.inbound["IB_FEED"] = dataclasses.replace(registry.inbound["IB_FEED"], messages_days=-1)
    assert keep_forever_overrides(registry) == ("inbound 'IB_FEED' (messages_days = -1)",)


async def test_the_engine_reload_path_runs_the_guard(tmp_path: Path) -> None:
    """The engine's own reload path raises the guard's refusal. A dry run, so this does not show
    that a running graph is kept; the engine's reload tests own that ordering."""
    cfg = tmp_path / "cfg"
    _graph(cfg, inbound_days=0, outbound_days=None)
    eng = await Engine.create(
        tmp_path / "e.db",
        poll_interval=0.02,
        registry_guard=_guard(acknowledged=False, enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        with pytest.raises(WiringError, match="IB_FEED"):
            await eng.reload_detail(cfg, dry_run=True)
    finally:
        await eng.stop()


def _served_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str
) -> Callable[[Registry], None]:
    """The registry guard ``serve`` hands the managed app for a clean enforcing production config."""
    toml = extra + "security.block_unlisted_outbound = true\n" + _SECURE_RETENTION + _SECURE_ALERTS
    rc, captured = _run_secure_serve(tmp_path, monkeypatch, toml, env="prod")
    assert rc == 0
    return cast("Callable[[Registry], None]", captured["registry_guard"])


_SERVE_PROVISIONS = pytest.mark.usefixtures(
    "bounded_warn_only_retention", "verified_log_forwarding"
)


@_SERVE_PROVISIONS
def test_serve_wires_the_guard_and_it_refuses_under_bounded_global_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both global windows are 30 days, so the start gate passes. The override is the only thing
    # keeping bodies forever, and only the guard can see it.
    guard = _served_guard(tmp_path, monkeypatch, "")
    with pytest.raises(WiringError, match="OB_FEED"):
        guard(_graph(tmp_path / "cfg", inbound_days=None, outbound_days=0))
    guard(_graph(tmp_path / "ok", inbound_days=None, outbound_days=30))


@_SERVE_PROVISIONS
def test_serve_reads_the_acknowledgement_into_the_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _served_guard(tmp_path, monkeypatch, "security.allow_keeping_phi_indefinitely = true\n")
    guard(_graph(tmp_path / "cfg", inbound_days=0, outbound_days=0))


@_SERVE_PROVISIONS
def test_serve_keeps_the_static_credential_guard_in_the_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The chain test above uses made-up guards. This one pins the real wiring: the guard serve
    # hands the managed app still calls the guard the static-credential factory returned.
    judged: list[Registry] = []
    monkeypatch.setattr(
        "messagefoundry.config.static_credentials.make_static_credential_guard",
        lambda settings, *, enforcing, log: judged.append,
    )
    guard = _served_guard(tmp_path, monkeypatch, "")
    registry = _graph(tmp_path / "cfg", inbound_days=None, outbound_days=30)
    guard(registry)
    assert judged == [registry]


def _clear_posture_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every ``MEFOR_*`` variable the host or an earlier fixture set, so no environment
    override changes how the edit is judged. Any case: the loader lower-cases the name itself."""
    for name in list(os.environ):
        if name.upper().startswith("MEFOR_"):
            monkeypatch.delenv(name)


_EDIT_LOGIC = (
    "from messagefoundry import handler, router\n"
    "@router('r')\n"
    "def route(msg):\n"
    "    return ['h']\n"
    "@handler('h')\n"
    "def handle(msg):\n"
    "    return None\n"
)


@pytest.mark.parametrize(
    ("service_toml", "accepted"),
    [
        ("", False),
        ("security.allow_keeping_phi_indefinitely = true\n", True),
        ('security.enforcement = "warn"\n', True),
    ],
)
def test_connection_upsert_refuses_what_an_enforcing_reload_would(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    service_toml: str,
    accepted: bool,
) -> None:
    _clear_posture_env(monkeypatch)
    (tmp_path / "logic.py").write_text(_EDIT_LOGIC, encoding="utf-8")
    svc = tmp_path / "svc.toml"
    svc.write_text(service_toml, encoding="utf-8")
    edit = {
        "direction": "inbound",
        "name": "IB_FEED",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2613},
        "messages_days": 0,
    }
    rc = main(
        ["connection", "upsert", "--config", str(tmp_path), "--data", json.dumps(edit), "--json"]
        + ["--service-config", str(svc)]
    )
    out = capsys.readouterr().out
    written = (tmp_path / "connections.toml").exists()
    if accepted:
        assert rc == 0 and written
    else:
        assert rc == 1 and not written
        assert "IB_FEED" in out and "allow_keeping_phi_indefinitely" in out
        assert "No --service-config was given" not in out


def test_connection_upsert_says_which_settings_it_read_when_none_were_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The IDE's usual call names no --service-config, so the edit is judged against the defaults
    # (enforce, no acknowledgement). The refusal must say so, or it names a switch the instance
    # may already have set.
    _clear_posture_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "logic.py").write_text(_EDIT_LOGIC, encoding="utf-8")
    edit = {
        "direction": "inbound",
        "name": "IB_FEED",
        "transport": "mllp",
        "router": "r",
        "settings": {"port": 2614},
        "messages_days": 0,
    }
    rc = main(
        ["connection", "upsert", "--config", str(tmp_path), "--data", json.dumps(edit), "--json"]
    )
    out = capsys.readouterr().out
    assert rc == 1 and "No --service-config was given" in out
    assert "this edit is then checked against that instance's [security] settings" in out
