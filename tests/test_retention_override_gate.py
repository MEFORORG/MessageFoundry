# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A connection's own keep-forever retention override meets the body-window gate (vault BACKLOG #2368).

An inbound ``messages_days = 0`` or an outbound ``dead_letter_days = 0`` keeps that connection's PHI
bodies forever. The ``serve`` gate read only the global windows, so the override needed no
acknowledgement and wrote no AUDIT line. The overrides live in the graph, so a registry guard judges
them: refuse under enforce, warn under warn, AUDIT once acknowledged.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from messagefoundry.config.retention_classification import (
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
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=0, outbound_days=0)
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        _guard(acknowledged=False, enforcing=False)(registry)
    (record,) = caplog.records
    text = record.getMessage()
    assert "IB_FEED" in text and "OB_FEED" in text and not text.startswith("AUDIT:")


@pytest.mark.parametrize("enforcing", [True, False])
def test_an_acknowledged_override_loads_and_is_audited_by_name(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, enforcing: bool
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=0, outbound_days=0)
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        _guard(acknowledged=True, enforcing=enforcing)(registry)
    (record,) = caplog.records
    text = record.getMessage()
    assert record.levelno == logging.WARNING and text.startswith("AUDIT:")
    assert "IB_FEED" in text and "OB_FEED" in text and f"{_ACK}=true" in text


@pytest.mark.parametrize("acknowledged", [True, False])
def test_a_graph_with_no_keep_forever_override_is_silent(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, acknowledged: bool
) -> None:
    registry = _graph(tmp_path / "cfg", inbound_days=7, outbound_days=None)
    with caplog.at_level(logging.WARNING, logger=_LOG.name):
        _guard(acknowledged=acknowledged, enforcing=True)(registry)
    assert caplog.records == []


async def test_a_reload_adding_a_keep_forever_override_is_refused(tmp_path: Path) -> None:
    """Through the engine's own reload path: the refused graph never goes live."""
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
        assert eng.registry_runner is None
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
