# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A refused sandbox worker raises one ``sandbox_worker_refused`` alert (vault BACKLOG #2724).

Owner ruling 2026-10-16: alert, keep dead-letter. A config file edited on disk with no reload makes
the next ``[sandbox].mode = "subprocess"`` worker refuse. The message in hand still fails as before;
these tests pin that an operator is also told, once per refusal and not once per message, and that
the alert carries fixed words and no message content.

Synthetic HL7 only.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.run_context import RunContext
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    EgressSettings,
)
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink, sandbox_worker_refused_detail
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.sandbox import (
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    SandboxWorkerRefused,
    graph_shape,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStore
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_sandbox import RAW
from tests.test_sandbox_graph_parity import _GRAPH, _VARIABLE

#: A value of the message's own that must never reach an alert.
_BODY_MARKER = "DOE^JANE"
assert _BODY_MARKER in RAW


class _Recorder:
    """Records ``sandbox_worker_refused`` and nothing else; any other alert is a test failure."""

    def __init__(self) -> None:
        self.refused: list[tuple[str, bool]] = []

    def sandbox_worker_refused(self, name: str, *, content_only: bool) -> None:
        self.refused.append((name, content_only))


@pytest.fixture
def edited_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config the engine loaded, whose Handler body was then edited on disk with no reload."""
    monkeypatch.delenv(_VARIABLE, raising=False)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "graph.py").write_text(_GRAPH, encoding="utf-8")
    return cfg


def _edit(cfg: Path) -> None:
    (cfg / "graph.py").write_text(_GRAPH.replace('"COUNT="', '"EDITED="'), encoding="utf-8")


async def test_the_first_refusal_alerts_once_and_later_messages_do_not(
    edited_config: Path, tmp_path: Path
) -> None:
    """Through the runner's own dispatch chokepoint: the refusal still raises (the message still
    fails and dead-letters under the policy), the alert fires on the first, and the cached
    refusals for the next messages on the same inbound raise no second alert."""
    registry = load_config(edited_config)
    _edit(edited_config)
    sink = _Recorder()
    store = await MessageStore.open(tmp_path / "refusal.db")
    try:
        runner = RegistryRunner(
            registry,
            store,
            sandbox_policy=SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
            sandbox_config_source=(str(edited_config), None),
            egress=EgressSettings(deny_by_default=False),
            alert_sink=cast(Any, sink),
        )
        try:
            for _ in range(3):
                with pytest.raises(SandboxWorkerRefused):
                    await runner._off_loop_sandboxed(
                        "IB_PARITY", transform_one, registry, "h_0", RAW, run_context=RunContext()
                    )
            assert sink.refused == [("IB_PARITY", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


def test_only_the_comparing_spawn_is_marked_first(edited_config: Path) -> None:
    serving = graph_shape(load_config(edited_config))  # one object, as the runner caches it
    _edit(edited_config)
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        inbound="IB_PARITY",
        config_dir=edited_config,
        env=None,
        graph=lambda: serving,
    )
    try:
        with pytest.raises(SandboxWorkerRefused) as first:
            session._spawn()
        with pytest.raises(SandboxWorkerRefused) as cached:
            session._spawn()
    finally:
        session.close()
    assert (first.value.first, first.value.content_only) == (True, True)
    assert (cached.value.first, cached.value.content_only) == (False, True)


async def test_the_shipped_notifier_carries_fixed_words_and_no_body(
    edited_config: Path, tmp_path: Path
) -> None:
    """What an operator's webhook receives and what the alert list shows. The CONTROL is the
    refusal itself, which the message's last error carries: it names what differs."""
    registry = load_config(edited_config)
    _edit(edited_config)
    transport, state = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, state))
    store = await MessageStore.open(tmp_path / "notifier.db")
    try:
        runner = RegistryRunner(
            registry,
            store,
            sandbox_policy=SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
            sandbox_config_source=(str(edited_config), None),
            egress=EgressSettings(deny_by_default=False),
            alert_sink=sink,
        )
        try:
            with pytest.raises(SandboxWorkerRefused) as refused:
                await runner._off_loop_sandboxed(
                    "IB_PARITY", transform_one, registry, "h_0", RAW, run_context=RunContext()
                )
        finally:
            await runner._close_sandbox_sessions()
        await _drain_state(sink)
        await _drain_transports(sink)
    finally:
        await store.close()

    assert "config module content" in str(refused.value)
    (event,) = transport.events
    (row,) = state.upserts
    assert set(event) == {"type", "connection", "detail", "ts", "severity"}
    assert (event["type"], event["connection"]) == ("sandbox_worker_refused", "IB_PARITY")
    assert event["detail"] == row["reason"] == sandbox_worker_refused_detail(content_only=True)
    for carrier in (repr(event), repr(state.upserts)):
        assert _BODY_MARKER not in carrier
        assert "MSH|" not in carrier


def test_the_detail_names_the_cause_and_the_remedy_first() -> None:
    edited = sandbox_worker_refused_detail(content_only=True)
    names = sandbox_worker_refused_detail(content_only=False)
    # The alert instance's reason column keeps about the first 200 characters.
    for detail in (edited, names):
        assert "reload the config" in detail[:200].lower()
    assert "changed on disk" in edited[:200] and "pass_environment" not in edited
    assert "[sandbox].pass_environment" in names[:200]


def test_the_logging_sink_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().sandbox_worker_refused("IB_PARITY", content_only=True)
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert record.getMessage().startswith(
        "ALERT sandbox_worker_refused: inbound 'IB_PARITY' sandbox worker refused: a config file"
    )


def test_a_rule_can_route_it_but_not_restart_on_it() -> None:
    assert "sandbox_worker_refused" in _ALERT_EVENT_TYPES
    assert "sandbox_worker_refused" not in _ALERT_CONTROL_EVENT_TYPES
