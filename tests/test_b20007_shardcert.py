# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5640 item 1 (S27-60, S27-93) and #5977: failing-test halves for fixes already on main.

S27-60: a teardown step of the two-box halves that fails is logged, and the later steps still run.
S27-93: ``build_corpus`` runs off the event loop thread in the driver and the driver worker. The
finding's other half, the synchronous ``FileDropCoord`` I/O, was recorded as not a bug in engine PR
2913 (tiny files) and is not tested here.
#5977: the multi-process drive polls the engine box over https with the remote rig session.
#5576's table-scan widening is in tests/test_shardcert_pass_bars.py.

Every network collaborator is faked, through the two-box suite's own fakes. Synthetic data only.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import logging
import textwrap
import threading
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import harness.load.shardcert as sc
from harness.load.coord import DRIVE_COMPLETE, DRIVE_GO, SINK_DONE, FileDropCoord
from harness.load.corpus import build_corpus
from harness.load.rigadmin import REMOTE_RIG_SESSION
from tests.test_shardcert_multiproc import _install_coordinator_fakes
from tests.test_shardcert_two_box import _install_fakes, _post_ready

_TEARDOWN = "shardcert teardown:"


def _raise(label: str) -> Any:
    async def failing(self: Any, *_a: Any, **_k: Any) -> None:
        raise OSError(f"synthetic {label} failure")

    return failing


def _fail_sender_teardown(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Each sender's stop records its grace and raises on the teardown stop (grace 0.5), not on the
    in-band ``stop(2.0)`` before the drain. Returns the recorded graces. Call it after
    ``_install_fakes``: the string path patches whatever ``PersistentConnection`` is installed."""
    stopped: list[float] = []

    async def sender_stop(self: Any, grace: float) -> None:
        stopped.append(grace)
        if grace == 0.5:
            raise OSError("synthetic sender failure")

    monkeypatch.setattr("harness.load.shardcert.PersistentConnection.stop", sender_stop)
    return stopped


class _Lines(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.getMessage().startswith(_TEARDOWN):
            self.lines.append(record.getMessage())


@contextlib.contextmanager
def _teardown_log() -> Iterator[list[str]]:
    """The teardown lines, captured by a handler on the emitting logger itself, so a capture that
    an earlier test's logging config detached from the root cannot lose them."""
    logger = logging.getLogger(sc.__name__)
    handler = _Lines()
    disabled, level = logger.disabled, logger.level
    logger.disabled = False
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        logger.removeHandler(handler)
        logger.disabled, logger.level = disabled, level


# --- S27-60: a failed teardown step is logged, and the rest still run -------------------------------


async def test_driver_logs_each_failed_teardown_step_and_runs_the_rest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """BACKLOG #5640 S27-60: the driver's finally block wrapped ``poller.close()``, each sender's
    ``stop`` and ``sink.stop()`` in ``contextlib.suppress(Exception)``, so a failed teardown left no
    trace. Each is now logged, and every later step still runs.

    Mutation: make ``_teardown_step`` suppress without logging (the code before engine PR 2913).
    Red: no teardown line is logged."""
    _install_fakes(monkeypatch)
    stopped = _fail_sender_teardown(monkeypatch)
    monkeypatch.setattr("harness.load.shardcert.EnginePoller.close", _raise("poller"))
    monkeypatch.setattr("harness.load.shardcert.CorrelationSink.stop", _raise("sink"))
    coord = FileDropCoord(tmp_path, run_id="teardown")
    _post_ready(coord)
    with _teardown_log() as lines:
        report = await sc.run_shardcert_driver(
            engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
        )
    assert report.drained
    assert any("drain poller close failed: OSError: synthetic poller failure" in m for m in lines)
    assert sum("sender stop failed" in m for m in lines) == 2, lines
    assert any("sink stop failed: OSError: synthetic sink failure" in m for m in lines)
    # Both engine shards' senders reached their teardown stop, though the first one raised.
    assert stopped.count(0.5) == 2, stopped


async def test_sink_logs_a_failed_stop(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """BACKLOG #5640 S27-60: the sink tier's ``sink.stop()`` is logged when it fails, and the sink
    still reports its tally.

    Mutation: as above. Red: no teardown line is logged."""
    _install_fakes(monkeypatch)
    monkeypatch.setattr("harness.load.shardcert.CorrelationSink.stop", _raise("sink"))
    coord = FileDropCoord(tmp_path, run_id="sinkstop")
    coord.post(DRIVE_COMPLETE, {})
    with _teardown_log() as lines:
        report = await sc.run_shardcert_sink(
            sink_base=3700,
            sink_ports=1,
            sink_index=0,
            sink_count=1,
            coord=coord,
            drive_complete_timeout=1.0,
            post_complete_grace=0.0,
        )
    assert any("sink stop failed: OSError: synthetic sink failure" in m for m in lines)
    # The sink still posted its tally after the failed stop.
    assert coord.read(f"{SINK_DONE}.0") is not None
    assert report.sink_index == 0


async def test_driver_worker_logs_a_failed_sender_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """BACKLOG #5640 S27-60: the sender tier's teardown ``stop`` is logged for each sender that
    fails, and every sender is still stopped.

    Mutation: as above. Red: no teardown line is logged."""
    _install_fakes(monkeypatch)
    stopped = _fail_sender_teardown(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="workerstop")
    _post_ready(coord)
    coord.post(DRIVE_GO, {})
    with _teardown_log() as lines:
        await sc.run_shardcert_driver_worker(
            engine_host="10.0.0.5",
            aggregate_rate=20.0,
            hold_seconds=0.05,
            driver_index=0,
            driver_count=1,
            coord=coord,
            drive_go_timeout=1.0,
        )
    assert sum("sender stop failed" in m for m in lines) == 2, lines
    assert stopped.count(0.5) == 2, stopped


#: The teardown steps each S27-60 site logs through ``_teardown_step``, by its label.
_S27_60_SITES = {
    "run_shardcert_driver": {"drain poller close", "sender stop", "sink stop"},
    "run_shardcert_sink": {"sink stop"},
    "run_shardcert_driver_worker": {"sender stop"},
    "run_shardcert_drive": {"drain poller close"},
}


def _unlogged_teardowns(source: str) -> list[str]:
    """Each ``close``/``stop`` await in a finally block that is swallowed without a log: inside a
    ``suppress`` block, or in a ``try`` whose handler only passes. Any receiver name counts."""

    def teardown_call(node: ast.AST) -> bool:
        return any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("close", "stop")
            for n in ast.walk(node)
        )

    found: list[str] = []
    for node in ast.walk(ast.parse(textwrap.dedent(source))):
        if not isinstance(node, ast.Try):
            continue
        for stmt in node.finalbody:
            for sub in ast.walk(stmt):
                swallowed = (
                    isinstance(sub, ast.With)
                    and any("suppress" in ast.unparse(item.context_expr) for item in sub.items)
                ) or (
                    isinstance(sub, ast.Try)
                    and any(all(isinstance(s, ast.Pass) for s in h.body) for h in sub.handlers)
                )
                if swallowed and teardown_call(sub):
                    found.append(ast.unparse(sub))
    return found


def _teardown_labels(source: str) -> set[str]:
    return {
        str(node.args[0].value)
        for node in ast.walk(ast.parse(textwrap.dedent(source)))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_teardown_step"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }


def test_s27_60_sites_log_every_teardown_step() -> None:
    """BACKLOG #5640 S27-60, including the fourth site, the multi-process drive's ``poller.close()``,
    which the tests above do not run. Each of the four functions S27-60 names logs its teardown
    steps through ``_teardown_step``, and swallows no ``close``/``stop`` unlogged in a finally block.
    Other functions in the module are not checked here, the engine half's ``node.stop()`` included.

    Mutation: replace a ``_teardown_step`` call with ``with contextlib.suppress(Exception): await
    poller.close()``. Red: the function is named, and its label is missing."""
    controls = (
        "try:\n    pass\nfinally:\n    with contextlib.suppress(Exception):\n        await p.close()",
        "try:\n    pass\nfinally:\n    try:\n        await self._sink.stop()\n"
        "    except Exception:\n        pass",
    )
    for control in controls:  # the instrument sees both swallow forms, whatever the receiver
        assert _unlogged_teardowns(control), control
    for name, labels in _S27_60_SITES.items():
        source = inspect.getsource(getattr(sc, name))
        assert _unlogged_teardowns(source) == [], name
        assert labels <= _teardown_labels(source), (name, labels - _teardown_labels(source))


# --- S27-93: build_corpus runs off the event loop ----------------------------------------------------


def _record_corpus_thread(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    threads: list[int] = []
    real = build_corpus

    def recording(*args: Any, **kwargs: Any) -> Any:
        threads.append(threading.get_ident())
        return real(*args, **kwargs)

    monkeypatch.setattr(sc, "build_corpus", recording)
    return threads


async def test_driver_builds_its_corpus_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """BACKLOG #5640 S27-93: the driver built its corpus, CPU work, on the event loop thread.

    Mutation: call ``build_corpus`` directly (the code before engine PR 2913). Red: the build ran
    on the loop's thread."""
    _install_fakes(monkeypatch)
    threads = _record_corpus_thread(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="corpus")
    _post_ready(coord)
    await sc.run_shardcert_driver(
        engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
    )
    assert threads and threading.get_ident() not in threads, threads


async def test_driver_worker_builds_its_corpus_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """BACKLOG #5640 S27-93: as above, for the sender tier.

    Mutation: as above. Red: the build ran on the loop's thread."""
    _install_fakes(monkeypatch)
    threads = _record_corpus_thread(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="wcorpus")
    _post_ready(coord)
    coord.post(DRIVE_GO, {})
    await sc.run_shardcert_driver_worker(
        engine_host="10.0.0.5",
        aggregate_rate=20.0,
        hold_seconds=0.05,
        driver_index=0,
        driver_count=1,
        coord=coord,
        drive_go_timeout=1.0,
    )
    assert threads and threading.get_ident() not in threads, threads


# --- #5977: the multi-process drive polls the engine box over https with the rig session ------------


class _PollerBuilt(Exception):
    """Ends the drive once its drain poller is built: the test reads only how it was built."""


async def test_drive_polls_the_engine_box_over_https_with_the_rig_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """BACKLOG #5977: the drive built its drain poller over ``http://`` with no session, against an
    engine box that serves TLS with sign-in on. It now takes the engine box's https URLs and the
    remote rig session. Only arguments every version of the drive takes are passed, so this test
    also runs against the code before engine PR 2913.

    Red on engine ``f67d8c818f8^1``: the poller is built with ``http://`` URLs and a ``None`` token.
    The tallies feed the code before that fix, which spawned its children before it built the poller.
    tests/test_shardcert_multiproc.py pins the same wiring with the arguments added since."""
    tally = {0: {"sent": 1, "acked": 1, "ack_p50_ms": 1.0, "ack_p99_ms": 1.0, "bands": [0]}}
    sinks = {
        0: {
            "sink_received": 1,
            "lane_inversions": 0,
            "lane_repeats": 0,
            "lanes_observed": 1,
            "ports": [3700],
        }
    }
    _install_coordinator_fakes(
        monkeypatch,
        sink_tally=sinks,
        worker_tally=tally,
        engine_final=types.SimpleNamespace(done=1, dead=0, in_pipeline=0),
    )
    built: list[tuple[list[str], Any]] = []

    class RecordingPoller:
        def __init__(self, urls: Any, token: Any = None, **_kw: Any) -> None:
            built.append((list(urls), token))
            raise _PollerBuilt

    monkeypatch.setattr(sc, "EnginePoller", RecordingPoller)
    coord = FileDropCoord(tmp_path, run_id="tls5977")
    _post_ready(coord, dests=1, handlers=1, delivering=1)
    with pytest.raises(_PollerBuilt):
        await sc.run_shardcert_drive(
            engine_host="10.0.0.5",
            aggregate_rate=20.0,
            hold_seconds=0.05,
            driver_count=1,
            sink_count=1,
            sink_host="10.0.0.9",
            coord=coord,
        )
    assert built == [(["https://10.0.0.5:9001", "https://10.0.0.5:9002"], REMOTE_RIG_SESSION)]
