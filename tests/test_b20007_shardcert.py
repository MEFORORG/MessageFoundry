# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5640 item 1 (S27-60, S27-93) and #5576: failing-test halves for fixes already on main.

S27-60: a teardown step of the two-box halves that fails is logged, and the later steps still run.
S27-93: ``build_corpus`` runs off the event loop thread in the driver and the driver worker.

Every network collaborator is faked, through the two-box suite's own fakes. Synthetic data only.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import logging
import re
import textwrap
import threading
import types
from pathlib import Path
from typing import Any

import pytest

import harness.load.shardcert as sc
from harness.load.coord import DRIVE_COMPLETE, DRIVE_GO, FileDropCoord
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
    in-band ``stop(2.0)`` before the drain. Returns the recorded graces."""
    stopped: list[float] = []

    async def sender_stop(self: Any, grace: float) -> None:
        stopped.append(grace)
        if grace == 0.5:
            raise OSError("synthetic sender failure")

    monkeypatch.setattr("harness.load.shardcert.PersistentConnection.stop", sender_stop)
    return stopped


def _teardown_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.getMessage().startswith(_TEARDOWN)]


# --- S27-60: a failed teardown step is logged, and the rest still run -------------------------------


async def test_driver_logs_each_failed_teardown_step_and_runs_the_rest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
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
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        report = await sc.run_shardcert_driver(
            engine_host="10.0.0.5", hold_seconds=0.05, drain_timeout=1.0, coord=coord
        )
    assert report.drained
    lines = _teardown_lines(caplog)
    assert any("drain poller close failed: OSError: synthetic poller failure" in m for m in lines)
    assert sum("sender stop failed" in m for m in lines) == 2, lines
    assert any("sink stop failed: OSError: synthetic sink failure" in m for m in lines)
    # Both shards' senders reached their teardown stop, though the first one raised.
    assert stopped.count(0.5) == 2, stopped


async def test_sink_logs_a_failed_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5640 S27-60: the sink tier's ``sink.stop()`` is logged when it fails, and the sink
    still reports its tally.

    Mutation: as above. Red: no teardown line is logged."""
    _install_fakes(monkeypatch)
    monkeypatch.setattr("harness.load.shardcert.CorrelationSink.stop", _raise("sink"))
    coord = FileDropCoord(tmp_path, run_id="sinkstop")
    coord.post(DRIVE_COMPLETE, {})
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        report = await sc.run_shardcert_sink(
            sink_base=3700,
            sink_ports=1,
            sink_index=0,
            sink_count=1,
            coord=coord,
            drive_complete_timeout=1.0,
            post_complete_grace=0.0,
        )
    assert report is not None
    assert any(
        "sink stop failed: OSError: synthetic sink failure" in m for m in _teardown_lines(caplog)
    )


async def test_driver_worker_logs_a_failed_sender_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5640 S27-60: the sender tier's teardown ``stop`` is logged for each sender that
    fails, and every sender is still stopped.

    Mutation: as above. Red: no teardown line is logged."""
    _install_fakes(monkeypatch)
    stopped = _fail_sender_teardown(monkeypatch)
    coord = FileDropCoord(tmp_path, run_id="workerstop")
    _post_ready(coord)
    coord.post(DRIVE_GO, {})
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        await sc.run_shardcert_driver_worker(
            engine_host="10.0.0.5",
            aggregate_rate=20.0,
            hold_seconds=0.05,
            driver_index=0,
            driver_count=1,
            coord=coord,
            drive_go_timeout=1.0,
        )
    assert sum("sender stop failed" in m for m in _teardown_lines(caplog)) == 2
    assert stopped.count(0.5) == 2, stopped


def test_no_two_box_finally_block_suppresses_a_teardown_unlogged() -> None:
    """BACKLOG #5640 S27-60, the fourth site: the multi-process drive's ``poller.close()``. No
    finally block in the four functions S27-60 names wraps a ``close``/``stop`` on the poller, a
    sender or the sink in ``contextlib.suppress``; each goes through the logging ``_teardown_step``.

    Mutation: put ``with contextlib.suppress(Exception): await poller.close()`` back in any of
    them. Red: the function is named."""

    def suppressed_teardowns(fn: Any) -> list[str]:
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        found: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            for stmt in node.finalbody:
                for sub in ast.walk(stmt):
                    if not isinstance(sub, ast.With):
                        continue
                    if not any("suppress" in ast.unparse(item.context_expr) for item in sub.items):
                        continue
                    body = ast.unparse(sub)
                    if re.search(r"\b(poller|pc|sink|c)\.(close|stop)\(", body):
                        found.append(body)
        return found

    # The instrument sees the shape it is looking for.
    def _control(poller: Any) -> None:  # pragma: no cover - parsed, never run
        try:
            pass
        finally:
            with contextlib.suppress(Exception):
                poller.close()

    assert suppressed_teardowns(_control)
    for fn in (
        sc.run_shardcert_driver,
        sc.run_shardcert_sink,
        sc.run_shardcert_driver_worker,
        sc.run_shardcert_drive,
    ):
        assert suppressed_teardowns(fn) == [], fn.__name__


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

    Red on engine ``f67d8c818f8^1``: the poller is built with ``http://`` URLs and a ``None`` token."""
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
