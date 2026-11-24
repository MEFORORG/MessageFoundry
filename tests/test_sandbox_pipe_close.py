# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reaped sandbox worker's pipes are closed by the engine, not left to the garbage collector,
and a worker that outlives the reap's wait says so (BACKLOG #6831)."""

from __future__ import annotations

import gc
import io
import logging
import queue
import subprocess
import threading
import time
import warnings
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import sandbox as sandbox_mod
from messagefoundry.pipeline.dryrun import transform_one
from tests.test_sandbox import RAW, _session, graph  # noqa: F401 - graph is a fixture


def test_close_closes_the_workers_pipes(graph: tuple[Registry, str]) -> None:  # noqa: F811
    """After ``close`` the worker's stdin, stdout and stderr are all closed: the stdin by the reap,
    and each drain's stream by its own thread once it reads EOF."""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        transform_one(registry, "h_ok", RAW, sandbox=session, run_context=RunContext())
        proc = session._proc
        assert proc is not None and proc.stdin is not None
        threads = list(session._threads)
    finally:
        session.close()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert proc.stdin is not None and proc.stdin.closed
    assert proc.stdout is not None and proc.stdout.closed
    assert proc.stderr is not None and proc.stderr.closed


def test_a_closed_worker_leaves_no_unclosed_file_for_the_collector(
    graph: tuple[Registry, str],  # noqa: F811
) -> None:
    """The observable cost of leaving the pipes open: the collector closes them and raises a
    ``ResourceWarning`` for each one."""
    registry, config_dir = graph
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        session = _session(config_dir)
        try:
            transform_one(registry, "h_ok", RAW, sandbox=session, run_context=RunContext())
            threads = list(session._threads)
            proc = session._proc
            assert proc is not None
            pipes = (proc.stdin, proc.stdout, proc.stderr)
            # This worker's pipes, by descriptor: another test's unclosed file is not this one's.
            names = {f"name={pipe.fileno()} " for pipe in pipes if pipe is not None}
            del proc, pipes
        finally:
            session.close()
        for thread in threads:
            thread.join(timeout=10)
        del session, threads
        gc.collect()
    assert len(names) == 3
    unclosed = [
        str(w.message)
        for w in caught
        if issubclass(w.category, ResourceWarning) and any(n in str(w.message) for n in names)
    ]
    assert unclosed == [], unclosed


def test_a_worker_still_running_after_the_reaps_wait_is_logged(
    graph: tuple[Registry, str],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A wait that times out after the tree kill is not swallowed: a WARNING names the inbound and
    the pid, and the reap goes on as before."""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        transform_one(registry, "h_ok", RAW, sandbox=session, run_context=RunContext())
        proc = session._proc
        assert proc is not None
        real_wait = proc.wait
        calls: list[Any] = []

        def wait(timeout: float | None = None) -> int:
            calls.append(timeout)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(proc.args, timeout or 0.0)
            return real_wait(timeout)

        monkeypatch.setattr(proc, "wait", wait)
        with caplog.at_level(logging.WARNING, logger=sandbox_mod.log.name):
            session._reap(proc)
    finally:
        session.close()
    assert calls and calls[0] == sandbox_mod._REAP_WAIT_SECONDS
    assert session._proc is None
    lines = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("'IB_T'" in line and str(proc.pid) in line for line in lines), lines
    real_wait(10)


def test_the_drains_close_their_stream_at_eof(tmp_path: Path) -> None:
    """Each drain owns its stream and closes it when it ends, so nothing else has to."""
    out = io.BytesIO(b"")
    sink: queue.Queue[Any] = queue.Queue()
    _session(str(tmp_path))._reader_loop(out, sink)
    assert out.closed
    err = io.BytesIO(b"partial line")
    sandbox_mod._StderrRelay("IB_T", 1, 1).run(err)
    assert err.closed


class _FakeWorker:
    """Hashable, with the one attribute the lookup path reads."""

    def __init__(self) -> None:
        self.stdin = io.BytesIO()


@pytest.mark.parametrize("abandoned", [True, False], ids=["given_up_on", "ended_in_time"])
def test_the_request_pipe_has_exactly_one_closer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, abandoned: bool
) -> None:
    """A lookup helper its dispatch gave up on may still be writing the request pipe, so the reap
    leaves the pipe to that helper, which closes it when it ends; a helper that ended in time
    leaves it to the reap (BACKLOG #6831)."""
    session = _session(str(tmp_path))
    worker: Any = _FakeWorker()  # stands in for the Popen the lookup path reads stdin off
    release = threading.Event()

    def reply(*_args: Any) -> bytes:
        if abandoned:
            assert release.wait(10)
        return b""

    monkeypatch.setattr(session, "_lookup_reply", reply)
    monkeypatch.setattr(sandbox_mod, "_write_frame", lambda stream, body: None)
    deadline = time.monotonic() + (0.2 if abandoned else 10.0)
    served = session._serve_bounded(worker, "rid", "transform", "h", cast(Any, None), deadline)
    assert served is not abandoned
    if abandoned:
        assert worker in session._stdin_held  # the reap must not close it under the helper
        assert not worker.stdin.closed
        release.set()
        for _ in range(200):
            if worker not in session._stdin_held:
                break
            time.sleep(0.05)
        assert worker not in session._stdin_held
        assert worker.stdin.closed  # the helper closed it when it ended
    else:
        assert worker not in session._stdin_held  # the reap closes it
        assert not worker.stdin.closed
