# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5885: the supervised cert-expiry pass must not block the event loop.

The file half of a pass (the reads, parsing, CRL staging) runs in a worker thread, so the loop
keeps serving while it runs. The held-copy snapshot and its ``gc.collect`` stay on the loop, since
the collect runs finalizers of loop-bound objects, and the collect is skipped when no context
holds a copy. The alerts are raised back on the loop thread, because the engine's alert sinks are
loop-bound."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.loaded_crls import HeldCrlSnapshot
from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.pipeline import cert_expiry
from messagefoundry.pipeline.cert_expiry import CertCheck, CertExpiryRunner, MonitoredCert


class _ThreadRecordingSink:
    def __init__(self) -> None:
        self.cert_threads: list[int] = []
        self.emitted = asyncio.Event()

    def cert_expiry(self, name: str, **_: Any) -> None:
        self.cert_threads.append(threading.get_ident())
        self.emitted.set()


def _runner(
    sink: _ThreadRecordingSink, *rows: MonitoredCert, watch: bool = False
) -> CertExpiryRunner:
    return CertExpiryRunner(
        lambda: list(rows),
        CertMonitorSettings(warn_days=30, check_interval_seconds=3600.0),
        alert_sink=sink,  # type: ignore[arg-type]
        watch_unlisted_held_crls=watch,
    )


def _in_window(cert: MonitoredCert) -> CertCheck:
    return CertCheck(cert.label, cert.path, "2026-12-01T00:00:00Z", 3)


async def test_pass_reads_files_off_the_loop_and_alerts_on_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop_thread = threading.get_ident()
    sink = _ThreadRecordingSink()
    runner = _runner(sink, MonitoredCert("api", "synthetic/api.pem"))
    # The inspection blocks until the loop has run a task. On the loop thread that wait could never
    # be met, so it times out: the stall the row describes.
    loop_ran = threading.Event()
    inspect_threads: list[int] = []
    snapshot_threads: list[int] = []
    waited: list[bool] = []

    def blocking_inspect(
        cert: MonitoredCert, now: float, held: object, *, said: object
    ) -> CertCheck:
        inspect_threads.append(threading.get_ident())
        waited.append(loop_ran.wait(timeout=2.0))
        return _in_window(cert)

    def snapshot() -> HeldCrlSnapshot:
        snapshot_threads.append(threading.get_ident())
        return HeldCrlSnapshot(())

    monkeypatch.setattr(runner, "_inspect", blocking_inspect)
    monkeypatch.setattr(runner, "_held_snapshot", snapshot)

    async def tick() -> None:
        await asyncio.sleep(0)
        loop_ran.set()

    ticker = asyncio.create_task(tick())
    runner.start()
    try:
        await asyncio.wait_for(sink.emitted.wait(), timeout=10.0)
    finally:
        await runner.stop()
        await ticker

    assert waited == [True], "the loop could not run while the scan inspected a file"
    assert inspect_threads and inspect_threads[0] != loop_thread
    assert snapshot_threads == [loop_thread]  # its gc.collect finalizers belong on the loop
    assert sink.cert_threads == [loop_thread]


def test_run_once_alerts_before_it_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = _ThreadRecordingSink()
    runner = _runner(sink, MonitoredCert("api", "synthetic/api.pem"))
    monkeypatch.setattr(runner, "_inspect", lambda cert, *a, **k: _in_window(cert))
    assert [c.label for c in runner.run_once(now=0.0)] == ["api"]
    assert sink.cert_threads == [threading.get_ident()]


def test_a_row_that_raises_does_not_drop_the_alerts_judged_before_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink = _ThreadRecordingSink()
    runner = _runner(
        sink, MonitoredCert("api", "synthetic/a.pem"), MonitoredCert("b", "synthetic/b.pem")
    )

    def inspect(cert: MonitoredCert, *args: Any, **kwargs: Any) -> CertCheck:
        if cert.label == "b":
            raise RuntimeError("synthetic")
        return _in_window(cert)

    monkeypatch.setattr(runner, "_inspect", inspect)
    assert [c.label for c in runner.run_once(now=0.0)] == ["api"]
    assert len(sink.cert_threads) == 1


def test_a_stopped_pass_ends_at_the_next_row(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = _ThreadRecordingSink()
    runner = _runner(
        sink, MonitoredCert("a", "synthetic/a.pem"), MonitoredCert("b", "synthetic/b.pem")
    )
    seen: list[str] = []

    def inspect(cert: MonitoredCert, *args: Any, **kwargs: Any) -> CertCheck:
        seen.append(cert.label)
        runner._stop.set()  # stop() lands while the first row is judged
        return _in_window(cert)

    monkeypatch.setattr(runner, "_inspect", inspect)
    checks, _ = runner._collect(
        0.0, list(runner._cert_source()), HeldCrlSnapshot(()), stoppable=True
    )
    assert seen == ["a"]
    assert [c.label for c in checks] == ["a"]


@pytest.mark.parametrize(("held", "collects"), [(False, 0), (True, 1)])
def test_the_collect_runs_only_while_a_context_holds_a_copy(
    monkeypatch: pytest.MonkeyPatch, held: bool, collects: int
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(cert_expiry, "has_held_copies", lambda: held)
    # A stand-in module, so the real collector is never patched process-wide.
    monkeypatch.setattr(cert_expiry, "gc", SimpleNamespace(collect=lambda: calls.append(1)))
    _runner(_ThreadRecordingSink(), watch=True)._held_snapshot()
    assert len(calls) == collects
