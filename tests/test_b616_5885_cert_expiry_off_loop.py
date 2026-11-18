# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5885: the supervised cert-expiry pass must not block the event loop.

The blocking half of a pass (``gc.collect``, file reads, parsing, CRL staging) runs in a worker
thread, so the loop keeps serving while it runs. The alerts are raised back on the loop thread,
because the engine's alert sinks are loop-bound."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.pipeline.cert_expiry import CertCheck, CertExpiryRunner, MonitoredCert


class _ThreadRecordingSink:
    def __init__(self) -> None:
        self.cert_threads: list[int] = []
        self.emitted = asyncio.Event()

    def cert_expiry(self, name: str, **_: Any) -> None:
        self.cert_threads.append(threading.get_ident())
        self.emitted.set()


async def test_pass_collects_off_the_loop_and_alerts_on_it(monkeypatch: pytest.MonkeyPatch) -> None:
    loop_thread = threading.get_ident()
    sink = _ThreadRecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("api", "synthetic/api.pem")],
        CertMonitorSettings(warn_days=30, check_interval_seconds=3600.0),
        alert_sink=sink,  # type: ignore[arg-type]
    )
    # The inspection blocks until the loop has run a task. On the loop thread that wait could never
    # be met, so it times out: the stall the row describes.
    loop_ran = threading.Event()
    inspect_threads: list[int] = []
    waited: list[bool] = []

    def blocking_inspect(
        cert: MonitoredCert, now: float, held: object, *, said: object
    ) -> CertCheck:
        inspect_threads.append(threading.get_ident())
        waited.append(loop_ran.wait(timeout=2.0))
        return CertCheck(cert.label, cert.path, "2026-12-01T00:00:00Z", 3)

    monkeypatch.setattr(runner, "_inspect", blocking_inspect)

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
    assert sink.cert_threads == [loop_thread]


def test_run_once_stays_synchronous() -> None:
    sink = _ThreadRecordingSink()
    runner = CertExpiryRunner(
        lambda: [MonitoredCert("api", "synthetic/missing.pem")],
        CertMonitorSettings(warn_days=30),
        alert_sink=sink,  # type: ignore[arg-type]
    )
    assert runner.run_once(now=0.0) == []
    assert sink.cert_threads == []
