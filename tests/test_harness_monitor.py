# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The harness Monitor tab: it builds disconnected, and observes a running engine over the API.

Like ``test_console_client``, this starts a real managed app (engine + API, auth disabled) in a
background uvicorn thread, then drives the GUI panel: connecting starts the off-thread poller,
which must populate the live connections table, and the reused message list must show the
delivered message with its disposition.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import pytest
import uvicorn

pytest.importorskip("PySide6")

from messagefoundry.api import create_managed_app  # noqa: E402
from harness.monitor import MonitorPanel  # noqa: E402

ADT = "MSH|^~\\&|APP|FAC|RAPP|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _write_config(config_dir: Path, inbox: Path, outdir: Path) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    module = f'''\
from messagefoundry import File, Send, handler, inbound, outbound, router

inbound("in", File(directory="{inbox.as_posix()}", pattern="*.hl7", poll_seconds=0.05), router="r")
outbound("archive", File(directory="{outdir.as_posix()}", filename="{{MSH-10}}.hl7"))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("archive", msg)
'''
    (config_dir / "cfg.py").write_text(module, encoding="utf-8")


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _write_config(tmp_path / "config", inbox, outdir)
    app = create_managed_app(
        db_path=tmp_path / "console.db", config_dir=tmp_path / "config", poll_interval=0.05
    )
    port = _free_port()
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started:
        time.sleep(0.05)
        if time.time() > deadline:
            raise RuntimeError("server did not start")
    try:
        yield f"http://127.0.0.1:{port}", inbox
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _spin(qapp: Any, predicate: Any, timeout: float = 30.0) -> None:
    # 30s (was 10s): the predicate just needs the off-thread poller + file-poll + engine
    # processing + API round-trips + a Qt event-loop turn to complete. That's a few seconds
    # locally, but a loaded Windows CI runner intermittently overran 10s — a timing flake
    # (BACKLOG #17), not a real failure. The generous deadline only ever extends a SLOW pass;
    # a genuine hang still fails fast (predicate never true) well within the per-test watchdog.
    deadline = time.time() + timeout
    while not predicate():
        qapp.processEvents()
        time.sleep(0.05)
        if time.time() > deadline:
            raise AssertionError("condition not met within timeout")


def test_poller_cancel_abandons_remaining_calls(qapp: Any) -> None:
    # low-25: a cancel (set from the GUI thread before the blocking stop) must short-circuit the
    # 3-call poll so shutdown waits at most for the one call already on the wire.
    from harness.monitor import MonitorPoller

    poller = MonitorPoller("http://127.0.0.1:1", None)

    class CountingClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def stats(self) -> Any:
            self.calls.append("stats")
            poller.request_cancel()  # cancel arrives mid-poll, after the first call
            return type("S", (), {"outbox_by_status": {}})()

        def connections(self) -> list[Any]:
            self.calls.append("connections")
            return []

        def list_dead_letters(self, **k: Any) -> Any:
            self.calls.append("dead")
            return type("D", (), {"dead_letters": []})()

    client = CountingClient()
    poller._client = client  # type: ignore[assignment]
    emitted: list[Any] = []
    poller.snapshot.connect(lambda s: emitted.append(s))
    poller._poll()
    assert client.calls == ["stats"]  # cancel skipped connections + dead-letters
    assert emitted == []  # and no snapshot was emitted

    # A cancel before the poll even starts makes it a no-op.
    poller._cancelled = True
    client.calls.clear()
    poller._poll()
    assert client.calls == []


def test_monitor_panel_builds_disconnected(qapp: Any) -> None:
    panel = MonitorPanel()
    assert panel._client is None
    assert panel._body.currentIndex() == 0  # the "not connected" placeholder
    panel.shutdown()  # safe to call when never connected


# Override the global 60s per-test watchdog: this test makes two sequential _spin waits (30s each
# worst case) plus fixture/engine startup, so a slow-but-passing CI run could otherwise brush the
# 60s cap. 120s keeps an ample backstop without the watchdog itself becoming the flake.
# In-run auto-retry for the residual timing flake (BACKLOG #17): even with the 30s _spin + 120s
# watchdog, a heavily-loaded Windows runner still intermittently overran the _spin deadline. reruns=2
# lets a single flake occurrence self-heal within the SAME CI run (up to 3 attempts) instead of reding
# the matrix and blocking the auto-merge pipeline; a genuine break still fails all attempts.
@pytest.mark.flaky(reruns=2)
@pytest.mark.timeout(120)
def test_monitor_observes_engine(qapp: Any, server: tuple[str, Path]) -> None:
    url, inbox = server
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    panel = MonitorPanel()
    panel._url.setText(url)
    panel._connect_btn.click()  # connects (auth disabled) and starts the off-thread poller
    try:
        assert panel._client is not None
        # The poller runs on its own thread; processEvents() delivers its queued snapshot.
        _spin(qapp, lambda: _live_rows(panel) > 0)
        # The reused message list shows the delivered message with a disposition.
        _spin(qapp, lambda: _has_message(panel, qapp))
    finally:
        panel.shutdown()
    assert panel._client is None


def _live_rows(panel: MonitorPanel) -> int:
    return panel._live_table.rowCount() if panel._live_table is not None else 0


def _has_message(panel: MonitorPanel, qapp: Any) -> bool:
    if panel._messages is None:
        return False
    panel._messages.refresh()  # user-initiated re-query (GUI thread)
    qapp.processEvents()
    return panel._messages._table.rowCount() > 0
