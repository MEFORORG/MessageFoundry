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
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

pytest.importorskip("PySide6")

from harness.monitor import MonitorPanel  # noqa: E402
from messagefoundry.api import create_managed_app  # noqa: E402

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


def _spin(qapp: Any, predicate: Any, what: str, deadline: float, context: Any = None) -> None:
    """Pump the Qt event loop until ``predicate()`` holds, or the SHARED ``deadline`` passes.

    Takes an absolute deadline rather than a per-call timeout because this test makes two sequential
    waits, and two independent budgets fail where one shared budget would not: a first wait that eats
    25s of its own 30s allowance still hands the second a full fresh 30s, so the pair can blow the
    watchdog with most of it unspent — while a single budget simply absorbs the slow stage.

    ``what`` names the condition and ``context`` (called only on failure) reports live panel state,
    including the status label — which carries ``poll failed: …`` when the background poller is
    erroring. Both waits used to raise the same bare "condition not met within timeout", so four CI
    failures never revealed which stage stalled, and the diagnosis had to start from nothing.
    """
    start = time.time()
    while not predicate():
        if time.time() > deadline:
            detail = f" | {context()}" if context is not None else ""
            raise AssertionError(
                f"{what}: still false after {time.time() - start:.1f}s "
                f"(shared budget exhausted){detail}"
            )
        qapp.processEvents()
        time.sleep(0.05)


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


# Override the global 60s per-test watchdog: the two waits share a 60s budget, and fixture/engine
# startup sits outside it, so a slow-but-passing CI run could otherwise brush the 60s cap.
#
# NO reruns=2 here any more, deliberately. It was added to let BACKLOG #17 "self-heal" within a run,
# on the theory that this was a residual timing flake on loaded Windows runners. It was not: the
# message list was livelocking (MessagesPanel._apply discarded every snapshot as superseded while this
# test polled refresh() at 50ms — see tests/test_console_messages_refresh.py), which is why neither
# 10s→30s nor the reruns ever fixed it. That is now fixed at the source. Keeping the retry would only
# hide the next real defect the same way it hid this one, and would make the fix unmeasurable — a
# masked failure looks exactly like a working one.
@pytest.mark.timeout(120)
def test_monitor_observes_engine(qapp: Any, server: tuple[str, Path]) -> None:
    url, inbox = server
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    panel = MonitorPanel()
    panel._url.setText(url)
    panel._connect_btn.click()  # connects (auth disabled) and starts the off-thread poller
    deadline = time.time() + 60  # ONE budget spanning both waits, not 30s each
    try:
        assert panel._client is not None

        def ctx() -> str:
            """Failure-path only. The status label carries 'poll failed: …' when the background
            poller is erroring, which is otherwise invisible to this test."""
            return f"live_rows={_live_rows(panel)} status={panel._status.text()!r}"

        # The poller runs on its own thread; processEvents() delivers its queued snapshot.
        _spin(
            qapp, lambda: _live_rows(panel) > 0, "live connections table populated", deadline, ctx
        )
        # The reused message list shows the delivered message with a disposition.
        _spin(qapp, lambda: _has_message(panel, qapp), "delivered message in list", deadline, ctx)
    finally:
        panel.shutdown()
    assert panel._client is None


@pytest.mark.timeout(120)
def test_monitor_observes_a_message_that_arrives_after_connect(
    qapp: Any, server: tuple[str, Path]
) -> None:
    """The deterministic form of what CI kept hitting, and the reason BACKLOG #17 looked like a flake.

    The sibling test writes the message BEFORE the panel connects, so the single initial ``refresh()``
    in ``_build_inner`` normally renders it and the polling path below is never exercised at all. That
    race is the whole difference between local and CI: a fast machine wins it every time, a loaded
    runner lost it about a third of the time and then hit a livelock no timeout could escape.

    Connecting first makes the initial snapshot empty by construction, so the message can ONLY appear
    via the 50ms ``refresh()`` polling — exercising the path that used to discard every snapshot.
    """
    url, inbox = server
    panel = MonitorPanel()
    panel._url.setText(url)
    panel._connect_btn.click()
    (inbox / "a.hl7").write_bytes(
        ADT.encode("utf-8")
    )  # only AFTER the initial refresh has gone out

    deadline = time.time() + 60
    try:
        assert panel._client is not None
        _spin(
            qapp,
            lambda: _has_message(panel, qapp),
            "message arriving after connect appears in list",
            deadline,
            lambda: f"status={panel._status.text()!r}",
        )
    finally:
        panel.shutdown()


def _live_rows(panel: MonitorPanel) -> int:
    return panel._live_table.rowCount() if panel._live_table is not None else 0


def _has_message(panel: MonitorPanel, qapp: Any) -> bool:
    if panel._messages is None:
        return False
    panel._messages.refresh()  # user-initiated re-query (GUI thread)
    qapp.processEvents()
    return panel._messages._table.rowCount() > 0
