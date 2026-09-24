# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness Monitor tab: it builds disconnected, and observes a running engine over the API.

Like ``test_console_client``, this starts a real managed app (engine + API, auth disabled) in a
background uvicorn thread, then drives the GUI panel: connecting starts the off-thread poller,
which must populate the live connections table, and the reused message list must show the
delivered message with its disposition.
"""

from __future__ import annotations

import socket
import sys
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

#: How long the fixture waits for uvicorn to report ``started``. A module constant so the
#: leak regression below can drive the timeout path in well under a second instead of forty.
#: Match the scenarios fixture's single bring-up allowance; do not retry a slow lifespan.
_START_TIMEOUT_SECONDS = 40.0


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
    yield from _serve(tmp_path)


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[str, Path, str]]:
    """The same engine served over TLS with a pair minted the way a stock engine mints its own
    (``pki.make_self_signed`` for the bind host, ADR 0172). Yields the cert path to pin."""
    from messagefoundry import pki

    cert_pem, key_pem = pki.make_self_signed("127.0.0.1", [], 1)
    cert, key = tmp_path / "api-generated-cert.pem", tmp_path / "api-generated-key.pem"
    cert.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    gen = _serve(tmp_path, ssl_pair=(str(cert), str(key)))
    url, inbox = next(gen)
    try:
        yield url, inbox, str(cert)
    finally:
        gen.close()


def _serve(tmp_path: Path, ssl_pair: tuple[str, str] | None = None) -> Iterator[tuple[str, Path]]:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _write_config(tmp_path / "config", inbox, outdir)
    app = create_managed_app(
        db_path=tmp_path / "console.db", config_dir=tmp_path / "config", poll_interval=0.05
    )
    port = _free_port()
    tls: dict[str, str] = {}
    if ssl_pair is not None:
        tls = {"ssl_certfile": ssl_pair[0], "ssl_keyfile": ssl_pair[1]}
    uv = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", **tls)
    )
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    # The try opens HERE, immediately after the thread exists, not after the wait succeeds.
    # The start timeout used to raise from outside it, so the one exit path that fires on a
    # loaded machine -- the flaky one -- left a live uvicorn thread holding a bound port and an
    # open handle under `tmp_path` for the rest of the pytest worker's life (BACKLOG #1515).
    # `test_harness_scenarios.server` already had this right; this is that shape.
    try:
        deadline = time.monotonic() + _START_TIMEOUT_SECONDS
        while True:
            if not thread.is_alive():
                raise RuntimeError(f"monitor server exited during startup (api_port={port})")
            if uv.started:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    f"monitor server startup timed out after {_START_TIMEOUT_SECONDS:g}s "
                    f"(api_port={port})"
                )
            time.sleep(min(0.05, remaining))
        yield f"{'https' if ssl_pair else 'http'}://127.0.0.1:{port}", inbox
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
    # The engine always serves TLS (ADR 0172), so an http default names a socket that never answers.
    assert panel._url.text().startswith("https://")
    panel.shutdown()  # safe to call when never connected


@pytest.mark.timeout(120)
def test_monitor_reaches_a_tls_engine_only_with_its_minted_cert_pinned(
    qapp: Any, tls_server: tuple[str, Path, str]
) -> None:
    """A stock engine serves a certificate it minted itself, which no trust store holds. The Cert
    field is the only way the tab can reach it, and the pin must reach the off-thread poller too:
    it builds its own client, so a pin applied only to the GUI client would connect and then fail
    every poll."""
    url, inbox, cert = tls_server
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))

    # CONTROL: the same engine with the field blank verifies against the OS store and is refused.
    # Without this, the pass below could come from verification having been switched off.
    blank = MonitorPanel()
    blank._url.setText(url)
    blank._connect_btn.click()
    try:
        assert blank._client is None
        assert (
            "certificate" in blank._status.text().lower() or "ssl" in blank._status.text().lower()
        )
    finally:
        blank.shutdown()

    panel = MonitorPanel()
    panel._url.setText(url)
    panel._cacert.setText(cert)
    panel._connect_btn.click()
    try:
        assert panel._client is not None, panel._status.text()
        assert not panel._cacert.isEnabled()  # a live connection's pin cannot be edited under it
        _spin(
            qapp,
            lambda: _live_rows(panel) > 0,
            "poller populated the live table over the pinned TLS hop",
            time.time() + 60,
            lambda: f"status={panel._status.text()!r}",
        )
    finally:
        panel.shutdown()
    assert panel._cacert.isEnabled()


# Override the global 60s per-test watchdog: the two waits share a 60s budget, and fixture/engine
# startup sits outside it, so a slow-but-passing CI run could otherwise brush the 60s cap.
#
# NO reruns=2 here any more, deliberately. It was added to let this "self-heal" within a run, on the
# theory that it was a residual timing flake on loaded Windows runners. It was not: the message list
# was livelocking (MessagesPanel._apply discarded every snapshot as superseded while this test polled
# refresh() at 50ms — see tests/test_console_messages_refresh.py), which is why neither 10s→30s nor the
# reruns ever fixed it. That is now fixed at the source. Keeping the retry would only hide the next real
# defect the same way it hid this one, and would make the fix unmeasurable — a masked failure looks
# exactly like a working one.
#
# The comment this replaced blamed "BACKLOG #17". That is the py3.11 pytest/aiosqlite cancellation
# deadlock, OBSOLETE since the 3.14-only migration and unrelated to anything here — a wrong citation
# that survived long enough to be copied into new files. This defect has no backlog entry.
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
    """The deterministic form of what CI kept hitting, and the reason this looked like a flake at all.

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


# --- BACKLOG #1515: the fixture's own teardown ---------------------------------------------------


class _NeverStartingServer:
    """A uvicorn.Server stand-in whose ``started`` never flips, so the fixture hits its timeout.

    ``run`` blocks until ``should_exit`` is set, which is exactly how the real server's thread
    behaves -- so if the fixture forgets to set it, the thread stays alive and the assertion below
    catches the leak rather than a shutdown that happened for some other reason.
    """

    def __init__(self, config: Any) -> None:
        self.started = False
        self.should_exit = False

    def run(self) -> None:
        while not self.should_exit:
            time.sleep(0.01)


def test_server_fixture_stops_its_thread_when_startup_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timeout path must tear the thread down, not raise past it.

    A leaked uvicorn thread is a daemon: it survives the test, keeps its port bound and keeps a
    handle open under `tmp_path`, and nothing reports it. The fixture is the thing under test here,
    so it is driven directly as a generator.
    """
    monkeypatch.setattr(uvicorn, "Server", _NeverStartingServer)
    monkeypatch.setattr(uvicorn, "Config", lambda *a, **k: None)
    monkeypatch.setattr(sys.modules[__name__], "_START_TIMEOUT_SECONDS", 0.3)

    before = {t.ident for t in threading.enumerate()}
    gen = server.__wrapped__(tmp_path)  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="server startup timed out"):
        next(gen)

    leaked = [t for t in threading.enumerate() if t.ident not in before and t.is_alive()]
    # join(timeout=10) has already run inside the fixture's finally, so a thread still alive here
    # was never asked to stop.
    assert leaked == [], f"the fixture leaked {len(leaked)} live thread(s): {leaked}"
