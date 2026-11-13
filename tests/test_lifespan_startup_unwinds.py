# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1257: a startup failure after ``engine.start()`` must let the PROCESS exit.

The lifespan's teardown is complete -- it stops the engine (which closes the store), both
notifiers, the upload-retention runner and all three background tasks. It was simply
UNREACHABLE from a startup failure: its ``try:`` began at the ``yield``, so it guarded the
RUNNING phase and never the STARTUP phase. Everything brought up between ``engine.start()``
and the yield was therefore abandoned in place.

What that costs is the process itself, not just tidiness. ``engine.stop()`` ends in
``store.close()``, and aiosqlite's connection worker is a NON-DAEMON thread -- so an
unclosed store means interpreter shutdown blocks forever. uvicorn refuses correctly and
legibly, prints ``Application startup failed. Exiting.``, raises ``SystemExit(3)`` -- and
then the process stays alive. A hung refusal, not a silent one.

THE ASSERTION HERE IS DELIBERATELY NARROW: **the process terminates**. Not that the error
prints, not that ``SystemExit`` is raised. Both of those were measured TRUE while the process
went on living for 90 seconds, so neither discriminates -- a test asserting either would have
passed against the defect.

The failure is injected by patching a real call site inside the span rather than by driving
any one feature's logic, so this stays a test about UNWINDING and does not fail when the gate
that happens to sit there changes.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.api.app as appmod
from messagefoundry.api import create_managed_app
from messagefoundry.config.settings import AlertsSettings, EgressSettings, StoreSettings
from messagefoundry.pipeline import engine as engine_module
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.store import open_store

# The defect is an INDEFINITE hang, so any finite bound discriminates; this is sized to stay
# UNDER the suite's own `--timeout=60` watchdog. That ordering is the whole point: at 90s the
# watchdog fired first and the failure surfaced as a raw traceback from inside `communicate`,
# with this test's diagnosis never reaching the report. A bound above the watchdog is dead code.
_EXIT_TIMEOUT_SECONDS = 30.0

_CHILD = """
import sys
from pathlib import Path

import uvicorn

import messagefoundry.api.app as appmod
from messagefoundry.api import create_managed_app
from messagefoundry.config.settings import AlertsSettings, AuthSettings, EgressSettings


def _boom(*args: object, **kwargs: object) -> None:
    raise RuntimeError("PROBE: deliberate failure in the post-engine startup span")


# A real call site inside the span (after engine.start(), before the yield). Patching the
# function rather than arranging its preconditions keeps this about unwinding. It must be a call
# whose raise reaches the lifespan: the lockable-account census sits after the start too, but its
# own guard swallows a raise, so a probe there would never fail startup.
appmod._initial_credential_warn_lead = _boom  # type: ignore[assignment]

app = create_managed_app(
    db_path=Path(sys.argv[1]) / "probe.db",
    poll_interval=0.05,
    auth_settings=AuthSettings(),
    # The notice gate was this probe until BACKLOG #2131 moved it before engine.start(). On this
    # empty store it would now refuse first, before the span, so its written waiver is set.
    alerts_settings=AlertsSettings(security_notifications_required=False),
    egress_settings=EgressSettings(),
)

print("PROBE: starting uvicorn", flush=True)
try:
    # port 0: nothing binds a real port, and startup fails before serving regardless.
    uvicorn.run(app, host="127.0.0.1", port=0, log_level="error")
except SystemExit:
    # uvicorn's own refusal. Caught so the child returns normally -- interpreter shutdown then
    # has to JOIN every non-daemon thread, which is precisely the condition under test.
    print("PROBE: uvicorn refused (SystemExit)", flush=True)
print("PROBE: reached end of script", flush=True)
"""


def test_a_startup_failure_after_engine_start_lets_the_process_exit(tmp_path: Path) -> None:
    child = tmp_path / "child.py"
    child.write_text(textwrap.dedent(_CHILD), encoding="utf-8")

    proc = subprocess.Popen(
        [sys.executable, str(child), str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        out, _ = proc.communicate(timeout=_EXIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        pytest.fail(
            "the process did NOT exit within "
            f"{_EXIT_TIMEOUT_SECONDS}s after a startup failure -- a hung refusal. "
            f"child output:\n{out}"
        )

    # POSITIVE CONTROLS on the injection. Without these the timeout check alone is satisfied by a
    # child that exited for any reason at all -- including never reaching the span, or dying before
    # uvicorn started. Each line below pins one step of the path that must actually have run.
    #
    # `returncode is not None` is NOT among them: communicate() always sets it, so it asserts
    # nothing about the subject.
    assert "PROBE: starting uvicorn" in out, f"child never reached uvicorn:\n{out}"
    assert "PROBE: uvicorn refused (SystemExit)" in out, (
        f"the injected failure did not produce uvicorn's refusal -- this test no longer exercises "
        f"a startup failure at all:\n{out}"
    )
    assert "PROBE: reached end of script" in out, (
        f"the child did not return normally from the refusal, so what this measured is some other "
        f"exit path:\n{out}"
    )

    # The refusal was reported at all. WEAK ON PURPOSE, and labelled so: it does NOT establish that
    # the startup error survived teardown, because CPython chains. An exception raised inside the
    # `finally` carries the original as ``__context__``, and Starlette's lifespan handler formats the
    # WHOLE chain, so this string is present even when the original was replaced.
    assert "deliberate failure in the post-engine startup span" in out, (
        f"the startup failure was not reported at all:\n{out}"
    )

    # THE TEARDOWN MUST NOT MASK THE STARTUP ERROR -- and this is the assertion that tests it.
    # Measured with a paired control (Engine.stop patched to raise AFTER a real stop, so the store
    # still closes and the process still exits promptly):
    #     clean run  -> "deliberate failure..." present, chaining banner ABSENT
    #     masked run -> "deliberate failure..." present, chaining banner PRESENT
    # So the presence check above is true in both and discriminates nothing; the banner is what
    # separates them. An earlier version of this test asserted only presence and was captioned as
    # the masking guard -- it would have passed against the very defect it named.
    assert "During handling of the above exception" not in out, (
        f"something raised while handling the startup failure, so the operator is shown the "
        f"teardown's error instead of the real cause:\n{out}"
    )


# --- BACKLOG #5907: the spans between open_store and the teardown's try --------------------------
#
# Before #5907 five isolated guards each closed the notifier and the store for their own span, and
# at least the UploadStore rebuild, notifier.set_store/start, prime_suspensions,
# record_generated_pair_replacements, build_coordinator, the Engine(...) call and the factories it
# evaluates as arguments, and _install_security_signals sat between them unguarded. A raise or a
# cancel there left the store open, so aiosqlite's non-daemon worker held the process at exit.
# These run in-process: what they read is that the store and the notifier were closed, which is
# the precondition the subprocess test above measures as the process exiting.


class _Opened:
    """What the probed lifespan opened, and whether it closed it."""

    def __init__(self) -> None:
        self.store: Any = None
        self.store_closed = False
        self.notifier: Any = None
        self.notifier_drained = False
        self.state_drained_after_close = False
        self.engine_stops = 0


def _probed_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opened: _Opened, *, uploads: bool = False
) -> Any:
    async def _open(*args: Any, **kwargs: Any) -> Any:
        store: Any = await open_store(*args, **kwargs)
        real_close = store.close

        async def _close() -> None:
            opened.store_closed = True
            await real_close()

        store.close = _close
        opened.store = store
        return store

    def _notifier(*_args: Any, **_kwargs: Any) -> NotifierAlertSink:
        # A real sink with no transport: the lifespan builds none from bare AlertsSettings.
        sink: Any = NotifierAlertSink([])
        real_aclose = sink.aclose

        async def _aclose() -> None:
            # Recorded only for a sink that was started, so it reads that the drain ran, which a
            # never-started sink's empty task would not show.
            if sink._task is not None:
                opened.notifier_drained = True
            await real_aclose()

        sink.aclose = _aclose
        real_drain_state = sink.drain_state

        async def _drain_state(timeout: float) -> None:
            # After the delivery drain, so an alert-state write it scheduled is waited for.
            opened.state_drained_after_close = sink._task is None
            await real_drain_state(timeout)

        sink.drain_state = _drain_state
        opened.notifier = sink
        return sink

    real_stop = engine_module.Engine.stop

    async def _stop(self: Any) -> None:
        opened.engine_stops += 1
        await real_stop(self)

    monkeypatch.setattr(appmod, "open_store", _open)
    monkeypatch.setattr(appmod, "notifier_from_settings", _notifier)
    monkeypatch.setattr(engine_module.Engine, "stop", _stop)
    settings = StoreSettings(
        path=str(tmp_path / "probe.db"),
        uploads_dir=str(tmp_path / "up") if uploads else "",
    )
    return create_managed_app(
        store_settings=settings,
        alerts_settings=AlertsSettings(),
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def _close_leftovers(opened: _Opened) -> None:
    # Red, the lifespan left these open; close them so the test process can still exit.
    if opened.notifier is not None and opened.notifier._task is not None:
        await opened.notifier.aclose()
    if opened.store is not None and not opened.store_closed:
        await opened.store.close()


def _boom(*_args: object, **_kwargs: object) -> Any:
    raise RuntimeError("PROBE: deliberate failure in an unguarded startup span")


async def _aboom(*_args: object, **_kwargs: object) -> Any:
    raise RuntimeError("PROBE: deliberate failure in an unguarded startup span")


#: Each probe replaces one call the lifespan makes between open_store and the teardown's ``try:``,
#: as (the object it lives on, its name, the replacement).
_PROBES: dict[str, tuple[object, str, Callable[..., Any]]] = {
    "the UploadStore rebuild": (appmod, "UploadStore", _boom),
    "the suspension priming": (NotifierAlertSink, "prime_suspensions", _aboom),
    "the generated-pair audit": (appmod, "record_generated_pair_replacements", _aboom),
    "the coordinator": (appmod, "build_coordinator", _boom),
    "an anchor-preflight factory evaluated as an Engine argument": (
        appmod,
        "make_lane_anchor_check",
        _boom,
    ),
    "the Engine constructor": (appmod, "Engine", _boom),
    "the security-signal install": (appmod, "_install_security_signals", _boom),
}


@pytest.mark.parametrize("probe", list(_PROBES))
async def test_a_raise_in_an_unguarded_startup_span_closes_the_store_and_notifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe: str
) -> None:
    opened = _Opened()
    app = _probed_app(tmp_path, monkeypatch, opened, uploads=probe == "the UploadStore rebuild")
    # Patched after create_app, which builds its own UploadStore from the same name.
    target, name, fake = _PROBES[probe]
    monkeypatch.setattr(target, name, fake)
    try:
        with pytest.raises(RuntimeError, match="PROBE: deliberate failure"):
            async with app.router.lifespan_context(app):
                pytest.fail("startup should have failed")
        # The control: the probe fired after the store opened, so there was a store to close.
        assert opened.store is not None
        assert opened.store_closed, f"{probe}: the store was left open"
        assert opened.notifier is not None and opened.notifier._task is None, (
            f"{probe}: the notifier's drain task was left running"
        )
        # Even where the probe fired before the notifier's own start: it is started and drained.
        assert opened.notifier_drained, f"{probe}: the notifier was never drained"
        assert opened.state_drained_after_close, f"{probe}: its alert-state writes were not drained"
        # The engine never started, so nothing stops it.
        assert opened.engine_stops == 0
    finally:
        await _close_leftovers(opened)


async def test_a_cancel_in_an_unguarded_startup_span_closes_the_store_and_notifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened = _Opened()
    app = _probed_app(tmp_path, monkeypatch, opened)
    reached = asyncio.Event()

    async def _held(*_args: object, **_kwargs: object) -> None:
        reached.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(appmod, "record_generated_pair_replacements", _held)

    async def _start() -> None:
        async with app.router.lifespan_context(app):
            pytest.fail("startup should not have finished")

    task = asyncio.create_task(_start())
    try:
        await asyncio.wait_for(reached.wait(), 10.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 10.0)
        assert opened.store_closed, "a cancel left the store open"
        assert opened.notifier is not None and opened.notifier._task is None
        assert opened.notifier_drained
        assert opened.state_drained_after_close
        assert opened.engine_stops == 0
    finally:
        await _close_leftovers(opened)


class _BlackholedTransport:
    """A webhook or SMTP host that accepts the connection and never answers."""

    name = "webhook"

    def __init__(self) -> None:
        self.entered = asyncio.Event()

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.entered.set()
        await asyncio.Event().wait()


async def test_a_hung_notifier_transport_does_not_keep_the_store_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5907: the unwind drained the notifier's delivery with no cut before it closed the
    store, so a blackholed alert host held the store open, and with it aiosqlite's non-daemon
    worker (#1257). The budget is shrunk so the test is quick; the bound is read from it."""
    monkeypatch.setattr(appmod, "_SHUTDOWN_BUDGET_SECONDS", 1.5)
    monkeypatch.setattr(appmod, "_ENGINE_STOP_RESERVE_SECONDS", 0.5)
    transport = _BlackholedTransport()
    sink = NotifierAlertSink([transport])
    sink.connection_stopped("IB_TEST_ADT", detail="PROBE-DETAIL-TEXT")
    sink.connection_stopped("IB_TEST_ORU", detail="PROBE-DETAIL-TEXT")
    closed: list[float] = []
    loop = asyncio.get_running_loop()

    class _Store:
        async def close(self) -> None:
            closed.append(loop.time())

    store: Any = _Store()
    caplog.set_level(logging.ERROR, logger="messagefoundry.api.app")
    began = loop.time()
    await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
    # The control: the drain did reach the hung send, so the cut is what ended it.
    assert transport.entered.is_set()
    assert closed, "the store was never closed"
    # Within the unwind's budget, plus one cut grace.
    assert closed[0] - began <= 1.0 + appmod._CUT_GRACE_SECONDS + 0.5
    errors = [r for r in caplog.records if "did not drain" in r.getMessage()]
    assert len(errors) == 1, caplog.text
    assert "2 alert(s) left undelivered" in errors[0].getMessage()
    # A count only, never the alert's content.
    assert "PROBE-DETAIL-TEXT" not in caplog.text
    assert "IB_TEST_ADT" not in caplog.text
    # The teardown did not also cut the step: the notifier's own wait ended first.
    assert "cutting it" not in caplog.text
    assert sink._task is None
