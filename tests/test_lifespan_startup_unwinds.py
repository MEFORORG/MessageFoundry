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

    async def _stop(self: Any, **kwargs: Any) -> None:
        opened.engine_stops += 1
        await real_stop(self, **kwargs)

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


#: The startup unwind's budget in the tests that pin what the notifier's own drain wait logs when
#: it ends. That wait ends at ``_INNER_SHARE`` of the notifier step's bound; the teardown cuts the
#: step at the bound, as a backstop. Both are wall-clock deadlines, so a loop stall longer than the
#: gap between them lets the backstop win: it cancels the step while it unwinds, and the step's own
#: ERROR, with its count, is never logged. A 0.10 s gap lost that race on a loaded windows-2022
#: runner (merge queue run 45460183201). The bound is therefore kept far above the wait, so a run
#: takes the wait's path unless the loop stalls for longer than the 6.5 s gap left between them.
_UNWIND_BUDGET_SECONDS = 8.0
#: How long the notifier's own drain wait runs before it cuts the drain. A healthy or fast-failing
#: send must end inside it, so it is not cut finer than a loaded runner can schedule.
_DRAIN_WAIT_SECONDS = 1.0


def _pin_the_drain_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give the unwind :data:`_UNWIND_BUDGET_SECONDS`, which is above the shipped one, and the
    notifier's own drain wait :data:`_DRAIN_WAIT_SECONDS`, so the teardown's cut stays out of reach.

    The unwind reads only the budget less the reserve, so the reserve is zeroed. ``_INNER_SHARE``
    is module-wide: the alert-state drain's wait shrinks with it, to about 0.07 s, which these
    tests' sinks, holding no state writes, never wait on. The hung-notifier test pins the wait this
    derives from the notifier step's bound, in the ERROR it logs."""
    monkeypatch.setattr(appmod, "_SHUTDOWN_BUDGET_SECONDS", _UNWIND_BUDGET_SECONDS)
    monkeypatch.setattr(appmod, "_ENGINE_STOP_RESERVE_SECONDS", 0.0)
    bound = _UNWIND_BUDGET_SECONDS - appmod._UNWIND_STATE_DRAIN_FLOOR_SECONDS
    monkeypatch.setattr(appmod, "_INNER_SHARE", _DRAIN_WAIT_SECONDS / bound)


async def test_a_hung_notifier_transport_does_not_keep_the_store_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5907: the unwind drained the notifier's delivery with no cut before it closed the
    store, so a blackholed alert host held the store open, and with it aiosqlite's non-daemon
    worker (#1257). The notifier's own drain wait is pinned short so the test is quick."""
    _pin_the_drain_wait(monkeypatch)
    transport = _BlackholedTransport()
    sink = NotifierAlertSink([transport])
    # Every level and logger, before the emits, so the content check below covers them all.
    caplog.set_level(logging.DEBUG)
    sink.connection_stopped("IB_TEST_ADT", detail="PROBE-DETAIL-TEXT")
    sink.connection_stopped("IB_TEST_ORU", detail="PROBE-DETAIL-TEXT")
    closed: list[float] = []
    loop = asyncio.get_running_loop()

    class _Store:
        async def close(self) -> None:
            closed.append(loop.time())

    store: Any = _Store()
    began = loop.time()
    await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
    # The control: the drain did reach the hung send, so the cut is what ended it.
    assert transport.entered.is_set()
    assert closed, "the store was never closed"
    # Soon after the notifier's own wait ended, and well before the teardown would cut the step.
    assert closed[0] - began <= _DRAIN_WAIT_SECONDS + 1.5
    errors = [r for r in caplog.records if "did not drain" in r.getMessage()]
    assert len(errors) == 1, caplog.text
    assert "2 alert(s) not confirmed delivered" in errors[0].getMessage()
    # The control on _pin_the_drain_wait: the wait it derives is the one that ran.
    assert f"within {_DRAIN_WAIT_SECONDS:.2f}s" in errors[0].getMessage()
    # A count only, never the alert's content.
    assert "PROBE-DETAIL-TEXT" not in caplog.text
    assert "IB_TEST_ADT" not in caplog.text
    # The teardown did not also cut the step: the notifier's own wait ended first.
    assert "cutting it" not in caplog.text
    assert sink._task is None


class _HealthyEmail:
    """An SMTP relay that accepts every alert at once."""

    name = "email"

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


async def test_a_blackholed_webhook_does_not_stop_the_email_in_the_unwind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5907: the notifier sent each alert to its transports in turn, webhook first, so a
    blackholed webhook held the email until the unwind cut the drain, and the refusal alert never
    reached a healthy relay. The alert being handled now reaches the email; an alert queued behind
    it still waits on the webhook and is lost to the cut, which the count reports."""
    _pin_the_drain_wait(monkeypatch)
    webhook, email = _BlackholedTransport(), _HealthyEmail()
    sink = NotifierAlertSink([webhook, email])  # notifier_from_settings's order
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    sink.connection_stopped("IB_TEST_ORU", detail="probe")

    class _Store:
        async def close(self) -> None:
            return None

    store: Any = _Store()
    await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
    assert webhook.entered.is_set()  # the control: the webhook did hang
    assert [e["connection"] for e in email.events] == ["IB_TEST_ADT"]
    # The email took the first, so only the second, which no transport took, is counted.
    assert sink.undelivered == 1


@pytest.mark.parametrize("webhook_first", [True, False], ids=["webhook-first", "email-first"])
@pytest.mark.parametrize("webhook_kind", ["fails-fast", "hangs-until-cut"])
async def test_an_alert_the_email_took_counts_as_delivered_whatever_the_webhook_timing(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    webhook_kind: str,
    webhook_first: bool,
) -> None:
    """BACKLOG #5907 step 4, Lander hold finding 1 on PR 3191: whether an alert counted as
    delivered depended on timing. A webhook that failed fast beside an email that took the alert
    read delivered, and the same webhook hanging until the unwind cut the drain read undelivered.
    One rule now holds in both: an alert one selected transport took counts as delivered. The
    webhook's loss is logged either way, by transport name."""
    _pin_the_drain_wait(monkeypatch)
    webhook: Any = (
        _BlackholedTransport() if webhook_kind == "hangs-until-cut" else _FailingTransport()
    )
    email = _HealthyEmail()
    sink = NotifierAlertSink([webhook, email] if webhook_first else [email, webhook])
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    store: Any = _ClosingStore()
    caplog.set_level(logging.WARNING)
    await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
    assert [e["connection"] for e in email.events] == ["IB_TEST_ADT"]  # the email took it
    assert sink.undelivered == 0
    if webhook_kind == "hangs-until-cut":
        assert webhook.entered.is_set()  # the control: the webhook did hang
        assert (
            "alert transport(s) webhook still sending when the drain was cancelled" in caplog.text
        )
        assert "did not drain" in caplog.text  # the unwind still logs the cut
        assert "cutting it" not in caplog.text  # the notifier's own wait cut it, not the teardown
        assert "0 alert(s) not confirmed delivered" in caplog.text
    else:
        assert webhook.calls == 1  # the control: the webhook did run and fail
        assert "alert transport webhook failed" in caplog.text
        assert "did not drain" not in caplog.text
        assert "not confirmed delivered" not in caplog.text


class _SlowToCloseSink(NotifierAlertSink):
    """A sink whose close stalls after its drain has delivered everything, so the unwind's wait
    cuts a close that has no send running."""

    stall_cut = False

    async def aclose(self) -> None:
        await super().aclose()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.stall_cut = True
            raise


async def test_a_cut_that_reached_no_running_send_and_lost_nothing_logs_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5907 step 4: the unwind logged its ERROR on every cut, so a cut that reached no
    running send and left nothing counted read as a loss. It stays silent, as on main."""
    _pin_the_drain_wait(monkeypatch)
    email = _HealthyEmail()
    sink = _SlowToCloseSink([email])
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    store: Any = _ClosingStore()
    caplog.set_level(logging.WARNING)
    await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
    assert [e["connection"] for e in email.events] == ["IB_TEST_ADT"]  # the control: delivered
    assert sink.stall_cut  # the control: the unwind's wait was cut
    assert "cutting it" not in caplog.text  # the notifier's own wait cut it, not the teardown
    assert sink.undelivered == 0
    assert "did not drain" not in caplog.text
    assert "not confirmed delivered" not in caplog.text
    assert sink.sends_cut == 0


class _CancelIgnoringEmail(_HealthyEmail):
    """An email send that takes no notice of a cancel and takes the alert once released."""

    def __init__(self) -> None:
        super().__init__()
        self.release = asyncio.Event()
        self.entered = asyncio.Event()

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.entered.set()
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                continue  # the defect this stands for: a send that will not end on a cancel
        await super().send(event)


class _CancelSwallowingWebhook:
    """A send that hangs, then swallows the cancel that reaches it and returns, sending nothing."""

    name = "webhook"

    def __init__(self, *, uncancel: bool = False) -> None:
        self.entered = asyncio.Event()
        self.uncancel = uncancel

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            task = asyncio.current_task()
            if self.uncancel and task is not None:
                task.uncancel()
            return


@pytest.mark.parametrize("uncancel", [False, True], ids=["swallows", "swallows-and-uncancels"])
async def test_a_send_that_swallows_the_cut_and_returns_does_not_count_as_delivered(
    caplog: pytest.LogCaptureFixture, uncancel: bool
) -> None:
    """BACKLOG #5907 step 4: a send that returned counted as delivered even when the drain's
    cancel had reached it and it swallowed the cancel, though it sent nothing. It stays counted,
    the delivery observer is not told, and a WARNING names the transport, also when the send
    clears its task's cancel request."""
    webhook = _CancelSwallowingWebhook(uncancel=uncancel)
    sink = NotifierAlertSink([webhook])
    observed: list[str] = []
    sink.set_delivery_observer(lambda name, _event: observed.append(name))
    caplog.set_level(logging.WARNING)
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    await asyncio.wait_for(webhook.entered.wait(), 5.0)
    task = sink._task
    assert task is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5.0)
    assert not sink._left_sends  # the control: the send returned within the grace
    assert sink.undelivered == 1
    assert observed == []
    assert "alert transport webhook returned after the drain's cancel reached it" in caplog.text
    assert sink.sends_cut == 1


class _SelfCancelledOnReleaseEmail:
    """Waits for a release, then raises its own CancelledError, sending nothing."""

    name = "email"

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.entered = asyncio.Event()

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.entered.set()
        await self.release.wait()
        raise asyncio.CancelledError


async def test_a_send_cancelled_on_its_own_in_the_drain_cancels_pass_is_logged_and_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #5907 step 4: a send that raised its own CancelledError in the loop pass the
    drain's cancel was requested in, before _cut_sends ran, was taken for the drain's cancel and
    re-raised, so no line named that transport's loss; only the undelivered count held it. It is
    now logged by transport, and the alert stays counted."""
    email = _SelfCancelledOnReleaseEmail()
    sink = NotifierAlertSink([email])
    caplog.set_level(logging.WARNING)
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    await asyncio.wait_for(email.entered.wait(), 5.0)
    task = sink._task
    assert task is not None
    email.release.set()  # the send resumes ahead of the drain, in the same pass as its cancel
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5.0)
    assert caplog.text.count("alert transport email was cancelled") == 1
    assert sink.sends_cut == 0  # the control: the send had ended before the cut reached it
    assert sink.undelivered == 1


async def test_a_send_cancelled_on_its_own_outside_a_cut_is_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #5907 step 4: a send that raises its own CancelledError with no drain cancel is
    named by one line, deliver's, and not also by the loop after the wait, now that the cancel
    ends its child task cancelled."""
    email = _SelfCancelledOnReleaseEmail()
    sink = NotifierAlertSink([email])
    caplog.set_level(logging.WARNING)
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    email.release.set()
    await asyncio.wait_for(sink.aclose(), 5.0)
    assert caplog.text.count("alert transport email was cancelled") == 1
    assert "ended cancelled after its send" not in caplog.text
    assert sink.undelivered == 1


async def test_an_external_cancel_in_the_drain_cancels_pass_still_ends_the_send_cancelled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #5907 step 4: a cancel another canceller (asyncio's cancel-all at loop shutdown,
    say) requested on a send in the loop pass the drain's cancel was requested in, which reached
    deliver's handler before _cut_sends ran, was logged as the transport's loss and swallowed, so
    the send's task ended normally. The cancel goes on now, as on main, and the loss is still
    logged and counted. This pins the child-first order only."""
    webhook = _BlackholedTransport()
    sink = NotifierAlertSink([webhook])
    caplog.set_level(logging.WARNING)
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    await asyncio.wait_for(webhook.entered.wait(), 5.0)
    drain = sink._task
    assert drain is not None
    (child,) = [t for t in asyncio.all_tasks() if t.get_name() == "webhook" and not t.done()]
    child.cancel()  # the external canceller, ahead of the drain in the same pass
    drain.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(drain, 5.0)
    assert child.cancelled()
    assert caplog.text.count("alert transport webhook was cancelled") == 1
    assert sink.sends_cut == 0  # the control: the send had ended before the cut reached it
    assert sink.undelivered == 1


class _TakeThenSelfCancelEmail(_HealthyEmail):
    """Waits for a release, takes the alert, cancels its own task and returns."""

    def __init__(self) -> None:
        super().__init__()
        self.release = asyncio.Event()
        self.entered = asyncio.Event()

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.entered.set()
        await self.release.wait()
        await super().send(event)
        task = asyncio.current_task()
        assert task is not None
        task.cancel()


async def test_a_send_that_returns_before_the_cut_reaches_it_counts_though_it_cancelled_itself(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #5907 step 4: a send that takes the alert, cancels its own task and returns in
    the loop pass the drain is cancelled in returned before the cut reached it, so it counts and
    the observer is told. Its own cancel is not the drain's."""
    webhook, email = _BlackholedTransport(), _TakeThenSelfCancelEmail()
    sink = NotifierAlertSink([webhook, email])
    observed: list[str] = []
    sink.set_delivery_observer(lambda name, _event: observed.append(name))
    caplog.set_level(logging.WARNING)
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    await asyncio.wait_for(asyncio.gather(webhook.entered.wait(), email.entered.wait()), 5.0)
    task = sink._task
    assert task is not None
    email.release.set()  # the email's send resumes in the same pass as the drain's cancel
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5.0)
    assert [e["connection"] for e in email.events] == ["IB_TEST_ADT"]  # the control: it took it
    assert sink.undelivered == 0
    assert observed == ["email"]
    assert "returned after the drain's cancel reached it" not in caplog.text
    assert sink.sends_cut == 1  # only the webhook was still running


async def test_a_send_left_past_the_cut_does_not_count_when_it_returns() -> None:
    """BACKLOG #5907 step 4: the same rule for a send the drain's cancel left running past its
    grace. The cancel reached it, so the alert stays counted, even once the send returns."""
    email = _CancelIgnoringEmail()
    sink = NotifierAlertSink([email])
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    try:
        await asyncio.wait_for(email.entered.wait(), 5.0)
        task = sink._task
        assert task is not None
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5.0)
        assert sink.undelivered == 1  # cut, and nothing had taken it
        assert len(sink._left_sends) == 1  # the control: the send was left running
    finally:
        email.release.set()  # a send that swallows every cancel must not outlive the test
    await asyncio.wait_for(asyncio.gather(*sink._left_sends), 5.0)
    assert not sink._left_sends  # released by the send's done callback
    assert [e["connection"] for e in email.events] == ["IB_TEST_ADT"]  # the control: it returned
    assert sink.undelivered == 1


class _FailingTransport:
    """A transport whose every send raises, as a refused webhook POST does."""

    name = "webhook"

    def __init__(self) -> None:
        self.calls = 0

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.calls += 1
        raise OSError("synthetic refusal")


class _ClosingStore:
    """A store whose close does nothing, for an unwind run without one."""

    async def close(self) -> None:
        return None


class _SelfCancellingFailingWebhook(_FailingTransport):
    """Cancels its own task, then fails before the cancel lands, so the alert never left."""

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()
        await super().send(event)


class _SelfCancellingEmail(_HealthyEmail):
    """Takes the alert, then cancels its own task and returns before the cancel lands."""

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        await super().send(event)
        task = asyncio.current_task()
        assert task is not None
        task.cancel()


@pytest.mark.parametrize(
    ("transports", "expected"),
    [
        pytest.param(lambda: [_HealthyEmail()], 0, id="delivered"),
        pytest.param(lambda: [_FailingTransport()], 2, id="every-send-failed"),
        pytest.param(lambda: [_FailingTransport(), _HealthyEmail()], 0, id="one-transport-took-it"),
        pytest.param(lambda: [_SelfCancellingEmail()], 0, id="ended-cancelled-after-its-send"),
        pytest.param(lambda: [_SelfCancellingFailingWebhook()], 2, id="self-cancelled-then-failed"),
        pytest.param(lambda: [], 2, id="no-transport-selected"),
    ],
)
async def test_undelivered_counts_alerts_not_delivered_rather_than_handled(
    transports: Callable[[], list[Any]], expected: int
) -> None:
    """BACKLOG #5907 step 4: the drain took an alert off the count once it was handled, whether
    or not any transport took it, so a failed send read as delivered. An alert stays counted
    unless at least one transport its rule selected took it."""
    sink = NotifierAlertSink(transports())
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    sink.connection_stopped("IB_TEST_ORU", detail="probe")
    await asyncio.wait_for(sink.aclose(), 10.0)
    assert sink.undelivered == expected


async def test_the_unwind_reports_alerts_no_transport_took_when_the_drain_ends_in_time(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #5907 step 4: the unwind read the count only once its drain wait timed out, so an
    alert whose sends all failed fast was lost with no count. A drain that ends in time now logs
    the count when it is not zero, and nothing when every alert was taken."""
    store: Any = _ClosingStore()
    with caplog.at_level(logging.ERROR, logger=appmod._log.name):
        sink = NotifierAlertSink([_HealthyEmail()])
        sink.connection_stopped("IB_TEST_ADT", detail="probe")
        await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
        assert "not confirmed delivered" not in caplog.text  # the control
        sink = NotifierAlertSink([_FailingTransport()])
        sink.connection_stopped("IB_TEST_ADT", detail="probe")
        await asyncio.wait_for(appmod._unwind_failed_start(store, sink), 10.0)
    assert "startup unwind: 1 alert(s) not confirmed delivered" in caplog.text


async def test_a_close_cancelled_on_a_full_queue_still_stops_the_drain() -> None:
    """BACKLOG #5907: an alert notifier close cancelled while its sentinel waited on a full queue
    left the drain task delivering, so the unwind's cut did not stop it."""
    transport = _BlackholedTransport()
    sink = NotifierAlertSink([transport])
    sink._queue = asyncio.Queue(maxsize=1)  # full after one queued alert
    sink.start()
    sink.connection_stopped("IB_TEST_ADT", detail="probe")
    await asyncio.wait_for(transport.entered.wait(), 10.0)
    sink.connection_stopped("IB_TEST_ORU", detail="probe")  # fills the queue
    task = sink._task
    assert task is not None
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(sink.aclose(), 0.2)
    # Waited for inside the close, so it has ended by the time the close returns.
    assert task.cancelled()
    assert sink._task is None
