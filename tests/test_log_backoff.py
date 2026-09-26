# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1844: a failure that repeats on a fixed cadence is logged on a backoff, not per pass.

Two layers. The shared :class:`~messagefoundry.log_backoff.FailureRun` on its own (the schedule,
the count, a changed cause, the recovery line), then the engine loops that adopted it: the four
per-lane pipeline workers and the pooled dispatcher's claimer and sweep. The tray poller's own
arms in ``tests/test_tray_poller.py`` pin the same class through the tray.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from messagefoundry.config.models import OrderingMode
from messagefoundry.config.wiring import Registry
from messagefoundry.log_backoff import FailureRun, is_emission
from messagefoundry.pipeline import stage_dispatcher, wiring_runner
from messagefoundry.pipeline.stage_dispatcher import StageDispatcher
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import ClaimAbortPhase, ClaimLockTimeout, Stage
from messagefoundry.store.store import ClaimedHeads, OutboxItem

_LOGGER = "test.log_backoff"
_RUNNER_LOGGER = "messagefoundry.pipeline.wiring_runner"
_DISPATCHER_LOGGER = "messagefoundry.pipeline.stage_dispatcher"
_RECOVERED = "recovered after"


def _count(record: logging.LogRecord) -> int:
    """The ``(<label>: N)`` a fault record carries."""
    return int(record.getMessage().rsplit(": ", 1)[1].rstrip(")"))


def _faults(caplog: pytest.LogCaptureFixture, logger: str, level: int) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == logger and r.levelno == level and _RECOVERED not in r.getMessage()
    ]


def _recovery_records(caplog: pytest.LogCaptureFixture, logger: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == logger and _RECOVERED in r.getMessage()]


def _recoveries(caplog: pytest.LogCaptureFixture, logger: str) -> list[str]:
    return [r.getMessage() for r in _recovery_records(caplog, logger)]


def _carries_a_traceback(record: logging.LogRecord) -> bool:
    # exc_info or exc_text: the PHI RedactionFilter may have rendered the one into the other.
    return bool(record.exc_info or record.exc_text)


# --- the shared class -------------------------------------------------------------------------


def test_is_emission_is_the_power_of_two_schedule() -> None:
    assert [n for n in range(0, 70) if is_emission(n)] == [1, 2, 4, 8, 16, 32, 64]


def test_a_repeated_fault_emits_on_the_power_of_two_schedule_with_the_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    log = logging.getLogger(_LOGGER)
    run = FailureRun()
    for _ in range(20):
        run = run.record(log, OSError("database is locked"), "lane %r faulted", "OB")

    faults = _faults(caplog, _LOGGER, logging.ERROR)
    assert [_count(f) for f in faults] == [1, 2, 4, 8, 16]
    assert all(_carries_a_traceback(f) for f in faults)
    assert faults[0].getMessage() == "lane 'OB' faulted (consecutive failures: 1)"
    assert run.count == 20


def test_a_changed_cause_emits_at_once_and_starts_its_own_schedule(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    log = logging.getLogger(_LOGGER)
    run = FailureRun()
    for _ in range(5):
        run = run.record(log, OSError("database is locked"), "faulted")
    for _ in range(4):
        run = run.record(log, OSError("disk full"), "faulted")

    # 1, 2, 4 under the first cause; then 6, because the cause changed (the 8th slot is not waited
    # for), and 7 and 9 on the new cause's own 2nd and 4th. The count stays the whole run's.
    assert [_count(f) for f in _faults(caplog, _LOGGER, logging.ERROR)] == [1, 2, 4, 6, 7, 9]


def test_a_changed_exception_type_with_the_same_text_is_a_changed_cause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    log = logging.getLogger(_LOGGER)
    run = FailureRun().record(log, OSError("boom"), "x").record(log, OSError("boom"), "x")
    run = run.record(log, OSError("boom"), "x")  # 3rd of the cause: held back
    run = run.record(log, RuntimeError("boom"), "x")  # new type: emitted
    assert [_count(f) for f in _faults(caplog, _LOGGER, logging.ERROR)] == [1, 2, 4]


def _operational_error(driver: str) -> type[Exception]:
    class OperationalError(Exception):
        pass

    OperationalError.__module__ = driver
    return OperationalError


def test_two_drivers_same_named_exception_is_a_changed_cause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Keyed on the bare class name, sqlite3's and another driver's OperationalError with the same
    text would be one cause, and the second driver's first failure could be held back."""
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    log = logging.getLogger(_LOGGER)
    first, second = _operational_error("sqlite3"), _operational_error("asyncpg.exceptions")
    run = FailureRun()
    for _ in range(3):
        run = run.record(log, first("database is locked"), "x")
    run.record(log, second("database is locked"), "x")
    assert [_count(f) for f in _faults(caplog, _LOGGER, logging.ERROR)] == [1, 2, 4]


def test_recovery_is_logged_once_and_resets_the_run(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    log = logging.getLogger(_LOGGER)
    run = FailureRun()
    for _ in range(3):
        run = run.record(log, OSError("database is locked"), "faulted")
    run = run.clear(log, "worker %r", "OB")
    run = run.clear(log, "worker %r", "OB")  # a second healthy pass writes nothing more

    assert _recoveries(caplog, _LOGGER) == ["worker 'OB' recovered after 3 consecutive failures"]
    assert [r.levelno for r in _recovery_records(caplog, _LOGGER)] == [logging.INFO]
    assert run == FailureRun()
    # After the reset the same cause is a fresh run: its first failure emits again.
    caplog.clear()
    run.record(log, OSError("database is locked"), "faulted")
    assert [_count(f) for f in _faults(caplog, _LOGGER, logging.ERROR)] == [1]


def test_the_count_label_and_the_recovery_level_are_the_callers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    log = logging.getLogger(_LOGGER)
    run = FailureRun().record(log, OSError("x"), "m", count_label="failures in this run")
    run.clear(log, "w", level=logging.WARNING, count_label="failures in this run")
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.ERROR, "m (failures in this run: 1)"),
        (logging.WARNING, "w recovered after 1 failures in this run"),
    ]


def test_a_healthy_clear_writes_nothing_and_returns_itself(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    run = FailureRun()
    assert run.clear(logging.getLogger(_LOGGER), "worker") is run
    assert not caplog.records


def test_the_fault_level_is_the_callers(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    FailureRun().record(logging.getLogger(_LOGGER), OSError("x"), "m", level=logging.WARNING)
    assert [r.levelno for r in caplog.records] == [logging.WARNING]


def test_an_unprintable_exception_does_not_raise_out_of_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The caller is an except arm; a second fault raised from inside it would kill the loop."""

    class Unprintable(Exception):
        def __str__(self) -> str:
            raise ValueError("no text for you")

    caplog.set_level(
        logging.CRITICAL, logger=_LOGGER
    )  # the logging module's own render is not ours
    run = FailureRun().record(logging.getLogger(_LOGGER), Unprintable(), "m")
    run = run.record(logging.getLogger(_LOGGER), Unprintable(), "m")
    assert run.count == 2 and run.cause_run == 2  # and the cause still compares equal to itself


# --- the per-lane pipeline workers ----------------------------------------------------------------

# Short enough to run in a test, and far longer than one fault-to-fault cycle: a Windows timer
# rounds a 1 ms sleep up to about 15 ms, so one cycle (backoff, empty claim, poll) can near 50 ms.
_QUIET = 0.4


@pytest.fixture
def fast_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.001)
    monkeypatch.setattr(wiring_runner, "_FAULT_RUN_QUIET_SECONDS", _QUIET)
    monkeypatch.setattr(wiring_runner, "_BUILDUP_CHECK_INTERVAL", float("inf"))  # no store reads


def _row(row_id: str, stage: str = Stage.OUTBOUND.value) -> OutboxItem:
    return OutboxItem(
        id=row_id,
        message_id=f"msg-{row_id}",
        channel_id="IB",
        destination_name="OB",
        payload="MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1844|P|2.5.1\r",
        attempts=1,
        stage=stage,
    )


class _OutageStore:
    """Every claim raises for the first ``fail_times`` calls, then returns no work."""

    def __init__(self, fail_times: int) -> None:
        self.calls = 0
        self.fail_times = fail_times

    def _tick(self) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("simulated store outage: database is locked")

    async def claim_ready(self, **kwargs: Any) -> list[Any]:
        self._tick()
        return []

    async def claim_next_fifo(self, *args: Any, **kwargs: Any) -> Any:
        self._tick()
        return None

    async def claim_next_fifo_batch(self, *args: Any, **kwargs: Any) -> list[Any]:
        self._tick()
        return []


async def _until(predicate: Any, timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.005)


async def _stop(runner: RegistryRunner, task: asyncio.Future[None]) -> None:
    runner._stop.set()
    for ev in (runner._work, runner._ingress_work, runner._routed_work, runner._response_work):
        ev.set()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def _runner(store: Any) -> RegistryRunner:
    runner = RegistryRunner(Registry(), store, poll_interval=0.001, claim_mode="per_lane")
    runner._running = True
    return runner


_WORKERS = [
    ("_router_worker", "router"),
    ("_transform_worker", "transform"),
    ("_response_worker", "response"),
    ("_delivery_worker", "delivery"),
]


@pytest.mark.parametrize(("worker_attr", "label"), _WORKERS)
async def test_a_looping_store_fault_no_longer_logs_a_traceback_per_pass(
    worker_attr: str, label: str, caplog: pytest.LogCaptureFixture, fast_worker: None
) -> None:
    """All four per-lane workers. Eleven failed claims in a row used to write eleven tracebacks;
    now they write the 1st, 2nd, 4th and 8th, each with its count, then one recovery line once the
    lane has been quiet for the quiet period."""
    caplog.set_level(logging.INFO, logger=_RUNNER_LOGGER)
    store = _OutageStore(fail_times=11)
    runner = _runner(store)

    task = asyncio.ensure_future(getattr(runner, worker_attr)("IB"))
    try:
        await _until(lambda: bool(_recoveries(caplog, _RUNNER_LOGGER)))
        assert not task.done()  # it survived every fault; only _stop below ends it
    finally:
        await _stop(runner, task)

    faults = _faults(caplog, _RUNNER_LOGGER, logging.ERROR)
    assert [_count(f) for f in faults] == [1, 2, 4, 8]
    assert all(_carries_a_traceback(f) for f in faults)
    assert faults[0].getMessage() == (
        f"{label} worker 'IB': unexpected error; backing off and retrying (failures in this run: 1)"
    )
    (recovery,) = _recovery_records(caplog, _RUNNER_LOGGER)
    assert recovery.getMessage() == (
        f"{label} worker 'IB': no fault for 0 s, recovered after 11 failures in this run"
    )
    assert recovery.levelno == logging.WARNING
    # The records still name the worker, not the helper they now pass through.
    assert {f.funcName for f in faults} | {recovery.funcName} == {worker_attr}


async def test_the_run_closes_only_after_the_quiet_period(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, fast_worker: None
) -> None:
    """The empty claims that follow a fault come at once; the recovery line waits for quiet."""
    monkeypatch.setattr(wiring_runner, "_FAULT_RUN_QUIET_SECONDS", 0.3)
    caplog.set_level(logging.INFO, logger=_RUNNER_LOGGER)
    store = _OutageStore(fail_times=1)
    runner = _runner(store)
    task = asyncio.ensure_future(runner._router_worker("IB"))
    try:
        await _until(lambda: bool(_recoveries(caplog, _RUNNER_LOGGER)))
    finally:
        await _stop(runner, task)

    (fault,) = _faults(caplog, _RUNNER_LOGGER, logging.ERROR)
    (recovery,) = _recovery_records(caplog, _RUNNER_LOGGER)
    assert store.calls > 3  # many empty claims came and went before the run closed
    assert recovery.created - fault.created >= 0.3


class _PoisonRowStore:
    """The fault comes AFTER a committed claim: the claim hands out one row, the per-item body
    raises, and the worker re-pends the row dated ahead (#1611). Every other claim comes back
    empty, which is what a re-pended head looks like until its date passes."""

    def __init__(self, stage: str) -> None:
        self.item = _row("row-1", stage)
        self.claims = 0

    def _next(self) -> OutboxItem | None:
        self.claims += 1
        return self.item if self.claims % 2 == 1 else None

    async def claim_next_fifo(self, *a: Any, **k: Any) -> OutboxItem | None:
        return self._next()

    async def claim_ready(self, **k: Any) -> list[OutboxItem]:
        item = self._next()
        return [item] if item is not None else []

    async def reschedule_claimed(self, ids: Any, next_attempt_at: float, now: Any = None) -> None:
        return None


@pytest.mark.parametrize(
    ("worker_attr", "body_attr", "stage"),
    [
        ("_router_worker", "_process_ingress_item", Stage.INGRESS.value),
        ("_transform_worker", "_process_routed_batch", Stage.ROUTED.value),
        ("_response_worker", "_process_response_item", Stage.RESPONSE.value),
        ("_delivery_worker", "_process_delivery_item", Stage.OUTBOUND.value),
    ],
)
async def test_an_empty_claim_after_a_re_pended_row_does_not_close_the_run(
    worker_attr: str,
    body_attr: str,
    stage: str,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    fast_worker: None,
) -> None:
    """The empty claim between two faults is the re-pended row not being due yet, not the fault
    clearing. Counted as a close, each would log the next fault afresh as failure 1 -- a traceback
    and a recovery line per fault, which is the flood again. Eight faults must emit 1, 2, 4, 8
    with no recovery line, and the quiet after the row finally succeeds writes the one recovery."""
    caplog.set_level(logging.INFO, logger=_RUNNER_LOGGER)
    store = _PoisonRowStore(stage)
    runner = _runner(store)
    raised = {"n": 0}

    async def body(*a: Any, **k: Any) -> Any:
        raised["n"] += 1
        if raised["n"] <= 8:
            raise RuntimeError("simulated fault after the claim committed")
        if body_attr == "_process_routed_batch":
            return False  # the batch body's "do not halt"
        return (wiring_runner._ItemOutcome.PROCESSED, None)

    monkeypatch.setattr(runner, body_attr, body)

    task = asyncio.ensure_future(getattr(runner, worker_attr)("IB"))
    try:
        await _until(lambda: bool(_recoveries(caplog, _RUNNER_LOGGER)))
    finally:
        await _stop(runner, task)

    assert [_count(f) for f in _faults(caplog, _RUNNER_LOGGER, logging.ERROR)] == [1, 2, 4, 8]
    (recovery,) = _recoveries(caplog, _RUNNER_LOGGER)
    assert recovery.endswith("recovered after 8 failures in this run")


class _UnorderedLaneStore:
    """An UNORDERED delivery lane with a backlog: claims alternate between the one poison row and a
    fresh good row, so a pass over OTHER rows succeeds between each of the poison row's faults."""

    def __init__(self) -> None:
        self.claims = 0

    async def claim_ready(self, **k: Any) -> list[OutboxItem]:
        await asyncio.sleep(0)  # a real claim suspends; without this the loop starves the test
        self.claims += 1
        return [_row("poison")] if self.claims % 2 == 1 else [_row(f"good-{self.claims}")]

    async def reschedule_claimed(self, ids: Any, next_attempt_at: float, now: Any = None) -> None:
        return None


async def _drive_unordered_lane(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.INFO, logger=_RUNNER_LOGGER)
    store = _UnorderedLaneStore()
    runner = _runner(store)
    runner._ordering_default = OrderingMode.UNORDERED
    poison = {"n": 0}

    async def body(name: str, item: OutboxItem) -> Any:
        if item.id == "poison":
            poison["n"] += 1
            if poison["n"] <= 8:
                raise RuntimeError("simulated store fault on one row")
        return (wiring_runner._ItemOutcome.PROCESSED, None)

    monkeypatch.setattr(runner, "_process_delivery_item", body)
    task = asyncio.ensure_future(runner._delivery_worker("OB"))
    try:
        await _until(lambda: poison["n"] >= 9 and bool(_recoveries(caplog, _RUNNER_LOGGER)))
    finally:
        await _stop(runner, task)


async def test_a_healthy_pass_over_other_rows_does_not_close_a_poison_rows_run(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, fast_worker: None
) -> None:
    """An unordered lane keeps delivering other rows while one row keeps faulting. Closing the run
    on those passes would log the poison row afresh each time it came back, with a recovery line
    between, which is more lines than logging it unthrottled."""
    await _drive_unordered_lane(caplog, monkeypatch)
    assert [_count(f) for f in _faults(caplog, _RUNNER_LOGGER, logging.ERROR)] == [1, 2, 4, 8]
    (recovery,) = _recoveries(caplog, _RUNNER_LOGGER)
    assert recovery.endswith("recovered after 8 failures in this run")


async def test_the_same_lane_with_no_quiet_period_closes_on_every_good_pass(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, fast_worker: None
) -> None:
    """The control for the arm above: with the quiet period at zero every good pass closes the
    run, and every poison fault is failure 1 with a recovery line after it. That is the shape the
    quiet period exists to prevent, so the arm above is not green by accident."""
    monkeypatch.setattr(wiring_runner, "_FAULT_RUN_QUIET_SECONDS", 0.0)
    await _drive_unordered_lane(caplog, monkeypatch)
    assert [_count(f) for f in _faults(caplog, _RUNNER_LOGGER, logging.ERROR)] == [1] * 8
    assert len(_recoveries(caplog, _RUNNER_LOGGER)) == 8


class _RepeatFaultNoRependStore:
    """Every claim returns the row, and the re-pend that should hand it back fails too."""

    def __init__(self) -> None:
        self.reschedules = 0

    async def claim_next_fifo(self, *a: Any, **k: Any) -> OutboxItem | None:
        return _row("row-1", Stage.INGRESS.value)

    async def reschedule_claimed(self, ids: Any, next_attempt_at: float, now: Any = None) -> None:
        self.reschedules += 1
        raise RuntimeError("simulated store outage: database is locked")


async def test_a_failing_re_pend_in_the_same_arm_backs_off_too(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, fast_worker: None
) -> None:
    """Under a busy timeout the handoff and the re-pend fail on the same passes, so throttling only
    the first would leave a traceback per pass beside it."""
    caplog.set_level(logging.INFO, logger=_RUNNER_LOGGER)
    store = _RepeatFaultNoRependStore()
    runner = _runner(store)

    async def body(*a: Any, **k: Any) -> Any:
        raise RuntimeError("simulated fault after the claim committed")

    monkeypatch.setattr(runner, "_process_ingress_item", body)
    task = asyncio.ensure_future(runner._router_worker("IB"))
    try:
        await _until(lambda: store.reschedules >= 10)
    finally:
        await _stop(runner, task)

    repends = [
        r
        for r in _faults(caplog, _RUNNER_LOGGER, logging.WARNING)
        if "reschedule_claimed failed" in r.getMessage()
    ]
    n = store.reschedules
    assert [_count(r) for r in repends] == [k for k in (1, 2, 4, 8, 16, 32, 64) if k <= n]
    assert {r.funcName for r in repends} == {"_repend_claimed_on_fault"}


class _DeliverThenClaimFaultStore:
    """Pass 1 claims and delivers a row; pass 2's claim raises; after that the lane is idle."""

    def __init__(self) -> None:
        self.claims = 0
        self.rescheduled: list[list[str]] = []

    async def claim_next_fifo(self, *a: Any, **k: Any) -> OutboxItem | None:
        self.claims += 1
        if self.claims == 1:
            return _row("row-1", Stage.INGRESS.value)
        if self.claims == 2:
            raise RuntimeError("simulated store outage: database is locked")
        return None

    async def reschedule_claimed(self, ids: Any, next_attempt_at: float, now: Any = None) -> None:
        self.rescheduled.append(list(ids))


async def test_a_claim_fault_after_a_good_pass_re_pends_nothing(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, fast_worker: None
) -> None:
    """The loop's claimed list used to outlive a finished pass, so a claim fault on the next pass
    re-pended a row already resolved. Under an outage that write fails too and logs that the row
    stays INFLIGHT, which is false."""
    store = _DeliverThenClaimFaultStore()
    runner = _runner(store)

    async def body(*a: Any, **k: Any) -> Any:
        return (wiring_runner._ItemOutcome.PROCESSED, None)

    monkeypatch.setattr(runner, "_process_ingress_item", body)
    task = asyncio.ensure_future(runner._router_worker("IB"))
    try:
        await _until(lambda: store.claims >= 4)
    finally:
        await _stop(runner, task)
    assert store.rescheduled == []


# --- the pooled dispatcher (the default claim mode) ------------------------------------------------


async def _noop_body(lane: str, item: OutboxItem) -> Any:  # pragma: no cover - never dispatched
    raise AssertionError("no row is ever claimed in these tests")


def _dispatcher(store: Any) -> StageDispatcher:
    return StageDispatcher(
        Stage.INGRESS,
        store,
        process_item=_noop_body,
        lane_provider=lambda: set(),
        per_lane_limit=1,
        sweep_interval=0.001,
    )


async def test_the_pooled_sweep_backs_off_its_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The sweep retries every sweep_interval, 0.25 s by default, so an outage wrote four
    tracebacks a second per stage before this change."""
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    d = _dispatcher(store=None)
    sweeps = {"n": 0}

    async def sweep_once() -> None:
        sweeps["n"] += 1
        if sweeps["n"] <= 9:
            raise RuntimeError("simulated store outage: database is locked")
        d._stop.set()  # the 10th sweep is healthy; end the loop after it

    d._run_sweep_once = sweep_once  # type: ignore[method-assign]
    await asyncio.wait_for(d._sweep_loop(), timeout=10.0)

    faults = _faults(caplog, _DISPATCHER_LOGGER, logging.WARNING)
    assert [_count(f) for f in faults] == [1, 2, 4, 8]
    assert all(_carries_a_traceback(f) for f in faults)
    assert _recoveries(caplog, _DISPATCHER_LOGGER) == [
        "StageDispatcher ingress sweep recovered after 9 consecutive failures"
    ]


class _ClaimOutageStore:
    def __init__(self, fail_times: int) -> None:
        self.calls = 0
        self.fail_times = fail_times

    async def claim_fifo_heads(self, *a: Any, **k: Any) -> ClaimedHeads:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("simulated store outage: database is locked")
        return ClaimedHeads(by_lane={}, rearm=frozenset())


async def test_the_pooled_claimer_backs_off_its_traceback(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    monkeypatch.setattr(stage_dispatcher, "_CLAIM_ERROR_BACKOFF_SECONDS", 0.0)
    d = _dispatcher(_ClaimOutageStore(fail_times=5))
    claimer = d._claimers[0]
    for _ in range(7):  # five failed claims, then two that return
        await d._claim_and_dispatch(claimer, [])

    faults = _faults(caplog, _DISPATCHER_LOGGER, logging.WARNING)
    assert [_count(f) for f in faults] == [1, 2, 4]
    assert _recoveries(caplog, _DISPATCHER_LOGGER) == [
        "StageDispatcher ingress claim recovered after 5 consecutive failures"
    ]
    assert claimer.faults == FailureRun()


class _LockTimeoutThenCleanStore:
    """Two raised claims, then one that yields on a lock timeout (#1270), then a clean one."""

    def __init__(self) -> None:
        self.calls = 0

    async def claim_fifo_heads(self, *a: Any, **k: Any) -> ClaimedHeads:
        self.calls += 1
        if self.calls <= 2:
            raise RuntimeError("simulated store outage: database is locked")
        if self.calls == 3:
            timeout = ClaimLockTimeout(phase=ClaimAbortPhase.HEAD, lanes_in_claim=0)
            return ClaimedHeads(by_lane={}, rearm=frozenset(), lock_timeout=timeout)
        return ClaimedHeads(by_lane={}, rearm=frozenset())


async def test_a_claim_that_yields_on_a_lock_timeout_does_not_close_the_claimers_run(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    monkeypatch.setattr(stage_dispatcher, "_CLAIM_ERROR_BACKOFF_SECONDS", 0.0)
    d = _dispatcher(_LockTimeoutThenCleanStore())
    claimer = d._claimers[0]
    for _ in range(3):
        await d._claim_and_dispatch(claimer, [])
    assert not _recoveries(caplog, _DISPATCHER_LOGGER)  # the store is still in trouble
    assert claimer.faults.count == 2
    await d._claim_and_dispatch(claimer, [])
    assert _recoveries(caplog, _DISPATCHER_LOGGER) == [
        "StageDispatcher ingress claim recovered after 2 consecutive failures"
    ]


async def test_stopping_mid_outage_says_the_run_ended_without_a_recovery(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    monkeypatch.setattr(stage_dispatcher, "_CLAIM_ERROR_BACKOFF_SECONDS", 0.0)
    d = _dispatcher(_ClaimOutageStore(fail_times=99))
    claimer = d._claimers[0]
    for _ in range(3):
        await d._claim_and_dispatch(claimer, [])
    assert d._abandon(claimer.faults, "claim") == FailureRun()
    assert d._abandon(FailureRun(), "sweep") == FailureRun()  # a healthy run says nothing
    assert [r.getMessage() for r in caplog.records if "stopped with" in r.getMessage()] == [
        "StageDispatcher ingress claim: stopped with 3 consecutive failures and no recovery"
    ]
