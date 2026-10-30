# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connscale ``sandbox_modes`` axis, its warm-up, and the check that a subprocess arm really ran
its workers (BACKLOG #3132, steps 3, 5 and 7).

No engine is spawned here: the sweep is driven with a stand-in step, and the warm-up with a stand-in
driver. Synthetic values only.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from harness.load.connscale import runner as runner_mod
from harness.load.connscale.profile import (
    ConnScaleProfileError,
    get_connscale_profile,
    load_connscale_profile_text,
)
from harness.load.connscale.report import ConnScaleRecord, SandboxReading
from harness.load.connscale.runner import (
    _build_record,
    _node_env,
    _sandbox_reading,
    _warm_up,
    run_connscale,
    sweep_step_count,
)
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram, LiveMetrics

_SANDBOX_AB = """
[connscale]
name = "sandbox-ab"
counts = [10, 20]
aggregate_rate = 5.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
sandbox_modes = ["off", "subprocess"]
warmup_timeout_s = 30.0
"""


def _profile(extra: str = "", *, base: str = _SANDBOX_AB) -> Any:
    return load_connscale_profile_text(base + extra)


# --- the profile ----------------------------------------------------------------------------------


def test_a_profile_without_the_axis_is_unchanged() -> None:
    p = load_connscale_profile_text('[connscale]\nname = "x"\ncounts = [5]\n')
    assert p.sandbox_modes == ("off",)
    assert p.warmup_timeout_s == 0.0
    assert "sandbox_modes" not in p.ab_axes()


def test_the_axis_parses_and_counts_toward_the_sweep() -> None:
    p = _profile()
    assert p.sandbox_modes == ("off", "subprocess")
    assert p.ab_axes() == ("sandbox_modes",)
    # 1 claim x 1 fuse x 1 batch x 2 sandbox x 1 sweep mode x 2 counts x 1 trial
    assert sweep_step_count(p) == 4


@pytest.mark.parametrize(
    ("text", "match"),
    [
        (_SANDBOX_AB.replace("warmup_timeout_s = 30.0", ""), "warmup_timeout_s must be > 0"),
        (_SANDBOX_AB.replace('"subprocess"]', '"thread"]'), "sandbox_modes entry"),
        (_SANDBOX_AB.replace('["off", "subprocess"]', "[]"), "non-empty list"),
        (
            _SANDBOX_AB.replace('claim_modes = ["pooled"]', 'claim_modes = ["per_lane", "pooled"]'),
            "cannot BOTH be multi-arm",
        ),
        (
            _SANDBOX_AB + "\n[connscale.slo]\nfd_monotonic = true\n",
            "would mix the two sandbox arms",
        ),
    ],
)
def test_the_axis_refuses_a_profile_it_cannot_measure(text: str, match: str) -> None:
    with pytest.raises(ConnScaleProfileError, match=match):
        load_connscale_profile_text(text)


def test_a_fused_subprocess_arm_is_refused() -> None:
    # The engine disables fusion under the subprocess sandbox, so "fused" would be a false label.
    text = _SANDBOX_AB.replace('["off", "subprocess"]', '["subprocess"]') + "fuse_modes = [true]\n"
    with pytest.raises(ConnScaleProfileError, match="disables fusion"):
        load_connscale_profile_text(text)


def test_the_shipped_sandbox_ab_records_750_beside_1500_on_pooled() -> None:
    p = get_connscale_profile("connscale_sandbox_ab")
    assert p.sandbox_modes == ("off", "subprocess")
    assert p.claim_modes == ("pooled",)
    assert set(p.counts) >= {750, 1500}
    assert p.warmup_timeout_s > 0.0


# --- the environment and the stamp ----------------------------------------------------------------


def _env(**kw: Any) -> dict[str, str]:
    return _node_env(
        {},
        count=5,
        base_port=2600,
        transform="cheap",
        sink_host="127.0.0.1",
        sink_port=2700,
        sink_ports=1,
        install_executor_shim=False,
        db_path=None,
        **kw,
    )


def test_the_engine_environment_pins_the_arm() -> None:
    assert _env()["MEFOR_SANDBOX_MODE"] == "off"  # pinned, so an inherited value cannot decide it
    assert _env(sandbox_mode="subprocess")["MEFOR_SANDBOX_MODE"] == "subprocess"
    # An inherited value is overridden, not kept.
    env = _node_env(
        {"MEFOR_SANDBOX_MODE": "subprocess"},
        count=5,
        base_port=2600,
        transform="cheap",
        sink_host="127.0.0.1",
        sink_port=2700,
        sink_ports=1,
        install_executor_shim=False,
        db_path=None,
    )
    assert env["MEFOR_SANDBOX_MODE"] == "off"


def test_the_stamp_is_what_the_engine_parser_reads() -> None:
    reading = _sandbox_reading("subprocess", _env(sandbox_mode="subprocess"))
    assert (reading.requested, reading.effective) == ("subprocess", "subprocess")
    assert reading.startup_seconds == 30.0  # the engine default, read rather than assumed
    custom = _sandbox_reading(
        "subprocess", {**_env(sandbox_mode="subprocess"), "MEFOR_SANDBOX_STARTUP_SECONDS": "12.5"}
    )
    assert custom.startup_seconds == 12.5
    unparsed = _sandbox_reading("subprocess", {"MEFOR_SANDBOX_MODE": "nonsense"})
    assert (unparsed.effective, unparsed.startup_seconds) == (None, None)


# --- the warm-up ----------------------------------------------------------------------------------


#: The stand-in driver never reads the corpus.
_NO_CORPUS: Any = object()


class _Driver:
    """Queues one send per connection and delivers ``deliver`` of them after a short delay."""

    def __init__(self, metrics: LiveMetrics, *, count: int, deliver: int) -> None:
        self._m = metrics
        self._count = count
        self._deliver = deliver
        self.task: asyncio.Task[None] | None = None

    def send_one_each(self, *, corpus: object, mix: object) -> int:
        self.task = asyncio.create_task(self._arrive())
        return self._count

    async def _arrive(self) -> None:
        await asyncio.sleep(0.01)
        for i in range(self._deliver):
            self._m.e2e.record(float((i + 1) * 1_000_000))  # 1 ms, 2 ms, ...
            self._m.counters.sink_received += 1


async def test_the_warm_up_waits_for_every_first_delivery_and_keeps_it_out_of_the_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    walks = iter([3, 13])  # the engine subtree before and after: 10 processes started
    monkeypatch.setattr(runner_mod, "subtree_size", lambda _pid: next(walks))
    hold_ack, hold_e2e = Histogram(), Histogram()
    metrics = LiveMetrics(Counters(), hold_ack, hold_e2e)
    # A stand-in for ConnScaleDriver: only send_one_each is called.
    driver: Any = _Driver(metrics, count=10, deliver=10)
    start = SandboxReading(requested="subprocess", effective="subprocess", startup_seconds=30.0)

    reading = await _warm_up(
        start, driver=driver, corpus=_NO_CORPUS, metrics=metrics, pid=4242, timeout=5.0
    )

    assert (reading.warmup_sent, reading.warmup_delivered) == (10, 10)
    assert reading.processes_started == 10
    assert reading.warmup_first_delivery_max_ms == pytest.approx(10.0, rel=0.02)
    # The hold's histograms are back in place and hold none of the warm-up.
    assert metrics.ack is hold_ack and metrics.e2e is hold_e2e
    assert hold_e2e.count == 0


async def test_a_warm_up_that_runs_out_is_recorded_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner_mod, "subtree_size", lambda _pid: None)  # the walk did not read
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    # A stand-in for ConnScaleDriver: only send_one_each is called.
    driver: Any = _Driver(metrics, count=10, deliver=4)
    start = SandboxReading(requested="subprocess", effective="subprocess", startup_seconds=30.0)

    reading = await _warm_up(
        start, driver=driver, corpus=_NO_CORPUS, metrics=metrics, pid=4242, timeout=0.3
    )

    assert (reading.warmup_sent, reading.warmup_delivered) == (10, 4)
    assert reading.warmup_ran
    assert reading.processes_started is None


# --- the sweep and its SLOs -----------------------------------------------------------------------


def _sample(n: int) -> EngineSample:
    return EngineSample(
        elapsed_s=0.0,
        pending=0,
        inflight=0,
        done=n,
        dead=0,
        read=n,
        written=n,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=0.0,
    )


def _record(count: int, sandbox: SandboxReading) -> ConnScaleRecord:
    poller = EnginePoller("http://127.0.0.1:1", token=None, origin=0.0)
    poller._samples = [_sample(0), _sample(4)]
    return _build_record(
        claim_mode="pooled",
        fuse_mode=False,
        batch_mode=False,
        mode="fixed_aggregate",
        count=count,
        aggregate_rate=5.0,
        metrics_counters=Counters(sent=4, acked=4, sink_received=4),
        ack_hist=Histogram(),
        poller=poller,
        samples=[],
        in_hold_samples=0,
        in_hold_floor_ticks=0,
        proc_readings=[],
        drain_seconds=1.0,
        reload_seconds=None,
        sandbox=sandbox,
    )


def _reading(mode: str, count: int, *, started: int | None, effective: str | None = None) -> Any:
    return SandboxReading(
        requested=mode,
        effective=mode if effective is None else effective,
        startup_seconds=30.0,
        processes_before_warmup=None if started is None else 3,
        processes_after_warmup=None if started is None else 3 + started,
        warmup_sent=count,
        warmup_delivered=count,
        warmup_seconds=0.5,
    )


async def _sweep(
    monkeypatch: pytest.MonkeyPatch, started: dict[str, int | None], **reading_kw: Any
) -> Any:
    calls: list[tuple[str, int]] = []

    async def _step(
        _profile: object, *, sandbox_mode: str, count: int, **_kw: Any
    ) -> ConnScaleRecord:
        calls.append((sandbox_mode, count))
        return _record(
            count, _reading(sandbox_mode, count, started=started[sandbox_mode], **reading_kw)
        )

    monkeypatch.setattr(runner_mod, "_run_one_step", _step)
    report = await run_connscale(_profile(), engine_api_port_base=9000, sink_port=8000)
    assert sorted(calls) == [("off", 10), ("off", 20), ("subprocess", 10), ("subprocess", 20)]
    return report


def _check(report: Any, name: str) -> Any:
    (check,) = [c for c in report.slos if c.name == name]
    return check


async def test_a_subprocess_arm_with_a_worker_per_inbound_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 2 processes per worker tree, as a Windows venv starts them.
    report = await _sweep(monkeypatch, {"off": 0, "subprocess": 40})
    assert _check(report, "sandbox_workers").ok, report.slos
    assert _check(report, "warmup_delivered").ok
    assert {r.sandbox_mode for r in report.records} == {"off", "subprocess"}
    assert report.result_ok


@pytest.mark.parametrize(
    ("started", "says"),
    [
        (0, "started 0 process(es)"),  # the arm silently ran in-process
        (None, "did not read"),  # an instrument that did not read vouches for nothing
    ],
)
async def test_a_subprocess_arm_that_proves_no_workers_fails(
    monkeypatch: pytest.MonkeyPatch, started: int | None, says: str
) -> None:
    report = await _sweep(monkeypatch, {"off": 0, "subprocess": started})
    check = _check(report, "sandbox_workers")
    assert not check.ok
    assert says in str(check.observed)
    assert not report.result_ok


async def test_an_arm_the_engine_parses_differently_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = await _sweep(monkeypatch, {"off": 0, "subprocess": 40}, effective="off")
    check = _check(report, "sandbox_workers")
    assert not check.ok
    assert "parses mode 'off'" in str(check.observed)


def test_the_sandbox_reading_is_in_the_artifact() -> None:
    record = _record(10, _reading("subprocess", 10, started=20))
    payload = record.to_json_dict()["sandbox"]
    assert isinstance(payload, dict)
    assert payload["requested"] == "subprocess"
    assert payload["processes_started"] == 20
    warmup = payload["warmup"]
    assert isinstance(warmup, dict)
    assert warmup["delivered"] == 10
