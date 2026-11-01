# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connscale ``sandbox_modes`` axis, its warm-up, and the check that a subprocess arm really ran
its workers (BACKLOG #3132, steps 3, 5 and 7).

No engine is spawned here: the sweep is driven with a stand-in step, and the warm-up with a stand-in
driver. Synthetic values only.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import inspect
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from harness.config.connscale._shape import ConnScaleShape, make_connscale_shape
from harness.load.connscale import probe
from harness.load.connscale import profile as profile_mod
from harness.load.connscale import runner as runner_mod
from harness.load.connscale.batchbox import iter_batch_cells
from harness.load.connscale.intake_audit import VERDICT_INVARIANT_SUSPECT, not_run
from harness.load.connscale.profile import (
    ConnScaleProfileError,
    get_connscale_profile,
    load_connscale_profile_text,
)
from harness.load.connscale.report import ConnScaleRecord, SandboxReading
from harness.load.connscale.runner import (
    ConnScaleError,
    _build_record,
    _node_env,
    _sandbox_reading,
    _warm_up,
    run_connscale,
    sweep_step_count,
)
from harness.load.connscale.stepconfig import graph_module_text
from harness.load.correlator import Correlator
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
    # Every step's shape is accepted with the CLI's default sink port, so the documented invocation
    # does not miss every step at config generation.
    for count in p.counts:
        make_connscale_shape(count=count, base_port=p.base_port, sink_port=2700)


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
    """Queues one send per connection, and after a short delay the correlator takes one arrival for
    each seq in ``arrivals``."""

    def __init__(self, correlator: Correlator, *, count: int, arrivals: Sequence[int]) -> None:
        self._correlator = correlator
        self._count = count
        self._arrivals = arrivals
        self.task: asyncio.Task[None] | None = None

    def send_one_each(self, *, corpus: object, mix: object) -> list[int]:
        for seq in range(self._count):
            self._correlator.on_send(seq, 0)
        self.task = asyncio.create_task(self._arrive())
        return list(range(self._count))

    async def _arrive(self) -> None:
        await asyncio.sleep(0.01)
        for i, seq in enumerate(self._arrivals):
            self._correlator.on_recv(seq, (i + 1) * 1_000_000)  # 1 ms, 2 ms, ...


async def _warm(
    metrics: LiveMetrics, *, arrivals: Sequence[int], pid: int | None, timeout: float
) -> SandboxReading:
    """Run the warm-up over 10 connections, with a stand-in for ConnScaleDriver: only send_one_each
    is called."""
    correlator = Correlator(64, metrics)
    driver: Any = _Driver(correlator, count=10, arrivals=arrivals)
    return await _warm_up(
        SandboxReading(requested="subprocess", effective="subprocess", startup_seconds=30.0),
        driver=driver,
        corpus=_NO_CORPUS,
        metrics=metrics,
        correlator=correlator,
        pid=pid,
        timeout=timeout,
    )


async def test_the_warm_up_waits_for_every_first_delivery_and_keeps_it_out_of_the_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    walks = iter([3, 13])  # the engine subtree before and after: 10 processes started
    monkeypatch.setattr(runner_mod, "subtree_size", lambda _pid: next(walks))
    hold_ack, hold_e2e = Histogram(), Histogram()
    metrics = LiveMetrics(Counters(), hold_ack, hold_e2e)

    reading = await _warm(metrics, arrivals=range(10), pid=4242, timeout=5.0)

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

    reading = await _warm(metrics, arrivals=range(4), pid=4242, timeout=0.3)

    assert (reading.warmup_sent, reading.warmup_delivered) == (10, 4)
    assert reading.warmup_ran
    assert reading.processes_started is None


async def test_a_redelivery_does_not_stand_in_for_a_connection_that_never_delivered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connection 0 delivers twice and connection 9 never does. The sink saw 10 arrivals for 10
    sends, so a count of arrivals reads 10 of 10 and ends the wait at once; 9 of 10 is the truth."""
    monkeypatch.setattr(runner_mod, "subtree_size", lambda _pid: None)
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())

    reading = await _warm(metrics, arrivals=[0, 0, 1, 2, 3, 4, 5, 6, 7, 8], pid=None, timeout=0.3)

    assert metrics.counters.sink_received == 10
    assert (reading.warmup_sent, reading.warmup_delivered) == (10, 9)


def _compare_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    out: Path,
    *,
    profile_text: str,
) -> str:
    """What ``--report-compare`` tells an operator when the run produced no comparison table."""
    import harness.__main__ as hmain

    async def no_engine(_profile: object, **_kwargs: object) -> object:
        return SimpleNamespace(
            render_console=lambda: "report",
            comparison=None,
            fuse_comparison=None,
            batch_comparison=None,
            exit_code=0,
        )

    profile = load_connscale_profile_text(profile_text)
    monkeypatch.setattr(profile_mod, "get_connscale_profile", lambda _name: profile)
    monkeypatch.setattr(runner_mod, "run_connscale", no_engine)
    args = argparse.Namespace(
        connscale="stand-in",
        connscale_api_port=None,
        sink_port=None,
        sink_ports=None,
        report_json=None,
        report_csv=None,
        report_compare=str(out),
    )
    assert hmain._run_connscale(args) == 0
    assert not out.exists()
    return capsys.readouterr().err


def test_report_compare_says_a_sandbox_ab_has_no_table_rather_than_no_ab(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A sandbox A/B has two arms and no comparison in report.py, so "no A/B" would be false, and
    offering ``sandbox_modes`` beside the other axes would send an operator to a table that does
    not exist. The single-arm message is the control."""
    sandbox = _compare_stderr(monkeypatch, capsys, tmp_path / "out.txt", profile_text=_SANDBOX_AB)
    assert "a sandbox A/B has no comparison table" in sandbox
    assert "per-arm rows" in sandbox
    assert "no A/B" not in sandbox

    single = _compare_stderr(
        monkeypatch,
        capsys,
        tmp_path / "out.txt",
        profile_text=_SANDBOX_AB.replace('["off", "subprocess"]', '["off"]').replace(
            "warmup_timeout_s = 30.0\n", ""
        ),
    )
    assert "no A/B to write" in single
    assert "sandbox" not in single


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


def _only(checks: Any, name: str) -> Any:
    (check,) = [c for c in checks if c.name == name]
    return check


def _check(report: Any, name: str) -> Any:
    return _only(report.slos, name)


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


async def test_the_console_tells_the_two_arms_of_an_ab_apart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CSV and JSON carry the arm. Without it the console printed two rows, and two notes, with one
    label for each count."""
    report = await _sweep(monkeypatch, {"off": 0, "subprocess": 40})
    lines = report.render_console().splitlines()
    assert any(line.startswith("claim") and "sandbox" in line for line in lines), lines
    rows = [line.split() for line in lines if line.startswith("pooled")]
    assert sorted((row[2], int(row[3])) for row in rows) == [
        ("off", 10),
        ("off", 20),
        ("subprocess", 10),
        ("subprocess", 20),
    ]
    degraded = [
        dataclasses.replace(r, fd_probe_ticks=2, fd_probe_degraded_ticks=1) for r in report.records
    ]
    console = dataclasses.replace(report, records=degraded).render_console()
    notes = [line for line in console.splitlines() if line.startswith("fd probe:")]
    assert len(notes) == 4
    assert len(set(notes)) == 4, notes
    assert len({r.step_label for r in report.records}) == 4
    suspect = dataclasses.replace(not_run("synthetic"), verdict=VERDICT_INVARIANT_SUSPECT)
    audited = [dataclasses.replace(r, intake_audit=suspect) for r in report.records]
    console = dataclasses.replace(report, records=audited).render_console()
    assert "fixed_aggregate/pooled@N=10 sandbox=subprocess --" in console
    checks = runner_mod._evaluate_slos(dataclasses.replace(_profile(), intake_audit=True), audited)
    assert "fixed_aggregate/pooled@N=10 sandbox=subprocess" in str(_only(checks, "intake_audit"))


def test_the_sandbox_reading_is_in_the_artifact() -> None:
    record = _record(10, _reading("subprocess", 10, started=20))
    payload = record.to_json_dict()["sandbox"]
    assert isinstance(payload, dict)
    assert payload["requested"] == "subprocess"
    assert payload["processes_started"] == 20
    warmup = payload["warmup"]
    assert isinstance(warmup, dict)
    assert warmup["delivered"] == 10


# --- review round 1 -------------------------------------------------------------------------------


def test_a_non_finite_warm_up_is_refused() -> None:
    for value in ("nan", "inf"):
        text = _SANDBOX_AB.replace("warmup_timeout_s = 30.0", f"warmup_timeout_s = {value}")
        with pytest.raises(ConnScaleProfileError, match="finite"):
            load_connscale_profile_text(text)


def test_the_batch_box_refuses_a_sandbox_or_warm_up_profile() -> None:
    with pytest.raises(ConnScaleError, match="no sandbox arm"):
        iter_batch_cells(_profile(), claim_mode="pooled")
    plain = load_connscale_profile_text('[connscale]\nname = "x"\ncounts = [5]\n')
    assert iter_batch_cells(plain, claim_mode="pooled")  # the control: an ordinary profile runs


def test_the_generator_writes_every_shape_field() -> None:
    fields = {f.name for f in dataclasses.fields(ConnScaleShape)}
    # The generated call passes every field by name, so the two must be the same set.
    assert fields == set(inspect.signature(make_connscale_shape).parameters)
    text = graph_module_text(make_connscale_shape())
    for name in fields:
        assert f"        {name}=" in text


def test_an_unreadable_posix_walk_is_no_reading_not_no_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "_WINDOWS", False)
    # No /proc, or no row for the root: no reading, never "1 process".
    monkeypatch.setattr(probe.FdSampler, "_enumerate_posix", lambda _self: [])
    assert probe.subtree_size(4242) is None
    # The control: a snapshot holding the root and two children it started.
    rows = [(4242, 1, 100.0), (5000, 4242, 101.0), (5001, 4242, 102.0), (6000, 1, 99.0)]
    monkeypatch.setattr(probe.FdSampler, "_enumerate_posix", lambda _self: rows)
    assert probe.subtree_size(4242) == 3


async def test_a_sandbox_arm_miss_is_not_labelled_pooled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _step(
        _profile: object, *, sandbox_mode: str, count: int, **_kw: Any
    ) -> ConnScaleRecord:
        if sandbox_mode == "subprocess":
            raise ConnScaleError("engine failed to start (synthetic)")
        return _record(count, _reading("off", count, started=0))

    monkeypatch.setattr(runner_mod, "_run_one_step", _step)
    report = await run_connscale(_profile(), engine_api_port_base=9000, sink_port=8000)
    assert any(n.startswith("SANDBOX ARM MISSING") for n in report.notes), report.notes
    assert not any("POOLED ARM MISSING" in n for n in report.notes)
    assert "no subprocess step was recorded" in str(_check(report, "sandbox_workers").observed)
    assert not report.result_ok


# --- review round 2 -------------------------------------------------------------------------------


def test_a_reload_probe_with_a_subprocess_arm_is_refused() -> None:
    with pytest.raises(ConnScaleProfileError, match="reload_probe"):
        load_connscale_profile_text(_SANDBOX_AB + "reload_probe = true\n")


_PER_LANE_SANDBOX_AB = _SANDBOX_AB.replace('claim_modes = ["pooled"]', 'claim_modes = ["per_lane"]')


async def test_a_per_lane_sandbox_ab_records_a_subprocess_miss_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _step(
        _profile: object, *, sandbox_mode: str, count: int, **_kw: Any
    ) -> ConnScaleRecord:
        if sandbox_mode == "subprocess" and count == 20:
            raise ConnScaleError("engine failed to start (synthetic)")
        return _record(count, _reading(sandbox_mode, count, started=40 if count else 0))

    monkeypatch.setattr(runner_mod, "_run_one_step", _step)
    profile = _profile(base=_PER_LANE_SANDBOX_AB)
    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)
    # The subprocess arm stopping short of the top count is a result, recorded, not a crash.
    assert len(report.records) == 3
    assert any("SANDBOX ARM MISSING" in n and "N=20" in n for n in report.notes), report.notes
    assert not report.result_ok


async def test_a_failed_baseline_arm_of_a_sandbox_ab_is_a_setup_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _step(_profile: object, *, sandbox_mode: str, **_kw: Any) -> ConnScaleRecord:
        raise ConnScaleError(f"engine failed to start (synthetic, {sandbox_mode})")

    monkeypatch.setattr(runner_mod, "_run_one_step", _step)
    with pytest.raises(ConnScaleError, match="synthetic, off"):
        await run_connscale(_profile(), engine_api_port_base=9000, sink_port=8000)


def test_a_warm_up_check_with_no_step_is_not_a_pass() -> None:
    check = runner_mod._warmup_slo([])
    assert not check.ok
    assert "no step was recorded" in str(check.observed)
