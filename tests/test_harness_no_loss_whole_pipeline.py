# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The no-loss reconciles judge the WHOLE pipeline, and the connscale SLOs refuse a vacuous or
masked green (BACKLOG #5432, #5433, #5434, #5435).

``EngineSample.backlog`` used to be the outbound ``pending + inflight`` alone. A router or transform
that stalled leaves every accepted message in the ingress or routed stage: the outbound backlog reads
0, nothing is written, nothing reaches the sink, and the load reconcile's three arms (intake,
delivery, drained) all held, so a run that delivered nothing passed zero-loss once the drain wait
timed out. ``backlog`` now folds in the whole-pipeline ``in_pipeline`` gauge, so every reconcile that
reads it (load, connscale, estate, multishard and the remote driver) sees a stranded row.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from harness.load.connscale import runner as runner_mod
from harness.load.connscale.profile import ConnScaleProfile, load_connscale_profile_text
from harness.load.connscale.report import ConnScaleRecord, SloCheck
from harness.load.connscale.runner import _evaluate_slos, run_connscale
from harness.load.connscale.runner import _reconcile as connscale_reconcile
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.estate.runner import _reconcile as estate_reconcile
from harness.load.metrics import Counters
from harness.load.report import _reconcile as load_reconcile


def _sample(
    *, read: int, written: int, pending: int = 0, inflight: int = 0, in_pipeline: int = 0
) -> EngineSample:
    return EngineSample(
        elapsed_s=1.0,
        pending=pending,
        inflight=inflight,
        done=written,
        dead=0,
        read=read,
        written=written,
        out_dead=0,
        queue_depth=pending + inflight,
        in_pipeline=in_pipeline,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=1.0,
    )


_BASE = _sample(read=0, written=0)


def _poller(final: EngineSample) -> EnginePoller:
    return cast(EnginePoller, SimpleNamespace(baseline=_BASE, final=final, samples=[_BASE, final]))


# --- #5435: the sample ---------------------------------------------------------------------------


def test_backlog_counts_rows_stranded_before_the_outbound_stage() -> None:
    # A stalled router: nothing reached the outbound stage, everything is still in ingress/routed.
    assert _sample(read=10, written=0, in_pipeline=10).backlog == 10


def test_backlog_takes_the_larger_read_rather_than_double_counting() -> None:
    # `in_pipeline` already counts the outbound rows, so the two are not summed. They come from two
    # separate store reads, so either can be the larger one; the larger is the fail-closed read.
    assert _sample(read=5, written=0, pending=3, inflight=2, in_pipeline=5).backlog == 5
    assert _sample(read=5, written=0, pending=3, inflight=2, in_pipeline=4).backlog == 5
    assert _sample(read=5, written=0, pending=1, inflight=0, in_pipeline=4).backlog == 4
    assert _sample(read=5, written=5).backlog == 0


def test_load_reconcile_fails_a_run_whose_router_stalled_every_message() -> None:
    # 90 accepted, 90 committed to ingress, the router never ran. Nothing was written, so
    # `sink_received >= written` holds (0 >= 0); only the whole-pipeline drain term can fail it.
    c = Counters(sent=90, acked=90, sink_received=0)
    result = load_reconcile(
        c,
        _poller(_sample(read=90, written=0, in_pipeline=90)),
        None,
        tolerance=0,
        unconfirmed_budget=4,
    )
    assert not result.ok
    assert result.backlog == 90
    assert "in_pipeline 90 not done" in result.detail


def test_load_reconcile_still_passes_a_drained_run() -> None:
    # The control: the same run with the pipeline empty and every message delivered passes.
    c = Counters(sent=90, acked=90, sink_received=90)
    assert load_reconcile(
        c, _poller(_sample(read=90, written=90)), 1.0, tolerance=0, unconfirmed_budget=4
    ).ok


def test_estate_reconcile_sees_the_stranded_rows_through_the_sample() -> None:
    # The estate copy is not edited here: it reads `final.backlog`, so the sample carries the fix.
    c = Counters(sent=36, acked=36, sink_received=0)
    result = estate_reconcile(
        c, _BASE, _sample(read=36, written=0, in_pipeline=36), unconfirmed_budget=2
    )
    assert not result.ok
    assert result.backlog == 36
    # The control: the same estate run, drained and delivered, passes.
    c = Counters(sent=36, acked=36, sink_received=36)
    assert estate_reconcile(c, _BASE, _sample(read=36, written=36), unconfirmed_budget=2).ok


# --- #5433: the connscale reconcile ---------------------------------------------------------------


def test_connscale_reconcile_fails_rows_left_upstream_when_the_counts_cancel() -> None:
    # The case `written >= read` cannot see: counts that balance (a row carried over from before the
    # baseline, or a duplicated handoff, cancels a lost one) while rows still sit in ingress/routed.
    # Drained used to be the outbound backlog alone, so this passed.
    c = Counters(sent=36, acked=36, sink_received=36)
    result = connscale_reconcile(
        c, _BASE, _sample(read=36, written=36, in_pipeline=5), unconfirmed_budget=2
    )
    assert not result.ok
    assert "backlog 5 not drained" in result.detail


def test_connscale_reconcile_fails_a_stalled_router() -> None:
    c = Counters(sent=36, acked=36, sink_received=0)
    result = connscale_reconcile(
        c, _BASE, _sample(read=36, written=0, in_pipeline=36), unconfirmed_budget=2
    )
    assert not result.ok
    assert "backlog 36 not drained" in result.detail


def test_connscale_reconcile_still_passes_a_drained_run() -> None:
    c = Counters(sent=36, acked=36, sink_received=36)
    assert connscale_reconcile(c, _BASE, _sample(read=36, written=36), unconfirmed_budget=2).ok


# --- #5432 and #5434: the connscale SLOs ----------------------------------------------------------


def _profile(*, max_drain_seconds: float | None = None) -> ConnScaleProfile:
    drain = "" if max_drain_seconds is None else f"max_drain_seconds = {max_drain_seconds}\n"
    return load_connscale_profile_text(
        "[connscale]\n"
        'name = "slo-guard"\n'
        "counts = [4]\n"
        "base_port = 41000\n"
        "aggregate_rate = 10.0\n"
        "intake_audit = false\n"
        "\n"
        "[connscale.slo]\n"
        "zero_loss = true\n" + drain
    )


def _rec(*, ok: bool = True, drain_seconds: float | None = 1.0) -> ConnScaleRecord:
    # Only the two attributes these SLOs read; cast once so the call sites stay clean.
    return cast(
        ConnScaleRecord,
        SimpleNamespace(no_loss=SimpleNamespace(ok=ok), drain_seconds=drain_seconds),
    )


def _check(profile: ConnScaleProfile, records: list[ConnScaleRecord], name: str) -> SloCheck:
    return next(c for c in _evaluate_slos(profile, records) if c.name == name)


def test_zero_loss_refuses_an_empty_record_list() -> None:
    # `all()` over nothing is True: a sweep that measured no step would have read zero-loss PASS.
    # `_evaluate_slos` is shared with the batch-box aggregate, so the guard lives here.
    check = _check(_profile(), [], "zero_loss")
    assert not check.ok
    assert check.observed == "no step was recorded"  # not a loss reading
    assert _check(_profile(), [_rec()], "zero_loss").ok


def test_max_drain_seconds_is_poisoned_by_one_timed_out_step() -> None:
    # A timed-out drain is None. Dropping it before the max let a sibling that drained in time
    # mask the step that never drained, matching neither the batchbox nor the compare copy.
    profile = _profile(max_drain_seconds=60.0)
    masked = _check(
        profile, [_rec(drain_seconds=1.0), _rec(drain_seconds=None)], "max_drain_seconds"
    )
    assert not masked.ok
    assert masked.observed == -1.0
    clean = _check(profile, [_rec(drain_seconds=1.0), _rec(drain_seconds=2.5)], "max_drain_seconds")
    assert clean.ok and clean.observed == 2.5
    assert not _check(profile, [], "max_drain_seconds").ok


_EMPTY_SWEEP = """
[connscale]
name = "empty-sweep"
counts = [4]
aggregate_rate = 10.0
intake_audit = false

[connscale.slo]
zero_loss = false
"""


async def test_a_sweep_that_recorded_nothing_does_not_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    # The verdict itself refuses an empty record list, so a profile that grades no SLO on it
    # (zero_loss off) cannot exit 0 on a sweep that measured nothing. No step runs here at all.
    async def _never(*_a: Any, **_kw: Any) -> object:
        raise AssertionError("no step should run")

    monkeypatch.setattr(runner_mod, "_run_one_step", _never)
    monkeypatch.setattr(ConnScaleProfile, "modes", lambda _self: ())
    profile = load_connscale_profile_text(_EMPTY_SWEEP)
    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)
    assert report.records == []
    assert all(c.ok for c in report.slos)  # the control: no SLO fails it
    assert not report.result_ok
    assert any("NO STEP WAS RECORDED" in n for n in report.notes), report.notes
