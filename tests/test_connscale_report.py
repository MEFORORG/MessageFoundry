# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale report (B11) — curve schema, no-loss, the SEPARATED herd metric, monotonicity."""

from __future__ import annotations

import json

from harness.load.connscale.report import (
    ConnScaleRecord,
    ConnScaleReport,
    NoLoss,
    SloCheck,
)
from harness.load.connscale.runner import _monotonic_slo


def _record(
    *,
    mode: str,
    count: int,
    fd: int | None = 100,
    empty_per_s: float = 10.0,
    idle_per_s: float = 4.0,
    wake_per_s: float = 6.0,
    no_loss_ok: bool = True,
    pool_p99: float | None = None,
) -> ConnScaleRecord:
    return ConnScaleRecord(
        sweep_mode=mode,
        count=count,
        offered_aggregate_rate=35.0,
        sent=1000,
        acked=1000,
        nak=0,
        deferred=0,
        no_loss=NoLoss(no_loss_ok, 1000, 1000, 1000, 1000, 0, "ok"),
        in_pipeline_peak=3,
        drain_seconds=1.2,
        executor_queue_depth_peak=2,
        executor_busy_peak=8,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=pool_p99,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=empty_per_s,
        idle_poll_per_s=idle_per_s,
        wake_fanout_per_s=wake_per_s,
        empty_claims_per_msg=None,
        fd_count_peak=fd,
        reload_seconds=0.05,
        ack_p50_ms=1.0,
        ack_p95_ms=2.0,
        ack_p99_ms=3.0,
    )


def _report(
    records: list[ConnScaleRecord], slos: list[SloCheck], *, backend: str | None
) -> ConnScaleReport:
    ok = all(c.ok for c in slos)
    return ConnScaleReport(
        profile="t",
        engine_url="http://127.0.0.1:8800",
        db_backend=backend,
        shim_installed=True,
        records=records,
        slos=slos,
        result_ok=ok,
        exit_code=0 if ok else 1,
    )


def test_herd_is_reported_separately_from_idle_poll() -> None:
    # Critic must-change #3: the wake-fanout (per-commit herd) and the idle-poll re-SELECT floor are
    # carried DISTINCTLY in wall #3 — never summed into one number.
    rec = _record(
        mode="fixed_aggregate", count=100, empty_per_s=10.0, idle_per_s=4.0, wake_per_s=6.0
    )
    d = rec.to_json_dict()
    w3 = d["wall3_empty_claims"]
    assert w3["total_per_s"] == 10.0
    assert w3["idle_poll_per_s"] == 4.0  # the steady poll-interval floor
    assert w3["wake_fanout_per_s"] == 6.0  # the per-commit thundering herd (read distinctly)
    # The total carries both, but the split is preserved (not collapsed).
    assert w3["idle_poll_per_s"] + w3["wake_fanout_per_s"] == w3["total_per_s"]


def test_monotonic_slo_tolerates_jitter_but_catches_regression() -> None:
    # The subject is the band arithmetic in `_monotonic_slo`, driven through the ONLY caller it still
    # has: `fd_count_monotonic` over `fd_count_peak`. BACKLOG #1211 retired the empty-claims caller.
    # This test is REPOINTED, not retuned: the three verdicts below are the three it already asserted,
    # so a red here says the FD path moved rather than that the band was resized.
    #
    # WHERE THE SHAPE COMES FROM, AND IT IS NOT FROM FD. The 25 percent tolerance was set from an
    # empty-claims/sec flake on windows-2022 (mf-ci-test-flakes: a strict `>=` failed on 398.7 against
    # a prior 442.9, a 9.98 percent dip). The FD ratio's own distribution has never been harvested. So
    # these readings probe the band's arithmetic at a known dip; they are not FD evidence and must not
    # be read as grounds for retuning `_MONOTONIC_TOLERANCE`.
    #
    # `fd_count_peak` is a descriptor COUNT, so that recorded dip is restated in whole descriptors,
    # rounded so it cannot come out smaller than the one on record: 442.9 -> 443 and 398.7 -> 398 give
    # a 10.16 percent dip, which makes the "jitter passes" assertion marginally harder to satisfy,
    # never easier. The other two pairs were already integral and are unchanged.
    def _fd(rs: list[ConnScaleRecord]) -> bool:
        return _monotonic_slo("fd_count_monotonic", rs, lambda r: r.fd_count_peak).ok

    # the recorded ~10% dip is jitter -> ok
    assert _fd(
        [
            _record(mode="fixed_aggregate", count=12, fd=443),
            _record(mode="fixed_aggregate", count=24, fd=398),
        ]
    )
    # a genuine collapse (to 0.375 of the prior, well past the band) -> fail
    assert not _fd(
        [
            _record(mode="fixed_aggregate", count=12, fd=400),
            _record(mode="fixed_aggregate", count=24, fd=150),
        ]
    )
    # a clean increase -> ok
    assert _fd(
        [
            _record(mode="fixed_per_conn", count=12, fd=100),
            _record(mode="fixed_per_conn", count=24, fd=200),
        ]
    )


def test_json_curve_schema_keyed_by_count() -> None:
    recs = [
        _record(mode="fixed_aggregate", count=50),
        _record(mode="fixed_aggregate", count=100),
    ]
    rep = _report(recs, [SloCheck("zero_loss", True, True, True)], backend="postgres")
    body = json.loads(rep.to_json())
    assert body["kind"] == "connscale"
    assert body["schema_version"] == 1
    assert [r["count"] for r in body["records"]] == [50, 100]
    # Every record carries the 6 walls.
    r0 = body["records"][0]
    for key in (
        "wall1_executor",
        "wall2_pool_wait",
        "wall3_empty_claims",
        "wall4_fd",
        "wall5_reload",
        "wall6_ack_ms",
    ):
        assert key in r0


def test_coverage_note_is_honest_on_sqlite() -> None:
    # The SQLite report must STATE that the pool wall (#2) is a no-op there (not over-read it).
    rep = _report(
        [_record(mode="fixed_aggregate", count=50)],
        [SloCheck("zero_loss", True, True, True)],
        backend=None,
    )
    body = json.loads(rep.to_json())
    assert "NO-OP" in body["coverage"]
    assert "pool" in body["coverage"].lower()


def test_csv_has_separated_herd_columns() -> None:
    rep = _report(
        [_record(mode="fixed_aggregate", count=50)],
        [SloCheck("zero_loss", True, True, True)],
        backend="postgres",
    )
    csv = rep.to_csv()
    header = csv.splitlines()[0]
    assert "idle_poll_per_s" in header and "wake_fanout_per_s" in header
    # n/a renders for a None gauge (SQLite pool wait), never a misleading 0.
    rep2 = _report(
        [_record(mode="fixed_aggregate", count=50, pool_p99=None)],
        [SloCheck("zero_loss", True, True, True)],
        backend=None,
    )
    assert "n/a" in rep2.to_csv()


def test_console_render_runs() -> None:
    rep = _report(
        [_record(mode="fixed_aggregate", count=50), _record(mode="fixed_per_conn", count=100)],
        [SloCheck("zero_loss", True, True, True)],
        backend="postgres",
    )
    text = rep.render_console()
    assert "Connection-scale report" in text
    assert "RESULT: PASS" in text
