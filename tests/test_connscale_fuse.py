# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Thread-hop-fusion A/B (ADR 0071 B5) — profile parsing, per-arm env injection, and the §6.4(b)
GO/NO-GO verdict logic. Pure + hermetic (no live engine / SQL Server)."""

from __future__ import annotations

import json

import pytest

from harness.load.connscale.compare import (
    FUSE_GO,
    FUSE_INCONCLUSIVE,
    FUSE_MISSING,
    FUSE_NO_GO,
    build_fuse_comparison,
)
from harness.load.connscale.profile import (
    ConnScaleProfileError,
    get_connscale_profile,
    list_connscale_profiles,
    load_connscale_profile_text,
)
from harness.load.connscale.report import ConnScaleRecord, NoLoss
from harness.load.connscale.runner import _node_env, run_connscale


# --------------------------------------------------------------------------- #
# B1 — profile parsing of the fuse_modes A/B axis
# --------------------------------------------------------------------------- #

_OK = """
[connscale]
name = "t"
counts = [256]
aggregate_rate = 400.0
"""


def test_fuse_modes_defaults_to_single_off() -> None:
    # Absent fuse_modes ⇒ the single-arm (False,) default, so every pre-existing profile keeps its
    # byte-identical single-arm sweep (fusion off is the engine default).
    p = load_connscale_profile_text(_OK)
    assert p.fuse_modes == (False,)


def test_fuse_modes_ab_axis_parses() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "ab"
counts = [256]
aggregate_rate = 400.0
claim_modes = ["pooled"]
fuse_modes = [false, true]
""")
    assert p.fuse_modes == (False, True)


def test_fuse_modes_dedups_first_seen_order() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "ab"
counts = [256]
aggregate_rate = 400.0
fuse_modes = [true, false, true]
""")
    assert p.fuse_modes == (True, False)


@pytest.mark.parametrize(
    "body, needle",
    [
        # not a list
        ("[connscale]\nname='x'\ncounts=[10]\nfuse_modes=true\n", "fuse_modes"),
        # empty list
        ("[connscale]\nname='x'\ncounts=[10]\nfuse_modes=[]\n", "fuse_modes"),
        # non-boolean entry (ints are a common mistake — must be rejected, not read as on/off)
        ("[connscale]\nname='x'\ncounts=[10]\nfuse_modes=[1]\n", "boolean"),
        ("[connscale]\nname='x'\ncounts=[10]\nfuse_modes=['true']\n", "boolean"),
    ],
)
def test_fuse_modes_fail_loud(body: str, needle: str) -> None:
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text(body)
    assert needle in str(exc.value)


def test_both_axes_multi_arm_is_rejected() -> None:
    # The two A/B axes each pair records one axis at a time; a profile making BOTH multi-arm would
    # produce 4 arms per cell and silently collapse each comparison's keying — fail loud.
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text("""
[connscale]
name = "both"
counts = [256]
aggregate_rate = 400.0
claim_modes = ["per_lane", "pooled"]
fuse_modes = [false, true]
""")
    assert "BOTH" in str(exc.value)


def test_fuse_ab_builtin_resolves() -> None:
    p = get_connscale_profile("fuse_ab")
    assert p.fuse_modes == (False, True)
    assert p.claim_modes == ("pooled",)
    assert p.counts == (256, 512, 1024)
    assert p.store_backend == "sqlserver"
    # PR5: one invocation banks >= 3 trials/arm so the §6.4b ">2σ" spread guard is reachable directly.
    assert p.trials == 3
    assert "fuse_ab" in list_connscale_profiles()


# --------------------------------------------------------------------------- #
# B2 — the runner injects MEFOR_PIPELINE_FUSE_THREAD_HOPS per arm
# --------------------------------------------------------------------------- #


def _env(**kw: object) -> dict[str, str]:
    base = dict(
        count=256,
        base_port=2600,
        transform="cheap",
        sink_host="127.0.0.1",
        sink_port=2700,
        sink_ports=1,
        install_executor_shim=False,
        db_path=None,
    )
    base.update(kw)
    return _node_env({}, **base)  # type: ignore[arg-type]


def test_node_env_injects_fuse_flag_on() -> None:
    env = _env(claim_mode="pooled", fuse_mode=True)
    assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "true"
    assert env["MEFOR_PIPELINE_CLAIM_MODE"] == "pooled"


def test_node_env_injects_fuse_flag_off() -> None:
    env = _env(claim_mode="pooled", fuse_mode=False)
    assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "false"


def test_node_env_fuse_defaults_off_for_prebump_callers() -> None:
    # A pre-B5 caller (e.g. multishard) omits fuse_mode ⇒ "false" (the engine default) ⇒ byte-identical.
    env = _env()
    assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "false"


# --------------------------------------------------------------------------- #
# B3 — build_fuse_comparison GO / NO-GO / INCONCLUSIVE / MISSING verdicts
# --------------------------------------------------------------------------- #


def _rec(
    *,
    fuse: bool,
    read: float,
    count: int = 256,
    claim_mode: str = "pooled",
    sweep_mode: str = "fixed_aggregate",
    in_pipeline: int = 90,
    sent: int = 1000,
    sink_received: int = 1000,
    no_loss_ok: bool = True,
    offered: float = 400.0,
    written: float | None = None,
) -> ConnScaleRecord:
    written = read if written is None else written
    detail = "ok" if no_loss_ok else f"lost {sent - sink_received}"
    return ConnScaleRecord(
        sweep_mode=sweep_mode,
        count=count,
        offered_aggregate_rate=offered,
        sent=sent,
        acked=sent,
        nak=0,
        deferred=0,
        no_loss=NoLoss(no_loss_ok, sent, sent, sink_received, sink_received, 0, detail),
        in_pipeline_peak=in_pipeline,
        drain_seconds=1.0,
        executor_queue_depth_peak=None,
        executor_busy_peak=None,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=0.0,
        idle_poll_per_s=0.0,
        wake_fanout_per_s=0.0,
        fd_count_peak=100,
        reload_seconds=None,
        ack_p50_ms=1.0,
        ack_p95_ms=2.0,
        ack_p99_ms=3.0,
        claim_mode=claim_mode,
        achieved_read_per_s=read,
        achieved_written_per_s=written,
        cpu_seconds_total=5.0,
        cpu_util_cores_mean=0.5,
        fuse_thread_hops=fuse,
    )


def _trials(fuse: bool, reads: list[float], **kw: object) -> list[ConnScaleRecord]:
    return [_rec(fuse=fuse, read=r, **kw) for r in reads]  # type: ignore[arg-type]


def test_single_fuse_mode_has_no_comparison() -> None:
    # fuse_modes = (False,) — the pre-B5 single-arm shape — yields NO fusion comparison (byte-identical).
    recs = _trials(False, [100.0])
    assert build_fuse_comparison(recs, (False,)) is None
    # A degenerate multi that isn't a real B0/B1 pair also yields None.
    assert build_fuse_comparison(_trials(True, [120.0]), (True,)) is None


def test_go_when_b1_lift_ge_10pct_and_gt_2sigma() -> None:
    # B1 ~20% faster with tight per-arm spread ⇒ diff (20/s) >> 2σ (~2.8/s) ⇒ significant ⇒ GO.
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [120.0, 121.0, 119.0])
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_GO
    assert row.significant and row.lift_pct is not None and row.lift_pct >= 10.0
    assert row.in_pipeline_ok and row.delivered_offered_ok
    assert cmp.overall_verdict == FUSE_GO
    assert cmp.ok  # correctness gate (zero-loss held, present)


def test_no_go_when_lift_below_threshold() -> None:
    # B1 only ~2% faster ⇒ below the 10% bar ⇒ NO-GO (fusion banked no worthwhile margin).
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [102.0, 103.0, 101.0])
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert cmp.overall_verdict == FUSE_NO_GO


def test_inconclusive_when_lift_within_trial_spread() -> None:
    # B1 ~30% faster in the mean but with a huge per-arm spread ⇒ diff <= 2σ ⇒ INCONCLUSIVE.
    recs = _trials(False, [50.0, 100.0, 150.0]) + _trials(True, [70.0, 130.0, 190.0])
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_INCONCLUSIVE
    assert row.lift_pct is not None and row.lift_pct >= 10.0
    assert not row.significant


def test_inconclusive_when_single_trial_cannot_establish_spread() -> None:
    # One trial per arm ⇒ no spread to test the 2σ guard against ⇒ INCONCLUSIVE even at a big mean lift.
    recs = _trials(False, [100.0]) + _trials(True, [130.0])
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_INCONCLUSIVE


def test_no_go_when_b1_breaches_zero_loss() -> None:
    # B1 looks fast but dropped messages ⇒ hard NO-GO regardless of throughput; correctness fold fails.
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(
        True, [120.0, 121.0, 119.0], no_loss_ok=False, sink_received=900
    )
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_NO_GO
    assert row.candidate_lost
    assert not cmp.candidate_zero_loss_ok
    assert not cmp.ok  # a zero-loss breach fails the run's correctness fold


def test_no_go_when_in_pipeline_grows() -> None:
    # B1's intake is higher but its in_pipeline peak grew far past B0's ⇒ backlog mirage ⇒ NO-GO.
    recs = _trials(False, [100.0, 101.0, 99.0], in_pipeline=100) + _trials(
        True, [130.0, 131.0, 129.0], in_pipeline=500
    )
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_NO_GO
    assert not row.in_pipeline_ok


def test_no_go_when_delivered_offered_below_floor() -> None:
    # B1 posts a high intake but only delivers 95% of offered ⇒ not keeping up end-to-end ⇒ NO-GO.
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(
        True, [130.0, 131.0, 129.0], sink_received=950
    )
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_NO_GO
    assert not row.delivered_offered_ok


def test_missing_b1_arm_is_reported_loudly() -> None:
    # B0 ran; the B1 arm is absent (never ran) ⇒ MISSING row, never a silent compare-against-nothing.
    recs = _trials(False, [100.0, 101.0, 99.0])
    cmp = build_fuse_comparison(
        recs,
        (False, True),
        missing_detail={("pooled", "fixed_aggregate", 256): "whole pooled arm refused to start"},
    )
    assert cmp is not None
    assert cmp.missing_arms == 1
    assert not cmp.ok
    row = cmp.rows[0]
    assert row.verdict == FUSE_MISSING
    assert row.candidate_missing
    assert "refused to start" in row.reason
    assert cmp.overall_verdict == FUSE_NO_GO  # a missing arm cannot be a GO


def test_orphan_b1_without_baseline_fails_run() -> None:
    # A B1 (fusion-on) arm at a count whose B0 (fusion-off) BASELINE never produced a record must NOT be
    # silently dropped: the fusion-off baseline is itself a pooled arm, so a per-count baseline failure
    # (e.g. OOM only at N=512) would otherwise drop that count from BOTH the table and the ok-fold and
    # let a GO on the surviving counts mask it (ADR 0071 §6.4b). It fails the run.
    recs = (
        _trials(False, [100.0, 101.0, 99.0], count=256)  # a healthy GO cell at N=256
        + _trials(True, [120.0, 121.0, 119.0], count=256)
        + _trials(
            True, [200.0, 201.0, 199.0], count=512
        )  # B1 ran at N=512 but its B0 baseline did NOT
    )
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    assert ("pooled", "fixed_aggregate", 512) in cmp.baseline_missing
    assert cmp.rows[0].verdict == FUSE_GO  # the N=256 cell is still a legit GO...
    assert cmp.overall_verdict == FUSE_NO_GO  # ...but the swallowed N=512 baseline forces NO-GO
    assert not cmp.ok  # and fails the run's correctness fold
    assert any("BASELINE arm(s) MISSING" in n for n in cmp.notes)
    body = json.loads(json.dumps(cmp.to_json_dict()))
    assert body["summary"]["baseline_missing"] == 1
    assert ["pooled", "fixed_aggregate", 512] in body["baseline_missing"]
    assert "BASELINE MISSING" in cmp.render_table()


def test_json_and_table_render() -> None:
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [120.0, 121.0, 119.0])
    cmp = build_fuse_comparison(recs, (False, True))
    assert cmp is not None
    body = json.loads(json.dumps(cmp.to_json_dict()))  # must be JSON-serializable
    assert body["kind"] == "fuse_mode_ab"
    assert body["overall_verdict"] == FUSE_GO
    assert body["summary"]["go_cells"] == 1
    table = cmp.render_table()
    assert "Thread-hop-fusion A/B" in table
    assert "GO" in table


def test_default_single_arm_sweep_is_byte_identical() -> None:
    # The B5 default fuse_modes = (False,) tags every record fuse_thread_hops=False and produces NO
    # fusion comparison — i.e. a pre-B5 connscale/claim-mode run is unchanged.
    recs = _trials(False, [100.0, 101.0])
    assert all(r.fuse_thread_hops is False for r in recs)
    assert build_fuse_comparison(recs, (False,)) is None


# --------------------------------------------------------------------------- #
# B4 — the runner banks `trials` records per arm in ONE invocation (ADR 0071 B5 PR5)
# --------------------------------------------------------------------------- #


def _stub_run_one_step(
    monkeypatch: pytest.MonkeyPatch,
) -> list[dict[str, object]]:
    """Replace runner._run_one_step with a hermetic stub (no engine / SQL Server): it records every
    call's per-cell coordinates + the node tag / api_port the real step would use, and returns a fake
    ConnScaleRecord keyed to the call so build_fuse_comparison aggregates the trials. Returns the calls
    list the test asserts on."""
    from harness.load.connscale import runner as runner_mod

    calls: list[dict[str, object]] = []

    async def _stub(
        prof: object,
        *,
        claim_mode: str,
        fuse_mode: bool,
        mode: str,
        count: int,
        trial: int,
        aggregate_rate: float,
        api_port: int,
        **_kw: object,
    ) -> ConnScaleRecord:
        fuse_tag = "b1" if fuse_mode else "b0"
        calls.append(
            {
                "claim_mode": claim_mode,
                "fuse_mode": fuse_mode,
                "mode": mode,
                "count": count,
                "trial": trial,
                "api_port": api_port,
                "tag": f"cs-{claim_mode}-{fuse_tag}-{mode}-{count}-t{trial}",
            }
        )
        return _rec(fuse=fuse_mode, read=100.0, count=count, claim_mode=claim_mode, sweep_mode=mode)

    monkeypatch.setattr(runner_mod, "_run_one_step", _stub)
    return calls


async def test_runner_banks_trials_records_per_arm(monkeypatch: pytest.MonkeyPatch) -> None:
    # trials = 3 over a 2-count fusion A/B ⇒ claim(1) × fuse(2) × mode(1) × count(2) × trials(3) = 12
    # distinct steps, each with a unique api_port + node tag, and the fusion comparison sees 3 trials
    # per arm from a SINGLE invocation (the PR5 payoff — no concatenating multiple runs).
    calls = _stub_run_one_step(monkeypatch)
    profile = load_connscale_profile_text("""
[connscale]
name = "trials-ab"
counts = [256, 512]
aggregate_rate = 400.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
fuse_modes = [false, true]
trials = 3
""")
    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    assert len(calls) == 12
    assert len(report.records) == 12
    # Every step gets a distinct api_port (base + step) and a distinct node tag (…-t{trial}).
    assert len({c["api_port"] for c in calls}) == 12
    assert len({c["tag"] for c in calls}) == 12
    # Exactly `trials` records per arm, trial indices 0..2 for each (fuse, count) cell.
    per_arm: dict[tuple[bool, int], set[int]] = {}
    for c in calls:
        per_arm.setdefault((c["fuse_mode"], c["count"]), set()).add(c["trial"])  # type: ignore[index]
    assert len(per_arm) == 4  # (b0,256),(b1,256),(b0,512),(b1,512)
    assert all(indices == {0, 1, 2} for indices in per_arm.values())
    # The fusion comparison aggregates the 3 repeats per arm by key — the >=3 trials §6.4b needs.
    assert report.fuse_comparison is not None
    assert report.fuse_comparison.rows
    for row in report.fuse_comparison.rows:
        assert row.baseline.trials == 3
        assert row.candidate is not None and row.candidate.trials == 3


async def test_default_trials_one_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    # Absent trials ⇒ 1: the SAME step/record count as pre-PR5 (one per cell). The trial loop iterates
    # once, so the sweep is behaviorally identical — claim(1) × fuse(2) × mode(1) × count(2) = 4 steps.
    calls = _stub_run_one_step(monkeypatch)
    profile = load_connscale_profile_text("""
[connscale]
name = "no-trials"
counts = [256, 512]
aggregate_rate = 400.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
fuse_modes = [false, true]
""")
    assert profile.trials == 1
    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    assert len(calls) == 4  # one step per cell — no trial multiplier
    assert len(report.records) == 4
    assert all(c["trial"] == 0 for c in calls)  # the single trial is index 0 (-t0 tag)
    assert report.fuse_comparison is not None
    for row in report.fuse_comparison.rows:
        assert row.baseline.trials == 1
        assert row.candidate is not None and row.candidate.trials == 1
