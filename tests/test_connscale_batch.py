# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Statement-batching A/B (ADR 0075 Bench B) — profile parsing of the ``batch_modes`` axis, per-arm env
injection of ``MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS`` (with fusion kept OFF in both arms), and the
GO/NO-GO verdict logic. The verdict path is the SAME §6.4(b) machinery the fusion A/B uses
(``build_fuse_comparison`` / the ``_in_pipeline_ok`` drain-signal path from #812) — ``build_batch_
comparison`` only swaps the arm discriminator (``batch_handoff_statements``) + the axis labels. Pure +
hermetic (no live engine / SQL Server)."""

from __future__ import annotations

import json

import pytest

from harness.load.connscale.compare import (
    BATCH_AXIS_KIND,
    FUSE_GO,
    FUSE_INCONCLUSIVE,
    FUSE_MISSING,
    FUSE_NO_GO,
    build_batch_comparison,
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
# B1 — profile parsing of the batch_modes A/B axis
# --------------------------------------------------------------------------- #

_OK = """
[connscale]
name = "t"
counts = [256]
aggregate_rate = 400.0
"""


def test_batch_modes_defaults_to_single_off() -> None:
    # Absent batch_modes ⇒ the single-arm (False,) default, so every pre-existing profile keeps its
    # byte-identical single-arm sweep (batching off is the engine default).
    p = load_connscale_profile_text(_OK)
    assert p.batch_modes == (False,)


def test_batch_modes_ab_axis_parses() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "ab"
counts = [256]
aggregate_rate = 400.0
claim_modes = ["pooled"]
batch_modes = [false, true]
""")
    assert p.batch_modes == (False, True)


def test_batch_modes_dedups_first_seen_order() -> None:
    p = load_connscale_profile_text("""
[connscale]
name = "ab"
counts = [256]
aggregate_rate = 400.0
batch_modes = [true, false, true]
""")
    assert p.batch_modes == (True, False)


@pytest.mark.parametrize(
    "body, needle",
    [
        # not a list
        ("[connscale]\nname='x'\ncounts=[10]\nbatch_modes=true\n", "batch_modes"),
        # empty list
        ("[connscale]\nname='x'\ncounts=[10]\nbatch_modes=[]\n", "batch_modes"),
        # non-boolean entry (ints are a common mistake — must be rejected, not read as on/off)
        ("[connscale]\nname='x'\ncounts=[10]\nbatch_modes=[1]\n", "boolean"),
        ("[connscale]\nname='x'\ncounts=[10]\nbatch_modes=['true']\n", "boolean"),
    ],
)
def test_batch_modes_fail_loud(body: str, needle: str) -> None:
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text(body)
    assert needle in str(exc.value)


def test_batch_and_fuse_both_multi_arm_is_rejected() -> None:
    # The two boolean levers don't COMPOSE (ADR 0075) and each comparison pairs one axis at a time; a
    # profile making BOTH multi-arm would produce 4 arms per cell and silently collapse each keying —
    # fail loud.
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text("""
[connscale]
name = "both"
counts = [256]
aggregate_rate = 400.0
claim_modes = ["pooled"]
fuse_modes = [false, true]
batch_modes = [false, true]
""")
    msg = str(exc.value)
    assert "BOTH" in msg
    assert "fuse_modes" in msg and "batch_modes" in msg


def test_batch_and_claim_both_multi_arm_is_rejected() -> None:
    with pytest.raises(ConnScaleProfileError) as exc:
        load_connscale_profile_text("""
[connscale]
name = "both"
counts = [256]
aggregate_rate = 400.0
claim_modes = ["per_lane", "pooled"]
batch_modes = [false, true]
""")
    msg = str(exc.value)
    assert "BOTH" in msg
    assert "claim_modes" in msg and "batch_modes" in msg


def test_batch_ab_builtin_resolves() -> None:
    p = get_connscale_profile("batch_ab")
    assert p.batch_modes == (False, True)
    assert p.claim_modes == ("pooled",)
    # Fusion is a single OFF arm in BOTH batching arms — the two levers don't compose (ADR 0075).
    assert p.fuse_modes == (False,)
    assert p.counts == (256, 512, 1024)
    assert p.store_backend == "sqlserver"
    # >= 3 trials/arm so the ">2σ" spread guard is reachable directly from one invocation.
    assert p.trials == 3
    assert "batch_ab" in list_connscale_profiles()


# --------------------------------------------------------------------------- #
# B2 — the runner injects MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS per arm
#      (keeping MEFOR_PIPELINE_FUSE_THREAD_HOPS OFF in BOTH arms)
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


def test_node_env_injects_batch_flag_on() -> None:
    env = _env(claim_mode="pooled", batch_mode=True)
    assert env["MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS"] == "true"
    assert env["MEFOR_PIPELINE_CLAIM_MODE"] == "pooled"
    # The two levers don't compose: the batch A/B keeps fusion OFF even on the batching-ON arm.
    assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "false"


def test_node_env_injects_batch_flag_off() -> None:
    env = _env(claim_mode="pooled", batch_mode=False)
    assert env["MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS"] == "false"
    assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "false"


def test_node_env_batch_defaults_off_for_prebump_callers() -> None:
    # A pre-ADR-0075 caller (e.g. the fuse A/B, or multishard) omits batch_mode ⇒ "false" (the engine
    # default) ⇒ byte-identical.
    env = _env()
    assert env["MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS"] == "false"


def test_node_env_batch_and_fuse_are_independent() -> None:
    # The two flags are set from independent kwargs: a fuse-only sweep never trips batching and vice
    # versa. (batch_ab pins fuse=[false], so this is the "batching on, fusion off" cell.)
    env = _env(claim_mode="pooled", fuse_mode=False, batch_mode=True)
    assert env["MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS"] == "true"
    assert env["MEFOR_PIPELINE_FUSE_THREAD_HOPS"] == "false"


# --------------------------------------------------------------------------- #
# B3 — build_batch_comparison GO / NO-GO / INCONCLUSIVE / MISSING verdicts
#      (the SAME comparator machinery as fuse, keyed on batch_handoff_statements)
# --------------------------------------------------------------------------- #


def _rec(
    *,
    batch: bool,
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
    drain_seconds: float | None = 1.0,
    backlog: int = 0,
    ack_p50: float = 1.0,
    ack_p99: float = 3.0,
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
        no_loss=NoLoss(no_loss_ok, sent, sent, sink_received, sink_received, backlog, detail),
        in_pipeline_peak=in_pipeline,
        drain_seconds=drain_seconds,
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
        ack_p50_ms=ack_p50,
        ack_p95_ms=(ack_p50 + ack_p99) / 2.0,
        ack_p99_ms=ack_p99,
        claim_mode=claim_mode,
        achieved_read_per_s=read,
        achieved_written_per_s=written,
        cpu_seconds_total=5.0,
        cpu_util_cores_mean=0.5,
        # Fusion is OFF in BOTH batching arms (the two levers don't compose, ADR 0075); the batch A/B
        # discriminator is the batch tag below, not fuse_thread_hops.
        fuse_thread_hops=False,
        batch_handoff_statements=batch,
    )


def _trials(batch: bool, reads: list[float], **kw: object) -> list[ConnScaleRecord]:
    return [_rec(batch=batch, read=r, **kw) for r in reads]  # type: ignore[arg-type]


def test_single_batch_mode_has_no_comparison() -> None:
    # batch_modes = (False,) — the pre-ADR-0075 single-arm shape — yields NO batch comparison.
    recs = _trials(False, [100.0])
    assert build_batch_comparison(recs, (False,)) is None
    # A degenerate multi that isn't a real B0/B1 pair also yields None.
    assert build_batch_comparison(_trials(True, [120.0]), (True,)) is None


def test_batch_comparison_keys_on_batch_tag_not_fuse() -> None:
    # THE non-vacuous guard: every record has fusion OFF (batch_ab keeps fuse off in both arms), so the
    # arms differ ONLY by the batch tag. Run through the FUSION comparator and it sees a single fuse arm
    # ⇒ the fusion-on candidate is MISSING (there is no fuse=on record). Run through the BATCH comparator
    # and it correctly pairs B0 vs B1 by batch_handoff_statements ⇒ a real GO. If the batch axis weren't
    # actually toggled / keyed on the right flag, this pairing would collapse and there'd be nothing to
    # compare.
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [120.0, 121.0, 119.0])
    assert all(r.fuse_thread_hops is False for r in recs)

    fuse_cmp = build_fuse_comparison(recs, (False, True))
    assert fuse_cmp is not None
    assert fuse_cmp.missing_arms == 1  # the fusion comparator finds NO fuse-on arm here
    assert fuse_cmp.rows[0].candidate_missing

    batch_cmp = build_batch_comparison(recs, (False, True))
    assert batch_cmp is not None
    row = batch_cmp.rows[0]
    assert row.candidate is not None and not row.candidate_missing
    assert row.verdict == FUSE_GO
    # B1 (candidate) records carry batching ON; B0 (baseline) OFF — proven from the tagged inputs.
    b1_recs = [r for r in recs if r.batch_handoff_statements]
    b0_recs = [r for r in recs if not r.batch_handoff_statements]
    assert b1_recs and all(r.batch_handoff_statements for r in b1_recs)
    assert b0_recs and all(not r.batch_handoff_statements for r in b0_recs)


def test_go_when_b1_lift_ge_10pct_and_gt_2sigma() -> None:
    # B1 ~20% faster with tight per-arm spread ⇒ diff (20/s) >> 2σ (~2.8/s) ⇒ significant ⇒ GO.
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [120.0, 121.0, 119.0])
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_GO
    assert row.significant and row.lift_pct is not None and row.lift_pct >= 10.0
    assert row.in_pipeline_ok and row.delivered_offered_ok
    assert cmp.overall_verdict == FUSE_GO
    assert cmp.ok  # correctness gate (zero-loss held, present)


def test_no_go_when_lift_below_threshold() -> None:
    # B1 only ~2% faster ⇒ below the 10% bar ⇒ NO-GO (batching banked no worthwhile margin).
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [102.0, 103.0, 101.0])
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    assert cmp.rows[0].verdict == FUSE_NO_GO
    assert cmp.overall_verdict == FUSE_NO_GO


def test_inconclusive_when_lift_within_trial_spread() -> None:
    # B1 ~30% faster in the mean but with a huge per-arm spread ⇒ diff <= 2σ ⇒ INCONCLUSIVE.
    recs = _trials(False, [50.0, 100.0, 150.0]) + _trials(True, [70.0, 130.0, 190.0])
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_INCONCLUSIVE
    assert row.lift_pct is not None and row.lift_pct >= 10.0
    assert not row.significant


def test_no_go_when_b1_breaches_zero_loss() -> None:
    # B1 looks fast but dropped messages ⇒ hard NO-GO regardless of throughput; correctness fold fails.
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(
        True, [120.0, 121.0, 119.0], no_loss_ok=False, sink_received=900
    )
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_NO_GO
    assert row.candidate_lost
    assert not cmp.candidate_zero_loss_ok
    assert not cmp.ok  # a zero-loss breach fails the run's correctness fold


def test_no_go_when_drain_time_grows_reads_drain_not_poller_peak() -> None:
    # B1's intake is higher but its post-load DRAIN TIME grew far past B0's ⇒ the higher intake rode a
    # larger backlog ⇒ NO-GO. Read from the AUTHORITATIVE drain signal (#812), NOT the /stats-poller
    # in_pipeline peak: here both arms poll to the SAME peak, so the old peak clause could not see it —
    # the drain time can. Both arms fully drained (finite drain time), so this is a slower flush, not a
    # zero-loss breach.
    recs = _trials(False, [100.0, 101.0, 99.0], drain_seconds=1.0) + _trials(
        True, [130.0, 131.0, 129.0], drain_seconds=10.0
    )
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_NO_GO
    assert not row.in_pipeline_ok
    assert "drain time grew" in row.reason


def test_in_pipeline_ok_ignores_poller_peak_spike() -> None:
    # The #812 fix, on the batch axis: B1's /stats-poller in_pipeline peak reads far HIGHER than B0's
    # (poller under-sampling), yet B1 fully drained and drained FASTER. The OLD peak clause would have
    # mis-fired NO-GO; the authoritative drain guard passes it. Guards that build_batch_comparison reuses
    # the FIXED verdict path, not a reintroduced poller-peak fork.
    recs = _trials(False, [100.0, 101.0, 99.0], in_pipeline=1369, drain_seconds=158.0) + _trials(
        True, [130.0, 131.0, 129.0], in_pipeline=21969, drain_seconds=143.0
    )
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.candidate is not None
    old_clause = row.candidate.in_pipeline_peak <= (row.baseline.in_pipeline_peak * 1.05 + 1.0)
    assert not old_clause  # the OLD poller-peak clause would MIS-FIRE here
    assert row.in_pipeline_ok  # the NEW drain-signal guard passes it


def test_no_go_when_candidate_drain_times_out_despite_empty_outbound() -> None:
    # A candidate that STRANDS rows in ingress/routed drains its OUTBOUND queue (backlog 0) and passes
    # the outbound-only zero-loss reconcile, but await_drain TIMED OUT (drain_seconds=None → the whole-
    # pipeline in_pipeline gauge never reached 0). That backlog mirage must be NO-GO, never a FALSE GO.
    recs = _trials(False, [100.0, 101.0, 99.0], drain_seconds=1.0) + _trials(
        True, [130.0, 131.0, 129.0], drain_seconds=None, backlog=0
    )
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.candidate is not None
    assert row.candidate.drain_seconds_worst is None and not row.candidate.drain_completed
    assert row.delivered_offered_ok  # delivered/offered == 1.0 — would NOT have caught the strand
    assert not row.in_pipeline_ok
    assert row.verdict == FUSE_NO_GO
    assert "did not fully drain" in row.reason and "await_drain timed out" in row.reason


def test_no_go_when_delivered_offered_below_floor() -> None:
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(
        True, [130.0, 131.0, 129.0], sink_received=950
    )
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.verdict == FUSE_NO_GO
    assert not row.delivered_offered_ok


def test_missing_b1_arm_is_reported_loudly() -> None:
    # B0 ran; the B1 (batching-on) arm is absent ⇒ MISSING row, never a silent compare-against-nothing.
    recs = _trials(False, [100.0, 101.0, 99.0])
    cmp = build_batch_comparison(
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
    assert cmp.overall_verdict == FUSE_NO_GO


def test_batch_labels_and_kind_are_the_batch_axis() -> None:
    # The reused comparator is RELABELLED for the batching axis — the report must not read "fusion".
    recs = _trials(False, [100.0, 101.0, 99.0]) + _trials(True, [120.0, 121.0, 119.0])
    cmp = build_batch_comparison(recs, (False, True))
    assert cmp is not None
    body = json.loads(json.dumps(cmp.to_json_dict()))  # must be JSON-serializable
    assert body["kind"] == BATCH_AXIS_KIND == "batch_mode_ab"
    assert body["baseline"] == "batch=off (B0)" and body["candidate"] == "batch=on (B1)"
    assert body["overall_verdict"] == FUSE_GO
    assert body["summary"]["go_cells"] == 1
    table = cmp.render_table()
    assert "Statement-batching A/B" in table and "ADR 0075" in table
    assert "Thread-hop-fusion" not in table  # not mislabelled as the fusion axis


def test_batch_comparison_surfaces_ack_latency_signal() -> None:
    # ADR 0075's benefit is a LATENCY / distance-insurance signal, not throughput: on a real bench at an
    # injected +20 ms engine→store RTT, batch-ON showed a LOWER ACK p99 (391 vs 475 ms), both arms
    # zero-loss. Surface ACK p50/p99 as first-class B0-vs-B1 columns (console table + the batch_comparison
    # JSON block) so operators no longer hand-diff them out of the raw records. "ON (B1) lower than OFF
    # (B0)" — a NEGATIVE delta — is the good sign. (A companion mean-drain column was dropped: bench
    # validation showed it was warm-up-dominated — one cold OFF trial spiked in-pipeline and skewed the
    # trial mean — so it was not a reliable batch signal; the ACK percentiles are.)
    b0 = _trials(False, [100.0, 101.0, 99.0], ack_p50=10.0, ack_p99=475.0)
    b1 = _trials(True, [100.0, 101.0, 99.0], ack_p50=8.0, ack_p99=391.0)
    cmp = build_batch_comparison(b0 + b1, (False, True))
    assert cmp is not None
    row = cmp.rows[0]
    assert row.candidate is not None

    # Per-arm aggregates (trial means) land on the shared arm dataclass — for BOTH arms.
    assert row.baseline.mean_ack_p50_ms == pytest.approx(10.0)
    assert row.candidate.mean_ack_p50_ms == pytest.approx(8.0)
    assert row.baseline.mean_ack_p99_ms == pytest.approx(475.0)
    assert row.candidate.mean_ack_p99_ms == pytest.approx(391.0)

    body = json.loads(json.dumps(cmp.to_json_dict()))  # JSON-serializable
    lat = body["rows"][0]["latency"]
    assert lat["b0_ack_p50_ms"] == 10.0 and lat["b1_ack_p50_ms"] == 8.0
    assert lat["b0_ack_p99_ms"] == 475.0 and lat["b1_ack_p99_ms"] == 391.0
    # ON lower than OFF ⇒ NEGATIVE delta (the good, distance-insurance direction).
    assert lat["ack_p50_delta_pct"] is not None and lat["ack_p50_delta_pct"] < 0.0
    assert lat["ack_p99_delta_pct"] is not None and lat["ack_p99_delta_pct"] < 0.0
    # The dropped (warm-up-dominated) mean-drain column must NOT reappear in the JSON latency block.
    assert "b0_drain_s" not in lat and "b1_drain_s" not in lat and "drain_delta_pct" not in lat

    # It is a REPORTED signal, not a gate: with a flat 0% throughput lift the verdict stays NO-GO even
    # though every latency column improved — the latency columns never move the GO/NO-GO decision.
    assert row.verdict == FUSE_NO_GO

    # And it reads in the console table too (B0, B1, and the delta columns); the dropped mean-drain
    # column is gone from the table.
    table = cmp.render_table()
    assert "ack_p50_ms (mean)" in table
    assert "ack_p99_ms (mean)" in table
    assert "drain_seconds (mean)" not in table


# --------------------------------------------------------------------------- #
# B4 — the runner banks `trials` records per batching arm in ONE invocation
# --------------------------------------------------------------------------- #


def _stub_run_one_step(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Replace runner._run_one_step with a hermetic stub (no engine / SQL Server): it records every
    call's per-cell coordinates (incl. the fuse + batch arm) and returns a fake ConnScaleRecord keyed to
    the call so build_batch_comparison aggregates the trials. Returns the calls list the test asserts
    on."""
    from harness.load.connscale import runner as runner_mod

    calls: list[dict[str, object]] = []

    async def _stub(
        prof: object,
        *,
        claim_mode: str,
        fuse_mode: bool,
        batch_mode: bool,
        mode: str,
        count: int,
        trial: int,
        aggregate_rate: float,
        api_port: int,
        **_kw: object,
    ) -> ConnScaleRecord:
        batch_tag = "bt1" if batch_mode else "bt0"
        fuse_tag = "b1" if fuse_mode else "b0"
        calls.append(
            {
                "claim_mode": claim_mode,
                "fuse_mode": fuse_mode,
                "batch_mode": batch_mode,
                "mode": mode,
                "count": count,
                "trial": trial,
                "api_port": api_port,
                "tag": f"cs-{claim_mode}-{fuse_tag}-{batch_tag}-{mode}-{count}-t{trial}",
            }
        )
        return _rec(
            batch=batch_mode, read=100.0, count=count, claim_mode=claim_mode, sweep_mode=mode
        )

    monkeypatch.setattr(runner_mod, "_run_one_step", _stub)
    return calls


async def test_runner_banks_trials_records_per_batch_arm(monkeypatch: pytest.MonkeyPatch) -> None:
    # trials = 3 over a 2-count batching A/B ⇒ claim(1) × fuse(1) × batch(2) × mode(1) × count(2) ×
    # trials(3) = 12 distinct steps, each with a unique api_port + node tag, and the batch comparison
    # sees 3 trials per arm from a SINGLE invocation.
    calls = _stub_run_one_step(monkeypatch)
    profile = load_connscale_profile_text("""
[connscale]
name = "batch-trials-ab"
counts = [256, 512]
aggregate_rate = 400.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
fuse_modes = [false]
batch_modes = [false, true]
trials = 3
""")
    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    assert len(calls) == 12
    assert len(report.records) == 12
    # Every step gets a distinct api_port (base + step) and a distinct node tag (…-bt{n}-…-t{trial}).
    assert len({c["api_port"] for c in calls}) == 12
    assert len({c["tag"] for c in calls}) == 12
    # Fusion stays OFF on EVERY step (the two levers don't compose); only the batch flag toggles.
    assert all(c["fuse_mode"] is False for c in calls)
    # Exactly `trials` records per batching arm, trial indices 0..2 for each (batch, count) cell. The
    # call dicts are typed dict[str, object], so key/value are `object` — annotate the tally to match.
    per_arm: dict[tuple[object, object], set[object]] = {}
    for c in calls:
        per_arm.setdefault((c["batch_mode"], c["count"]), set()).add(c["trial"])
    assert len(per_arm) == 4  # (b0,256),(b1,256),(b0,512),(b1,512)
    assert all(indices == {0, 1, 2} for indices in per_arm.values())
    # The batch comparison aggregates the 3 repeats per arm; the fuse comparison is absent (single arm).
    assert report.fuse_comparison is None
    assert report.batch_comparison is not None
    assert report.batch_comparison.rows
    for row in report.batch_comparison.rows:
        assert row.baseline.trials == 3
        assert row.candidate is not None and row.candidate.trials == 3
    # The batch comparison is embedded in the JSON report under 'batch_comparison'.
    body = json.loads(report.to_json())
    assert body["batch_comparison"]["kind"] == "batch_mode_ab"
    assert "fuse_comparison" not in body


async def test_default_batch_modes_one_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    # Absent batch_modes ⇒ (False,): the sweep runs one batching arm (off), no batch comparison — a
    # pre-ADR-0075 (e.g. fuse-only) run is behaviorally unchanged.
    calls = _stub_run_one_step(monkeypatch)
    profile = load_connscale_profile_text("""
[connscale]
name = "no-batch"
counts = [256, 512]
aggregate_rate = 400.0
sweep_mode = "fixed_aggregate"
claim_modes = ["pooled"]
fuse_modes = [false, true]
""")
    assert profile.batch_modes == (False,)
    report = await run_connscale(profile, engine_api_port_base=9000, sink_port=8000)

    # claim(1) × fuse(2) × batch(1) × mode(1) × count(2) = 4 steps; batching off on every one.
    assert len(calls) == 4
    assert all(c["batch_mode"] is False for c in calls)
    # The fuse A/B is present (its axis is multi-arm here); the batch A/B is absent (single arm).
    assert report.fuse_comparison is not None
    assert report.batch_comparison is None
