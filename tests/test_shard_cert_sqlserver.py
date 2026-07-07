# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""N-active engine-shard CERTIFICATION under load against a REAL SQL Server (ADR 0073) — the live
proof that N ``serve --shard`` processes on ONE unified server store are SAFE.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
:mod:`tests.test_load_failover_sqlserver`. Runs 4 real ``serve --shard`` subprocesses against one
shared SQL Server store with the ``harness/config/shardcert`` graph (shards deliver to OVERLAPPING
outbound destinations), drives MLLP load, and certifies the ADR 0073 invariants from the sink/drain
signal:

* **baseline** — no kill: zero acknowledged loss, per-lane FIFO (non-vacuous), no duplicate delivery,
  no stranded INFLIGHT, clean drain. Proves the single-delivery-consumer-per-outbound-lane assignment
  drains every shared destination exactly once across the fleet.
* **kill leg** — SIGKILL the shard owning the most lanes mid-load, restart it (supervisor-style); its
  startup ownership-scoped ``reset_stale_inflight(owned=...)`` recovers ONLY its lanes while siblings
  are untouched, and the whole fleet drains with the same invariants (bounded at-least-once dups
  allowed across the crash).

This is the LOCAL CORRECTNESS half of the throughput plan's clean-4-engine-no-loss bench — it proves
safety at a modest rate on one box. The throughput/sizing number needs the isolated AWS two-box rig
(per-process CPU, client isolation); see ``harness/load/shardcert.py`` + the AWS bench handoff.
"""

from __future__ import annotations

import os

import pytest

from harness.load.shardcert import ShardCertReport, run_shardcert

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run the SQL Server "
    "N-active shard-certification test",
)


def _store_env() -> dict[str, str]:
    """The ambient ``MEFOR_STORE_*`` connection env the gated CI/dev shell provides. ``run_shardcert``
    adds the graph shape + the auth/insecure-TLS escapes itself."""
    return {k: v for k, v in os.environ.items() if k.startswith("MEFOR_STORE_")}


def _assert_certified(report: ShardCertReport) -> None:
    detail = "\n\n" + report.render()
    assert report.acked > 0, "no load was accepted" + detail
    assert report.acked_not_delivered == 0, "acknowledged-message loss" + detail
    assert report.drained, "fleet pipeline did not drain" + detail
    assert report.in_pipeline_final == 0, "pipeline not empty at drain" + detail
    assert report.engine_dead == 0, "messages were dead-lettered" + detail
    assert report.lane_inversions == 0, "per-lane FIFO violation" + detail
    # Non-vacuous ordering: 4 shards x N shared destinations => many (source-shard, dest) lanes. A
    # collapse to < 2 lanes would certify nothing (the MSH-6 stamp went missing).
    assert report.lanes_observed >= 2, "per-lane ordering measurement is vacuous" + detail
    assert report.stranded_nonterminal == 0, "stranded non-terminal rows after drain" + detail
    # Every shared destination must be owned (single delivery consumer) by exactly one shard, and the
    # owned sets must be disjoint and cover the whole outbound map.
    all_owned = [d for lanes in report.owned.values() for d in lanes]
    assert len(all_owned) == len(set(all_owned)), "a destination is owned by >1 shard" + detail


@pytest.mark.timeout(300)
@pytest.mark.flaky(reruns=1)
def test_shardcert_baseline_no_loss() -> None:
    """4 shards on one SS store, overlapping destinations, no kill: zero loss / zero dup / per-lane
    FIFO / no stranded — the single-consumer assignment drains every shared lane exactly once."""
    import asyncio

    report = asyncio.run(
        run_shardcert(
            dests=6,
            aggregate_rate=30.0,
            hold_seconds=10.0,
            kill=False,
            drain_timeout=120.0,
            store_env=_store_env(),
        )
    )
    _assert_certified(report)
    assert report.lane_repeats == 0, "duplicate delivery on a clean run\n\n" + report.render()
    assert report.ok, "baseline certification failed\n\n" + report.render()


@pytest.mark.timeout(360)
@pytest.mark.flaky(reruns=1)
def test_shardcert_kill_leg_scoped_recovery() -> None:
    """SIGKILL the shard owning the most lanes mid-load, restart it: ownership-scoped recovery re-pends
    only its lanes, siblings untouched, fleet drains with zero acknowledged loss + per-lane FIFO."""
    import asyncio

    report = asyncio.run(
        run_shardcert(
            dests=6,
            aggregate_rate=30.0,
            hold_seconds=18.0,
            kill=True,
            kill_at_fraction=0.4,
            drain_timeout=150.0,
            store_env=_store_env(),
        )
    )
    assert report.killed_shard is not None, "kill leg did not kill a shard\n\n" + report.render()
    _assert_certified(report)
    assert report.ok, "kill-leg certification failed\n\n" + report.render()
