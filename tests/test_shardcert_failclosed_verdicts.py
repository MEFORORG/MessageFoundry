# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shard-certification verdicts that read PASS on a run they exist to refuse (BACKLOG #5440).

Unit tests over synthetic counters: no load run, no database, no fleet.
"""

from __future__ import annotations

from harness.load.shardcert import ShardCertReport


def _report(**over: object) -> ShardCertReport:
    """A healthy co-located broadcast report: 1000 ACKed messages, D = 2, every copy arrived."""
    base: dict[str, object] = {
        "shards": ("s1", "s2"),
        "owned": {"s1": ["OB_1"], "s2": ["OB_2"]},
        "killed_shard": None,
        "sent": 1000,
        "acked": 1000,
        "delivered_distinct": 1000,
        "sink_received": 2000,
        "acked_not_delivered": 0,
        "lane_inversions": 0,
        "lanes_observed": 4,
        "lane_repeats": 0,
        "engine_done": 3000,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 2.0,
        "stranded_nonterminal": 0,
        "queue_breakdown": "",
        "offered": 1000,
        "achieved_intake": 1000,
        "dests": 2,
        "handlers": 3,
        "delivering": 2,
        "acked_copies_missing": 0,
        "dead_total": 0,
    }
    base.update(over)
    return ShardCertReport(**base)  # type: ignore[arg-type]


# --- BACKLOG #5440: the single-box report gates the all-stage dead total ---------------------------------


def test_healthy_report_passes() -> None:
    assert _report().ok is True


def test_routed_stage_dead_letters_fail_the_single_box_report() -> None:
    """H = 3, D = 2: the third handler delivers nothing, so its transform dead-lettering at the routed stage
    loses no sink copy and leaves the outbound-scoped ``engine_dead`` at 0. Only the store's all-stage dead
    total sees it, and the verdict must read it."""
    rep = _report(dead_total=1000)
    assert rep.engine_dead == 0
    assert rep.lossless is True
    assert rep.ok is False
    assert "verdict=FAIL" in rep.render()
    js = rep.to_json_dict()
    assert js["verdict"] == "FAIL"
    assert js["correctness"]["dead_total"] == 1000  # type: ignore[index]
    assert js["schema_version"] == 6


def test_unmeasured_dead_total_fails_closed() -> None:
    """A producer that never supplies the all-stage dead total gets a FAIL, never a silent PASS."""
    fields = {k: v for k, v in _report().__dict__.items() if k != "dead_total"}
    rep = ShardCertReport(**fields)
    assert rep.dead_total == -1
    assert rep.ok is False
