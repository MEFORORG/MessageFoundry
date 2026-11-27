# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The failover report's per-copy dead-row check (BACKLOG #5572) and its S26-62 item.

A reused store's carried-over dead rows no longer fail a clean run: the rig reads each dead copy's
identity before load and after the drain, and excuses only the copies already dead, unchanged, at the
opening read. Where that reading is not conclusive the check stays absolute, as on ``main``. The
negative controls hold the cases the earlier run delta passed and must not: three rows leaving and
three new ones, and a carried-over copy that is replayed and dies again.
"""

from __future__ import annotations

import asyncio
import math
from types import SimpleNamespace
from typing import Any

import pytest

import harness.load.failover as failover
from harness.load.failover import (
    FailoverError,
    FailoverPorts,
    NodeStats,
    _build_report,
    _judge_new_dead,
    _KillOutcome,
)
from harness.load.failover_track import FailoverTracker
from harness.load.metrics import Counters
from harness.load.profile import load_profile_text

_PROFILE = """
[load]
name = "fo-b20006"
pool_size = 1
[[load.target]]
name = "adt"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[load.failover]
{failover}
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 20.0
duration_s = 2.0
"""

_FAILOVER = {
    "kill_at_fraction": "0.5",
    "heartbeat_seconds": "2.0",
    "leader_fence_timeout_seconds": "4.0",
    "leader_lease_ttl_seconds": "6.0",
    "recovery_ttl_multiple": "2.0",
    "max_dup_rate": "0.1",
}


def _profile(**knobs: str) -> Any:
    """The profile, with ``knobs`` written into its ``[load.failover]`` table as TOML values."""
    table = "\n".join(f"{k} = {v}" for k, v in {**_FAILOVER, **knobs}.items())
    return load_profile_text(_PROFILE.format(failover=table), where="<test>")


def _outcome() -> _KillOutcome:
    return _KillOutcome(
        killed=SimpleNamespace(node_id="fo-a"),  # type: ignore[arg-type]
        survivor=SimpleNamespace(node_id="fo-b"),  # type: ignore[arg-type]
        promotion_seconds=2.0,
        recovery_seconds=7.0,
        max_concurrent_leaders=1,
        leader_samples=10,
    )


def _tracker(lanes: tuple[str, ...] = ("d0", "d1"), n: int = 98) -> FailoverTracker:
    t = FailoverTracker()
    for seq in range(n):
        t.on_ack(seq)
        for lane in lanes:
            t.on_delivery(lane, seq)
    return t


def _report(
    *,
    tracker: FailoverTracker | None = None,
    dead: int = 0,
    dead_opening: int = 0,
    dead_new: int | None = None,
    acked: int = 98,
    db_backend: str | None = "postgres",
    fo: Any = None,
) -> failover.FailoverReport:
    profile = _profile()
    return _build_report(
        profile,
        db_backend,
        Counters(sent=100, acked=acked, sink_received=196, timeouts=100 - acked),
        tracker or _tracker(),
        _outcome(),
        NodeStats(done=5196, dead=dead, pending=0, inflight=0, in_pipeline=0),
        done_at_start=5000,
        fo=fo or profile.failover,
        notes=[],
        dead_opening=dead_opening,
        dead_new=dead_new,
    )


# --- the per-copy judgment ------------------------------------------------------

_A, _B, _C = ("oa", 1.0), ("ob", 2.0), ("oc", 3.0)


def test_only_carried_over_copies_are_no_new_dead() -> None:
    carried = frozenset({_A, _B, _C})
    assert _judge_new_dead(carried, carried, carried, 3) == 0


def test_three_leaving_and_three_new_count_three_new() -> None:
    # The case the withdrawn run delta passed: the dead count is unchanged and every row is new.
    new = frozenset({("od", 9.0), ("oe", 9.1), ("of", 9.2)})
    assert _judge_new_dead(frozenset({_A, _B, _C}), new, new, 3) == 3


def test_a_carried_copy_that_died_again_is_new() -> None:
    # Same outbox row, replayed and dead-lettered again: a later failed_at makes it a new copy.
    after = frozenset({_A, _B, ("oc", 7.5)})
    assert _judge_new_dead(frozenset({_A, _B, _C}), after, after, 3) == 1


@pytest.mark.parametrize(
    ("opening", "before", "after", "final_dead"),
    [
        (None, frozenset({_A}), frozenset({_A}), 1),  # no opening reading
        (frozenset({_A}), None, frozenset({_A}), 1),  # no reading before the final stats
        (frozenset({_A}), frozenset({_A}), None, 1),  # no reading after it
        (frozenset({_A}), frozenset({_A}), frozenset({_A, _B}), 2),  # the set moved across them
        (frozenset({_A, _B}), frozenset({_A}), frozenset({_A}), 2),  # stats sees a copy they miss
    ],
)
def test_an_inconclusive_reading_judges_nothing(
    opening: frozenset[tuple[str, float]] | None,
    before: frozenset[tuple[str, float]] | None,
    after: frozenset[tuple[str, float]] | None,
    final_dead: int,
) -> None:
    assert _judge_new_dead(opening, before, after, final_dead) is None


def test_carried_over_dead_rows_do_not_fail_a_clean_run() -> None:
    rep = _report(dead=3, dead_opening=3, dead_new=0)
    assert rep.dead_final == 3
    assert rep.dead_new == 0
    assert rep.result_ok is True, rep.render_console()


def test_a_new_dead_row_still_fails_beside_carried_ones() -> None:
    rep = _report(dead=6, dead_opening=3, dead_new=3)
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)
    assert any("3 of them new" in n for n in rep.notes)


def test_dead_rows_not_judged_per_copy_still_fail() -> None:
    # The absolute check of main stands wherever the per-copy reading was not conclusive.
    rep = _report(dead=3, dead_opening=3, dead_new=None)
    assert rep.result_ok is False
    assert any("could not tell" in n for n in rep.notes)
    js = rep.to_json_dict()
    assert js["no_loss"]["dead_new"] is None  # type: ignore[index]
    assert js["no_loss"]["dead_opening"] == 3  # type: ignore[index]


# --- the dead-copy read of /dead-letters ---------------------------------------


def _row(oid: str, at: float) -> dict[str, object]:
    return {"outbox_id": oid, "failed_at": at, "summary": "SYNTHETIC"}


def _node_answering(
    monkeypatch: pytest.MonkeyPatch, pages: list[dict[str, Any] | None]
) -> tuple[failover.EngineNode, list[str]]:
    node = failover.EngineNode.__new__(failover.EngineNode)
    node.node_id = "fo-x"
    paths: list[str] = []

    async def answer(_client: object, path: str) -> dict[str, Any] | None:
        paths.append(path)
        return pages[min(len(paths) - 1, len(pages) - 1)]

    monkeypatch.setattr(node, "_signed_in_json", answer)
    return node, paths


def test_dead_copies_reads_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(failover, "_DEAD_PAGE", 2)
    node, paths = _node_answering(
        monkeypatch,
        [
            {"total": 3, "dead_letters": [_row("a", 1.0), _row("b", 2.0)]},
            {"total": 3, "dead_letters": [_row("c", 3.0)]},
        ],
    )
    got = asyncio.run(node.dead_copies(object()))  # type: ignore[arg-type]
    assert got == frozenset({("a", 1.0), ("b", 2.0), ("c", 3.0)})
    assert paths == ["/dead-letters?limit=2&offset=0", "/dead-letters?limit=2&offset=2"]


@pytest.mark.parametrize(
    "pages",
    [
        [None],  # no answer
        [{"total": 2, "dead_letters": [_row("a", 1.0)]}, {"total": 2, "dead_letters": []}],  # short
        [
            {"total": 3, "dead_letters": [_row("a", 1.0), _row("b", 2.0)]},
            {"total": 4, "dead_letters": [_row("c", 3.0)]},
        ],  # the total moved between pages
        [
            {"total": 3, "dead_letters": [_row("a", 1.0), _row("b", 2.0)]},
            {"total": 3, "dead_letters": [_row("b", 2.0)]},
        ],  # a copy seen twice: the set shifted under the paging
        [{"total": 1, "dead_letters": [{"outbox_id": "a"}]}],  # no failed_at
        [{"total": 1, "dead_letters": [_row("a", math.nan)]}],  # a failed_at that never compares
        [{"total": True, "dead_letters": []}],  # not a count
        [{"total": 1}],  # no rows list
    ],
)
def test_dead_copies_is_none_unless_whole(
    pages: list[dict[str, Any] | None], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(failover, "_DEAD_PAGE", 2)
    node, _ = _node_answering(monkeypatch, pages)
    assert asyncio.run(node.dead_copies(object())) is None  # type: ignore[arg-type]


def test_dead_copies_past_its_cap_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(failover, "_DEAD_COPIES_MAX", 2)
    node, paths = _node_answering(monkeypatch, [{"total": 3, "dead_letters": []}])
    assert asyncio.run(node.dead_copies(object())) is None  # type: ignore[arg-type]
    assert len(paths) == 1


class _CopyNode:
    def __init__(self, copies: frozenset[tuple[str, float]] | None) -> None:
        self.copies = copies
        self.reads = 0

    async def dead_copies(self, client: object) -> frozenset[tuple[str, float]] | None:
        self.reads += 1
        return self.copies


def test_a_store_with_no_dead_rows_is_never_listed() -> None:
    node = _CopyNode(frozenset({_A}))
    opening = NodeStats(done=0, dead=0, pending=0, inflight=0, in_pipeline=0)
    got = asyncio.run(failover._opening_dead_copies([node], object(), opening))  # type: ignore[list-item,arg-type]
    assert got is None
    assert node.reads == 0


def test_the_opening_copies_come_from_the_first_node_that_reads() -> None:
    down, up = _CopyNode(None), _CopyNode(frozenset({_A}))
    opening = NodeStats(done=0, dead=1, pending=0, inflight=0, in_pipeline=0)
    got = asyncio.run(failover._opening_dead_copies([down, up], object(), opening))  # type: ignore[list-item,arg-type]
    assert got == frozenset({_A})


# --- S26-62 -----------------------------------------------------------------------


def test_per_lane_ordering_fails_on_one_lane() -> None:
    rep = _report(tracker=_tracker(lanes=("d0",)))
    assert rep.lanes_observed == 1
    assert rep.result_ok is False
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)


def test_per_lane_ordering_passes_on_two_lanes() -> None:
    rep = _report()
    assert any(s.name == "per_lane_ordering" and s.ok for s in rep.slos)
    assert not any("lane(s)" in n for n in rep.notes)


def test_per_lane_ordering_names_why_one_lane_fails() -> None:
    rep = _report(tracker=_tracker(lanes=("d0",)))
    assert any("observed 1 lane(s)" in n for n in rep.notes)


def test_per_lane_ordering_fails_on_an_inversion_over_two_lanes() -> None:
    # With two lanes the lane count passes, so only the inversion can fail the check.
    t = _tracker(lanes=("d1",))
    for seq in (*range(96), 97, 96):  # 96 arrives after 97 on lane d0
        t.on_delivery("d0", seq)
    assert t.lanes_observed == 2 and t.lane_inversions == 1
    rep = _report(tracker=t)
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)


# --- the final reads, in order ---------------------------------------------------


def _stats_dead(dead: int) -> NodeStats:
    return NodeStats(done=0, dead=dead, pending=0, inflight=0, in_pipeline=0)


class _FinalNode:
    """The survivor's final reads, from a script, logging their order. Each dead-copy read returns
    the next scripted set, and each one also lands a late sink arrival on ``counters``, so a test can
    see which side of the reads the counters were taken on."""

    def __init__(
        self,
        copies: list[frozenset[tuple[str, float]] | None],
        stats: NodeStats | None,
        counters: Counters,
    ) -> None:
        self._copies = copies
        self._stats = stats
        self._counters = counters
        self.calls: list[str] = []

    async def dead_copies(self, client: object) -> frozenset[tuple[str, float]] | None:
        self.calls.append("copies")
        self._counters.sink_received += 1
        return self._copies.pop(0)

    async def stats(self, client: object) -> NodeStats | None:
        self.calls.append("stats")
        return self._stats


def _final(
    copies: list[frozenset[tuple[str, float]] | None],
    stats: NodeStats | None,
    carried: frozenset[tuple[str, float]] | None,
) -> tuple[_FinalNode, tuple[NodeStats, Counters, int | None]]:
    counters = Counters(sink_received=10)
    node = _FinalNode(copies, stats, counters)
    got = asyncio.run(failover._final_reads(node, object(), carried, counters))  # type: ignore[arg-type]
    return node, got


def test_final_reads_bracket_the_stats_read() -> None:
    carried = frozenset({_A, _B})
    node, (final, snapshot, dead_new) = _final([carried, carried], _stats_dead(2), carried)
    assert node.calls == ["copies", "stats", "copies"]
    assert (final.dead, dead_new) == (2, 0)
    # The first read's arrival is in, the second's is not: taken straight after the stats read.
    assert snapshot.sink_received == 11


def test_final_reads_judge_nothing_when_the_set_moved() -> None:
    carried = frozenset({_A, _B})
    _, (_, _, dead_new) = _final([carried, frozenset({_A, ("ox", 9.0)})], _stats_dead(2), carried)
    assert dead_new is None


def test_final_reads_skip_both_lists_with_nothing_carried() -> None:
    node, (_, _, dead_new) = _final([], _stats_dead(4), None)
    assert node.calls == ["stats"]
    assert dead_new is None


def test_final_reads_skip_the_second_list_when_nothing_is_dead() -> None:
    carried = frozenset({_A})
    node, _ = _final([carried], _stats_dead(0), carried)
    assert node.calls == ["copies", "stats"]


def test_final_reads_refuse_a_missing_final_stats_read() -> None:
    with pytest.raises(FailoverError, match="final /stats"):
        _final([None], None, frozenset({_A}))


def test_an_opening_read_that_does_not_match_the_opening_count_excuses_nothing() -> None:
    node = _CopyNode(frozenset({_A, _B, _C}))
    got = asyncio.run(failover._opening_dead_copies([node], object(), _stats_dead(2)))  # type: ignore[list-item,arg-type]
    assert got is None


def test_a_refused_session_is_a_partial_dead_copy_read(monkeypatch: pytest.MonkeyPatch) -> None:
    node = failover.EngineNode.__new__(failover.EngineNode)
    node.node_id = "fo-x"

    async def refuse(_client: object, _path: str) -> dict[str, Any]:
        raise FailoverError("node fo-x: sign-in refused")

    monkeypatch.setattr(node, "_signed_in_json", refuse)
    assert asyncio.run(node.dead_copies(object())) is None  # type: ignore[arg-type]


def test_a_failure_time_too_large_for_a_float_is_a_partial_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node, _ = _node_answering(monkeypatch, [{"total": 1, "dead_letters": [_row("a", 10**400)]}])
    assert asyncio.run(node.dead_copies(object())) is None  # type: ignore[arg-type]


def test_no_accepted_load_is_a_named_violation() -> None:
    rep = _report(acked=0, tracker=_tracker(n=0))
    assert rep.result_ok is False
    assert any(s.name == "messages_acked" and not s.ok for s in rep.slos)
    assert "(0 violated)" not in rep.render_console()


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("max_dup_rate", "nan"),
        ("recovery_ttl_multiple", "nan"),
        ("max_promotion_seconds", "inf"),
        ("leader_lease_ttl_seconds", "inf"),
    ],
)
def test_a_non_finite_failover_knob_is_refused_before_any_start(
    key: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Through the profile loader, which lets each of these through, so the guard is what stops it.
    profile = _profile(**{key: value})

    def boom(*_a: object, **_k: object) -> object:
        raise AssertionError("the run started")

    monkeypatch.setattr(failover, "build_corpus", boom)
    monkeypatch.setattr(failover, "EngineNode", boom)
    ports = FailoverPorts(
        api_a=1, api_b=2, inbound_adt=3, inbound_results=4, inbound_other=5, sink=6, sink_count=1
    )
    with pytest.raises(FailoverError, match=f"{key} must be a finite number"):
        asyncio.run(failover.run_failover_load(profile, ports=ports, base_env={}))


def test_the_console_escapes_the_backend_name() -> None:
    text = _report(db_backend="pg\x1b[2J\n").render_console()
    assert "\x1b" not in text
    assert "pg\\x1b[2J" in text
