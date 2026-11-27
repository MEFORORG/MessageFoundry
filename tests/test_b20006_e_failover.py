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
import json
import logging
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
    ("opening", "first", "second", "final_dead"),
    [
        (None, frozenset({_A}), frozenset({_A}), 1),  # no opening reading
        (frozenset({_A}), None, frozenset({_A}), 1),  # no first reading after the final stats
        (frozenset({_A}), frozenset({_A}), None, 1),  # no second reading
        (frozenset({_A}), frozenset({_A}), frozenset({_A, _B}), 2),  # the set moved across them
        (frozenset({_A, _B}), frozenset({_A}), frozenset({_A}), 2),  # stats sees a copy they miss
    ],
)
def test_an_inconclusive_reading_judges_nothing(
    opening: frozenset[tuple[str, float]] | None,
    first: frozenset[tuple[str, float]] | None,
    second: frozenset[tuple[str, float]] | None,
    final_dead: int,
) -> None:
    assert _judge_new_dead(opening, first, second, final_dead) is None


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


#: A scripted page: a JSON object answered 200, ``None`` for a node that did not answer, or a bare
#: status: a refusal with a detail body, or 200 with no JSON object.
_Page = dict[str, Any] | int | None
_REFUSAL_DETAIL = "SYNTHETIC-REFUSAL-DETAIL"


def _node_answering(
    monkeypatch: pytest.MonkeyPatch, pages: list[_Page]
) -> tuple[failover.EngineNode, list[str]]:
    node = failover.EngineNode.__new__(failover.EngineNode)
    node.node_id = "fo-x"
    paths: list[str] = []

    async def answer(_client: object, path: str) -> tuple[int | None, dict[str, Any] | None]:
        paths.append(path)
        page = pages[min(len(paths) - 1, len(pages) - 1)]
        if page is None:
            return None, None
        if isinstance(page, int):
            # A refusal carries the engine's own detail text, which must never reach a log.
            return page, ({"detail": _REFUSAL_DETAIL} if page != 200 else None)
        return 200, page

    monkeypatch.setattr(node, "_signed_in_reply", answer)
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
    pages: list[_Page], monkeypatch: pytest.MonkeyPatch
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


def _stats_dead(dead: int, in_pipeline: int = 0) -> NodeStats:
    return NodeStats(done=0, dead=dead, pending=0, inflight=0, in_pipeline=in_pipeline)


class _FinalNode:
    """The survivor's final reads, from a script, logging their order. Each stats read returns the
    next scripted reading (the last one repeats), and each dead-copy read returns the next scripted
    set. A dead-copy read also lands a late sink arrival on ``counters`` and a late delivery of seq 0
    on ``tracker``, so a test can see which side of the reads the counters and tracker were taken
    on."""

    def __init__(
        self,
        copies: list[frozenset[tuple[str, float]] | None],
        stats: list[NodeStats | None],
        counters: Counters,
        tracker: FailoverTracker,
    ) -> None:
        self._copies = copies
        self._stats = stats
        self._counters = counters
        self._tracker = tracker
        self.calls: list[str] = []

    async def dead_copies(self, client: object) -> frozenset[tuple[str, float]] | None:
        self.calls.append("copies")
        self._counters.sink_received += 1
        self._tracker.on_delivery("d0", 0)
        return self._copies.pop(0)

    async def stats(self, client: object) -> NodeStats | None:
        self.calls.append("stats")
        return self._stats.pop(0) if len(self._stats) > 1 else self._stats[0]


def _final(
    copies: list[frozenset[tuple[str, float]] | None],
    stats: NodeStats | None | list[NodeStats | None],
    carried: frozenset[tuple[str, float]] | None,
    tracker: FailoverTracker | None = None,
) -> tuple[_FinalNode, tuple[NodeStats, Counters, FailoverTracker, int | None]]:
    counters = Counters(sink_received=10)
    tracker = tracker or FailoverTracker()
    script = stats if isinstance(stats, list) else [stats]
    node = _FinalNode(copies, script, counters, tracker)
    got = asyncio.run(failover._final_reads(node, object(), carried, counters, tracker))  # type: ignore[arg-type]
    return node, got


def test_final_reads_take_the_stats_first_then_bracket_a_second_one() -> None:
    carried = frozenset({_A, _B})
    node, (final, snapshot, _, dead_new) = _final([carried, carried], _stats_dead(2), carried)
    assert node.calls == ["stats", "copies", "stats", "copies"]
    assert (final.dead, dead_new) == (2, 0)
    # Taken straight after the first stats read: no dead-copy read's arrival is in.
    assert snapshot.sink_received == 10


def test_a_drain_that_finishes_during_the_dead_copy_reads_still_fails() -> None:
    """BACKLOG #5572: the final stats read must see the moment ``main`` saw, straight after the
    drain. Here the pipeline empties only once the rig starts reading dead copies; the verdict reads
    the stranded rows, so the run fails as it would on a fresh store."""
    carried = frozenset({_A})
    stranded, drained = _stats_dead(1, in_pipeline=4), _stats_dead(1)

    class _DrainsDuringTheRead(_FinalNode):
        async def stats(self, client: object) -> NodeStats | None:
            self.calls.append("stats")
            return drained if "copies" in self.calls else stranded

    counters = Counters(sent=100, acked=98, sink_received=196, timeouts=2)
    tracker = _tracker()
    node = _DrainsDuringTheRead([carried, carried], [], counters, tracker)
    final, snapshot, held, dead_new = asyncio.run(
        failover._final_reads(node, object(), carried, counters, tracker)  # type: ignore[arg-type]
    )
    assert final.in_pipeline == 4
    # The second stats read no longer matches the first, so nothing is excused either.
    assert dead_new is None
    profile = _profile()
    rep = _build_report(
        profile,
        "postgres",
        snapshot,
        held,
        _outcome(),
        final,
        done_at_start=0,
        fo=profile.failover,
        notes=[],
        dead_opening=1,
        dead_new=dead_new,
    )
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


def test_a_delivery_during_the_dead_copy_reads_counts_for_nothing() -> None:
    # Seq 0 was acked and had not reached the sink at the final stats read. The dead-copy reads
    # deliver it; the report still counts it as not delivered, as it would have on main.
    carried = frozenset({_A})
    tracker = FailoverTracker()
    tracker.on_ack(0)
    _, (_, _, held, _) = _final([carried, carried], _stats_dead(1), carried, tracker=tracker)
    assert tracker.acked_not_delivered() == 0
    assert held.acked_not_delivered() == 1


def test_final_reads_judge_nothing_when_the_second_stats_read_moved() -> None:
    carried = frozenset({_A, _B})
    moved = NodeStats(done=1, dead=2, pending=0, inflight=0, in_pipeline=0)
    node, (final, _, _, dead_new) = _final([carried], [_stats_dead(2), moved], carried)
    assert node.calls == ["stats", "copies", "stats"]
    assert final == _stats_dead(2)
    assert dead_new is None


def test_final_reads_judge_nothing_when_the_set_moved() -> None:
    carried = frozenset({_A, _B})
    _, (_, _, _, dead_new) = _final(
        [carried, frozenset({_A, ("ox", 9.0)})], _stats_dead(2), carried
    )
    assert dead_new is None


def test_final_reads_skip_every_list_with_nothing_carried() -> None:
    node, (_, _, _, dead_new) = _final([], _stats_dead(4), None)
    assert node.calls == ["stats"]
    assert dead_new is None


def test_final_reads_skip_every_list_when_nothing_is_dead() -> None:
    node, _ = _final([], _stats_dead(0), frozenset({_A}))
    assert node.calls == ["stats"]


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

    async def refuse(_client: object, _path: str) -> tuple[int, dict[str, Any]]:
        raise FailoverError("node fo-x: sign-in refused")

    monkeypatch.setattr(node, "_signed_in_reply", refuse)
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


@pytest.mark.parametrize(
    "before", [None, frozenset({_A})], ids=["no first read", "first read short of the count"]
)
def test_final_reads_skip_a_second_list_that_could_not_count(
    before: frozenset[tuple[str, float]] | None,
) -> None:
    node, (_, _, _, dead_new) = _final([before], _stats_dead(2), frozenset({_A, _B}))
    assert node.calls == ["stats", "copies"]
    assert dead_new is None


def test_a_store_past_the_cap_is_never_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(failover, "_DEAD_COPIES_MAX", 2)
    node = _CopyNode(frozenset({_A, _B, _C}))
    got = asyncio.run(failover._opening_dead_copies([node], object(), _stats_dead(3)))  # type: ignore[list-item,arg-type]
    assert got is None
    assert node.reads == 0


def test_a_lease_whose_recovery_bound_overflows_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every knob is finite and passes the loader; the bound 2 x 1e308 is not.
    profile = _profile(leader_lease_ttl_seconds="1e308")

    def started(*_a: object, **_k: object) -> object:
        raise AssertionError("the run started")

    monkeypatch.setattr(failover, "build_corpus", started)
    ports = FailoverPorts(
        api_a=1, api_b=2, inbound_adt=3, inbound_results=4, inbound_other=5, sink=6, sink_count=1
    )
    with pytest.raises(FailoverError, match="too large"):
        asyncio.run(failover.run_failover_load(profile, ports=ports, base_env={}))


# --- what a refused page logs, and what the rig keeps of a row ---------------------


@pytest.mark.parametrize(
    ("page", "reason"),
    [
        (None, "no answer at offset 0"),
        (429, "HTTP 429 at offset 0"),
        (403, "HTTP 403 at offset 0"),
        (422, "HTTP 422 at offset 0"),
        (200, "an answer that is not a JSON object at offset 0"),
    ],
)
def test_a_refused_page_is_logged_by_status_never_by_body(
    page: _Page, reason: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    node, _ = _node_answering(monkeypatch, [page])
    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(node.dead_copies(object())) is None  # type: ignore[arg-type]
    assert reason in caplog.text
    assert _REFUSAL_DETAIL not in caplog.text


_SENTINEL = "SYNTHETIC-PHI-SENTINEL"


def _full_row(oid: str, at: float) -> dict[str, object]:
    """A row with every field ``/dead-letters`` returns, each non-id field carrying the sentinel."""
    return {
        "outbox_id": oid,
        "failed_at": at,
        "message_id": f"{_SENTINEL}-mid",
        "channel_id": f"{_SENTINEL}-in",
        "destination_name": f"{_SENTINEL}-out",
        "attempts": 3,
        "last_error": f"{_SENTINEL}-error",
        "control_id": f"{_SENTINEL}-ctl",
        "message_type": f"{_SENTINEL}-type",
        "received_at": 1.0,
        "summary": f"{_SENTINEL}-summary",
    }


def test_a_whole_read_keeps_only_the_outbox_id_and_failure_time(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    node, _ = _node_answering(
        monkeypatch, [{"total": 2, "dead_letters": [_full_row("o1", 1.0), _full_row("o2", 2.0)]}]
    )
    with caplog.at_level(logging.DEBUG):
        got = asyncio.run(node.dead_copies(object()))  # type: ignore[arg-type]
    assert got == frozenset({("o1", 1.0), ("o2", 2.0)})
    assert _SENTINEL not in repr(got)
    assert _SENTINEL not in caplog.text


def test_a_partial_read_logs_no_row_field(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(failover, "_DEAD_PAGE", 1)
    node, _ = _node_answering(
        monkeypatch,
        [
            {"total": 2, "dead_letters": [_full_row("o1", 1.0)]},
            {"total": 2, "dead_letters": [_full_row("o1", 1.0)]},  # seen twice
        ],
    )
    with caplog.at_level(logging.DEBUG):
        assert asyncio.run(node.dead_copies(object())) is None  # type: ignore[arg-type]
    assert "seen twice" in caplog.text
    assert _SENTINEL not in caplog.text
    assert "o1" not in caplog.text


def test_the_report_carries_counts_never_a_dead_copy_id() -> None:
    carried = frozenset({("SYNTHETIC-OID-1", 1.0), ("SYNTHETIC-OID-2", 2.0)})
    grown = frozenset({("SYNTHETIC-OID-1", 1.0), ("SYNTHETIC-OID-3", 3.0)})
    _, (final, snapshot, held, dead_new) = _final([grown, grown], _stats_dead(2), carried)
    assert dead_new == 1
    profile = _profile()
    rep = _build_report(
        profile,
        "postgres",
        snapshot,
        held,
        _outcome(),
        final,
        done_at_start=0,
        fo=profile.failover,
        notes=[],
        dead_opening=1,
        dead_new=dead_new,
    )
    text = json.dumps(rep.to_json_dict()) + rep.render_console() + "".join(rep.notes)
    assert "SYNTHETIC-OID" not in text


# --- review round 1: optional reads never end a run, and every fallback says why ------


def test_a_refused_second_stats_read_judges_nothing_and_does_not_end_the_run() -> None:
    carried = frozenset({_A})

    class _RefusesTheSecondStats(_FinalNode):
        async def stats(self, client: object) -> NodeStats | None:
            self.calls.append("stats")
            if self.calls.count("stats") > 1:
                raise FailoverError("node fo-b: sign-in refused")
            return _stats_dead(1)

    counters, tracker = Counters(), FailoverTracker()
    node = _RefusesTheSecondStats([carried, carried], [], counters, tracker)
    final, _, _, dead_new = asyncio.run(
        failover._final_reads(node, object(), carried, counters, tracker)  # type: ignore[arg-type]
    )
    assert final == _stats_dead(1)
    assert dead_new is None
    assert node.calls == ["stats", "copies", "stats"]


def test_more_dead_rows_than_were_carried_are_never_listed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        node, (_, _, _, dead_new) = _final([], _stats_dead(3), frozenset({_A, _B}))
    assert node.calls == ["stats"]
    assert dead_new is None
    assert "3 dead rows at the end, more than the 2 carried over" in caplog.text


@pytest.mark.parametrize(
    ("copies", "stats", "why"),
    [
        ([frozenset({_A})], [_stats_dead(2)], "1 dead copies read at the end, of 2 counted"),
        (
            [frozenset({_A, _B})],
            [_stats_dead(2), NodeStats(done=1, dead=2, pending=0, inflight=0, in_pipeline=0)],
            "the counts moved",
        ),
        ([frozenset({_A, _B}), frozenset({_A, _C})], [_stats_dead(2)], "the dead copies moved"),
    ],
)
def test_a_final_fallback_logs_why(
    copies: list[frozenset[tuple[str, float]] | None],
    stats: list[NodeStats | None],
    why: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _, (_, _, _, dead_new) = _final(copies, stats, frozenset({_A, _B, _C}))
    assert dead_new is None
    assert f"dead-row check stays absolute: {why}" in caplog.text


def test_an_opening_count_mismatch_logs_why(caplog: pytest.LogCaptureFixture) -> None:
    node = _CopyNode(frozenset({_A, _B, _C}))
    with caplog.at_level(logging.WARNING):
        got = asyncio.run(failover._opening_dead_copies([node], object(), _stats_dead(2)))  # type: ignore[list-item,arg-type]
    assert got is None
    assert "3 dead copies read at the opening, of 2 counted" in caplog.text


def test_one_lane_fails_a_named_lane_count_check() -> None:
    rep = _report(tracker=_tracker(lanes=("d0",)))
    lanes = next(s for s in rep.slos if s.name == "lanes_observed")
    assert (lanes.threshold, lanes.observed, lanes.ok) == (2, 1, False)
    assert "lanes_observed: observed=1 threshold=2" in rep.render_console()
    assert next(s for s in _report().slos if s.name == "lanes_observed").ok


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("inf", "must be a finite number"),
        ("nan", "must be a finite number"),
        # Each finite, and the lease passes its own bound; 4 x 4e307 + 1e308 does not.
        ("1e308", "too large"),
    ],
)
def test_a_non_finite_drain_timeout_is_refused_before_any_start(
    value: str, match: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = _PROFILE.replace("pool_size = 1", f"pool_size = 1\ndrain_timeout_s = {value}")
    knobs = {**_FAILOVER, "leader_lease_ttl_seconds": "4e307"}
    table = "\n".join(f"{k} = {v}" for k, v in knobs.items())
    profile = load_profile_text(text.format(failover=table), where="<test>")

    def started(*_a: object, **_k: object) -> object:
        raise AssertionError("the run started")

    monkeypatch.setattr(failover, "build_corpus", started)
    ports = FailoverPorts(
        api_a=1, api_b=2, inbound_adt=3, inbound_results=4, inbound_other=5, sink=6, sink_count=1
    )
    with pytest.raises(FailoverError, match=f"drain_timeout_s (is )?{match}"):
        asyncio.run(failover.run_failover_load(profile, ports=ports, base_env={}))


def test_the_dead_copy_read_matches_the_route_it_reads() -> None:
    """The rig reads four names from ``/dead-letters`` and pages at :data:`failover._DEAD_PAGE`. A
    rename or a lower ``limit`` ceiling there would make every read partial and switch the per-copy
    check off with no test red, so both are pinned to the route's own definitions."""
    import ast
    from pathlib import Path

    from messagefoundry.api.models import DeadLetterList, DeadLetterRow

    assert {"total", "dead_letters"} <= set(DeadLetterList.model_fields)
    assert {"outbox_id", "failed_at"} <= set(DeadLetterRow.model_fields)
    app = Path(__file__).resolve().parents[1] / "messagefoundry" / "api" / "app.py"
    route = next(
        n
        for n in ast.walk(ast.parse(app.read_text(encoding="utf-8")))
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "list_dead_letters"
    )
    limit = next(a for a in route.args.args if a.arg == "limit")
    default = route.args.defaults[route.args.args.index(limit) - len(route.args.args)]
    assert isinstance(default, ast.Call)
    le = next(k.value for k in default.keywords if k.arg == "le")
    assert isinstance(le, ast.Constant) and isinstance(le.value, int)
    assert le.value >= failover._DEAD_PAGE
