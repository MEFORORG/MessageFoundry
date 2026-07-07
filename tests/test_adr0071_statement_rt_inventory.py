# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 (B5) Lane 3a — per-hop SQL statement / network round-trip inventory, as a LIVING gate.

Sibling to ``test_adr0071_crossing_count.py``. That gate locks the *executor->loop crossing* count;
this one locks the *SQL statement + pyodbc round-trip* count each staged SQL Server hop issues, plus
the batched-collapse estimate — evidence that informs (does NOT by itself decide) the "SQL
statement-batching per hop" build-go.

The counts are MEASURED by driving the REAL shipped store methods (``route_handoff_sync`` /
``transform_handoff_sync`` / ``mark_done``) against a recording fake cursor — the same offline
harness as ``test_sqlserver_sync_handoff_offline.py`` (no live SQL Server, no pyodbc/aioodbc extra).
The mechanism/analysis is NOT re-implemented here: the committed micro-bench
(``docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/statement_rt_inventory.py``) is
loaded as the single source of the recording + batching model, and the test asserts on its result
objects directly.

What is locked (so it cannot silently drift):
  * per-hop ``execute()`` (unbatched round-trip) counts and the ``commit()`` count;
  * the commits/msg == 2.000 identity across the route+transform pipeline pair (batching moves NO
    commit boundary — the ADR 0069 transaction-fusion fence is NOT crossed) — UNCONDITIONAL;
  * the batched round-trip counts under BOTH batching variants, and the CONDITIONALITY of the ≥40%
    claim: the applock-FOLD variant clears ≥40% for route_handoff / transform_handoff / the pair,
    while the STRICT variant clears NOTHING (27-33%). The gate asserts both floors so a "≥40% cleared"
    number can never be quoted without its condition (see
    ``test_batched_collapse_40pct_is_conditional_on_applock_fold``);
  * that the batched form preserves the IDENTICAL logical (sql, params) sequence (regroup-only), with
    a negative control proving that check is not vacuous.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


def _load_inventory_bench() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "benchmarks"
        / "results"
        / "2026-07-04-adr0071-b5-executor-marshaling"
        / "statement_rt_inventory.py"
    )
    assert path.is_file(), f"committed inventory micro-bench not found at {path}"
    spec = importlib.util.spec_from_file_location("adr0071_statement_rt_inventory", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: the bench defines a @dataclass under ``from __future__ import annotations``,
    # and dataclasses resolves ClassVar/InitVar via ``sys.modules[cls.__module__]`` — absent when a
    # file is loaded by path, which raises. (Running the bench as __main__ registers it implicitly.)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def inv() -> dict[str, Any]:
    result: dict[str, Any] = _load_inventory_bench().build_inventory()
    return result


# --- per-hop statement / round-trip counts (the locked inventory) ---------------------------------

# hop -> (executes, commits, statements, rt_unbatched, rt_batched_soft, rt_batched_hard)
# Exact, deterministic: crossings/statements are fixed per hop; the recording harness has no noise.
_EXPECTED = {
    "route_handoff": (5, 1, 8, 6, 3, 4),
    "transform_handoff": (6, 1, 9, 7, 4, 5),
    "mark_done": (10, 1, 13, 11, 7, 8),
}


@pytest.mark.parametrize("hop", list(_EXPECTED))
def test_per_hop_statement_and_round_trip_counts(inv: dict[str, Any], hop: str) -> None:
    h = inv[hop]
    exec_, commits, stmts, rt_now, rt_soft, rt_hard = _EXPECTED[hop]
    assert h.executes == exec_, f"{hop} execute() count drifted: {h.executes} != {exec_}"
    assert h.commits == commits, f"{hop} commit count drifted: {h.commits} != {commits}"
    assert h.statements == stmts, (
        f"{hop} logical statement count drifted: {h.statements} != {stmts}"
    )
    assert h.rt_unbatched == rt_now == exec_ + commits
    assert h.rt_batched_soft == rt_soft, (
        f"{hop} batched RT drifted: {h.rt_batched_soft} != {rt_soft}"
    )
    assert h.rt_batched_hard == rt_hard, (
        f"{hop} strict RT drifted: {h.rt_batched_hard} != {rt_hard}"
    )


def test_commits_per_msg_identity_is_two(inv: dict[str, Any]) -> None:
    """The two pipeline handoff hops commit EXACTLY once each -> commits/msg == 2.000, and batching
    keeps 1 commit/hop, so the identity is untouched (this is why per-hop batching is NOT the ADR 0069
    transaction-fusion fence)."""
    route = inv["route_handoff"]
    trans = inv["transform_handoff"]
    assert route.commits == 1
    assert trans.commits == 1
    assert route.commits + trans.commits == 2  # commits/msg == 2.000


def test_batched_form_preserves_identical_logical_sequence(inv: dict[str, Any]) -> None:
    """Batching only regroups consecutive statements into fewer round-trips: for the REAL partition of
    every hop, the content-based reconstruction equals the original (sql, params) sequence under BOTH
    batching variants. (That this check has teeth — that a reordered grouping WOULD fail it — is proven
    separately by ``test_regroup_check_has_teeth``, so this assertion is not vacuous.)"""
    mod = _load_inventory_bench()
    for hop in _EXPECTED:
        for applock_soft in (True, False):
            assert mod.verify_logical_sequence_preserved(inv[hop], applock_soft=applock_soft), (
                f"{hop} logical (sql,params) sequence not preserved (applock_soft={applock_soft})"
            )


def test_regroup_check_has_teeth(inv: dict[str, Any]) -> None:
    """Negative control: the content-based reconstruction MUST detect a grouping that reorders, drops,
    or duplicates a statement — otherwise the "regroup-only" proof above would be vacuous. Feed
    ``flatten_groups`` hand-corrupted groupings and assert each reconstruction differs from the
    original calls."""
    mod = _load_inventory_bench()
    calls = inv["route_handoff"].calls
    assert len(calls) >= 3
    # sanity: the identity grouping reconstructs exactly (control for the control).
    identity = [[i] for i in range(len(calls))]
    assert mod.flatten_groups(calls, identity) == calls

    # (a) REORDER: swap the first two statements (guard DELETE <-> first INSERT) -> reconstruction
    #     differs, so a reordering batcher would be caught.
    reordered = [[1, 0]] + [[i] for i in range(2, len(calls))]
    assert mod.flatten_groups(calls, reordered) != calls

    # (b) DROP: omit the last statement -> shorter reconstruction, caught.
    dropped = [[i] for i in range(len(calls) - 1)]
    assert mod.flatten_groups(calls, dropped) != calls

    # (c) DUPLICATE: repeat a statement -> longer reconstruction, caught.
    duplicated = identity + [[0]]
    assert mod.flatten_groups(calls, duplicated) != calls


def test_batched_collapse_40pct_is_conditional_on_applock_fold(inv: dict[str, Any]) -> None:
    """The ≥40% assessment is CONDITIONAL, and the gate locks BOTH sides so neither can be quoted in
    isolation to justify un-holding statement-batching:

      * applock-FOLD (soft): route_handoff (50.0%), transform_handoff (42.9%) and the route+transform
        pair (46.2%) clear ≥40%; mark_done (36.4%) does NOT.
      * applock-STRICT (hard): NOTHING clears ≥40% — the drops are 27.3-33.3%.

    So there is no interpretation-independent ≥40% result; the honest range is 27-50% per hop, and a
    real GO/NO-GO needs the Wave-2 rig e2e A/B. (The invariants — commits/msg==2.000 and the preserved
    logical sequence — hold unconditionally; those are asserted elsewhere.)"""
    route = inv["route_handoff"]
    trans = inv["transform_handoff"]
    mark = inv["mark_done"]

    # --- FOLD side: exactly which hops clear the bar (lock the values, not just the >= relation). ---
    assert route.drop_soft == pytest.approx(3 / 6, rel=1e-6) and route.drop_soft >= 0.40
    assert trans.drop_soft == pytest.approx(3 / 7, rel=1e-6) and trans.drop_soft >= 0.40
    assert (
        mark.drop_soft == pytest.approx(4 / 11, rel=1e-6) and mark.drop_soft < 0.40
    )  # honest floor

    pipe_now = route.rt_unbatched + trans.rt_unbatched
    pipe_soft = route.rt_batched_soft + trans.rt_batched_soft
    assert pipe_now == 13 and pipe_soft == 7
    assert (pipe_now - pipe_soft) / pipe_now == pytest.approx(6 / 13, rel=1e-6)
    assert (pipe_now - pipe_soft) / pipe_now >= 0.40

    # --- STRICT side: the conditionality made explicit — NOTHING clears ≥40%, and the floor is
    #     27-33%. Locking these is the whole point: a reader cannot see "≥40% cleared" without the
    #     gate also asserting the strict interpretation clears nothing. ---
    assert route.drop_hard == pytest.approx(2 / 6, rel=1e-6)  # 33.3% (strict max)
    assert trans.drop_hard == pytest.approx(2 / 7, rel=1e-6)  # 28.6%
    assert mark.drop_hard == pytest.approx(3 / 11, rel=1e-6)  # 27.3% (strict min)
    for h in (route, trans, mark):
        assert h.drop_hard < 0.40, f"{h.name} strict drop unexpectedly clears 40%: {h.drop_hard}"
    pipe_hard = route.rt_batched_hard + trans.rt_batched_hard
    assert (pipe_now - pipe_hard) / pipe_now == pytest.approx(4 / 13, rel=1e-6)  # 30.8%
    assert (pipe_now - pipe_hard) / pipe_now < 0.40

    # The full opportunity range spanning both interpretations is 27-50% per hop.
    all_drops = [route.drop_soft, trans.drop_soft, mark.drop_soft,
                 route.drop_hard, trans.drop_hard, mark.drop_hard]  # fmt: skip
    assert min(all_drops) == pytest.approx(3 / 11, rel=1e-6)  # 27.3%
    assert max(all_drops) == pytest.approx(3 / 6, rel=1e-6)  # 50.0%


def test_statement_count_is_batching_invariant(inv: dict[str, Any]) -> None:
    """Batching changes ONLY how statements group into round-trips, never how many statements are
    issued: the locked logical T-SQL statement total is independent of the batching variant (the
    finalize applock's 4-statement batch counts as 4 statements but 1 round-trip)."""
    for hop in _EXPECTED:
        assert inv[hop].statements == _EXPECTED[hop][2]
