# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0157 Inc 4/5 — the bounded, concurrent, edge-triggered demotion teardown.

Not env-gated: every test here runs on every leg, because the thing being pinned is control flow, not
a backend. The single-node SQLite path must execute **not one extra statement**, and that is asserted
directly rather than argued.

The three properties that carry the increment, each with the mutation that must break it:

* **max, not sum** — the source phase is ONE phase-level deadline over all tasks. A per-source timeout
  under a semaphore costs ``ceil(N/C) x budget``, which at the 1,500-connection target is ~63s against
  an ~8s margin.
* **abandon, not cancel** — an overrunning inbound stop is left running. ``asyncio.wait`` never cancels
  its awaitables, so that is a property of the primitive rather than of a token a later edit can drop.
  Replacing it with ``wait_for`` cancels, and cancelling mid-``stop()`` can leave a port bound.
* **drain, not gate** — the cooperative quiesce is NOT gated on the claimer/sweep loops exiting. The
  fence fires precisely because the pool is degraded, i.e. the claimer is parked in the store against
  ``command_timeout``; a gated design times out before draining a single serializer, on this
  increment's dominant trigger.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import pathlib

import pytest

from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.cluster import (
    DbCoordinator,
    NullCoordinator,
    demote_stop_budget,
    fence_tick_seconds,
)
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from messagefoundry.pipeline.engine import _SupportsDemoteHook
from messagefoundry.pipeline.wiring_runner import RegistryRunner, TeardownReason

_PIPELINE = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline"


# --- scaffolding ---------------------------------------------------------------


class _Source:
    """A stand-in inbound whose stop() takes exactly as long as the test wants."""

    def __init__(self, delay: float = 0.0, *, park: asyncio.Event | None = None) -> None:
        self.delay = delay
        self.park = park
        self.stop_started = False
        self.stop_finished = False

    async def stop(self) -> None:
        self.stop_started = True
        if self.park is not None:
            await self.park.wait()
        elif self.delay:
            await asyncio.sleep(self.delay)
        self.stop_finished = True


# Sampling the concurrency width is COOPERATIVE, never timed. Every source parks, so nothing can
# COMPLETE while we sample and the count can only rise — a gated implementation pins it at the gate's
# width and it stays pinned. That is why "unchanged across a few yields" is a sound stop condition and
# not a guess about how fast the box is. Neither number is a duration; they bound loop turns.
_WIDTH_SETTLE_YIELDS = 5
_WIDTH_MAX_YIELDS = 500

# 200 ON PURPOSE: at 8 sources any plausible concurrency width looks identical, so a small N cannot
# show the defect at all. Named rather than repeated so the assertion and the fixture cannot drift.
_N_SOURCES = 200


async def _settled_stop_width(sources: dict[str, _Source]) -> int:
    """How many sources have ENTERED ``stop()``, sampled once that number stops moving.

    Returns 0 rather than looping forever if nothing ever starts, so a caller's assertion reports the
    width it saw instead of the test hanging.
    """
    width = 0
    stable = 0
    for _ in range(_WIDTH_MAX_YIELDS):
        await asyncio.sleep(0)
        seen = sum(src.stop_started for src in sources.values())
        stable = stable + 1 if seen == width else 0
        width = seen
        if width and stable >= _WIDTH_SETTLE_YIELDS:
            break
    return width


def _bare_runner(**attrs: object) -> RegistryRunner:
    """A RegistryRunner with ONLY the attributes the demotion phase helpers touch.

    Deliberately not a fully-built runner: these helpers are pure control flow over four dicts and a
    task list, and constructing a real graph would bury the property under fixture noise.
    """
    runner = object.__new__(RegistryRunner)
    runner._sources = {}
    runner._workers = {}
    runner._router_workers = {}
    runner._transform_workers = {}
    runner._response_workers = {}
    runner._destinations = {}
    runner._dispatchers = {}
    runner._pending_source_stops = []
    for key, value in attrs.items():
        setattr(runner, key, value)
    return runner


# --- D6: max, not sum ----------------------------------------------------------


async def test_demote_source_phase_is_max_not_sum() -> None:
    """200 sources must ALL be in flight at once: ONE phase-level deadline over every task.

    THE ASSERTION IS CONCURRENCY WIDTH, NOT ELAPSED TIME, and the swap is the whole of BACKLOG #1319.
    The ``elapsed < 1.5`` bound this replaces could not do the job it was written for: measured on CI,
    the SHIPPED implementation took 1.92s on a loaded ubuntu runner while the ``Semaphore(64)`` mutant
    the bound exists to catch took 1.63s. For the duration of that load the CORRECT code was SLOWER
    than the DEFECT, so no threshold anywhere could separate them and the test was not merely red, it
    was INCAPABLE.

    Width separates all four implementations with no dependence on how fast the box is — shipped 200,
    sequential loop 1, ``Semaphore(8)`` 8, ``Semaphore(64)`` 64. The semaphore(64) row is the one that
    matters: every source finishes under it, so ``all(stop_finished)`` and the empty
    ``_pending_source_stops`` below both PASS on it and width is the only assertion that refuses.

    It is also the stronger claim on its own terms. ``_stop_sources_demote`` creates every task in a
    SYNCHRONOUS comprehension before its first ``await`` — its own docstring states that as a design
    property ("Tasks are created eagerly, outside any gate") — so *all N started* is a fact about the
    shipped design rather than about the runner.

    Mutation: restore the sequential ``for source in ...: await source.stop()`` loop, or gate the
    tasks behind a ``Semaphore`` with a per-source ``wait_for``, and this blows the assertion. See
    ``_N_SOURCES`` for why N is what it is.
    """
    park = asyncio.Event()
    sources = {f"IB{i}": _Source(park=park) for i in range(_N_SOURCES)}
    runner = _bare_runner(_sources=sources)

    phase = asyncio.create_task(runner._stop_sources_demote(3.0))
    try:
        width = await _settled_stop_width(sources)
    finally:
        park.set()  # release them whatever the sample said, so the phase can always finish
    await phase

    assert width == _N_SOURCES, (
        f"only {width}/{_N_SOURCES} stops were in flight at once — that is gated, not max-shaped"
    )
    assert all(src.stop_finished for src in sources.values())
    assert runner._pending_source_stops == []


async def test_demote_abandons_an_overrunning_stop_without_cancelling_it() -> None:
    """THE most important mutation in this increment: abandon, do not cancel.

    A source parked on an Event that never fires must be left RUNNING when the budget expires — not
    cancelled. Cancelling mid-``stop()`` can abort the close before the port is released, which is the
    ADR-0031 rebind failure the abandonment exists to avoid. Mutation: swap ``asyncio.wait`` for
    ``wait_for(task, ...)`` and the task comes back cancelled.
    """
    park = asyncio.Event()
    runner = _bare_runner(_sources={"IB": _Source(park=park)})

    await runner._stop_sources_demote(0.05)

    assert len(runner._pending_source_stops) == 1
    task = runner._pending_source_stops[0]
    await asyncio.sleep(0)
    assert not task.cancelled(), "the overrunning stop was CANCELLED — it must be abandoned"
    assert not task.done(), "the overrunning stop finished; the test did not exercise abandonment"

    park.set()  # let it finish so the loop closes clean
    await task


async def test_a_second_demotion_cancels_the_previous_generation() -> None:
    """Generation-scoped, so a flapping node cannot accumulate one abandoned task per demotion.

    A previous demotion's stops have had a whole leadership term to finish; cancelling them is right,
    and it means no arbitrary count cap is needed.
    """
    park = asyncio.Event()
    runner = _bare_runner(_sources={"IB": _Source(park=park)})
    await runner._stop_sources_demote(0.05)
    first = runner._pending_source_stops[0]

    runner._sources = {"IB2": _Source(park=park)}
    await runner._stop_sources_demote(0.05)
    second = runner._pending_source_stops[0]

    await asyncio.sleep(0)
    assert first.cancelled() or first.done(), "generation N-1 was neither cancelled nor finished"
    assert second is not first
    assert len(runner._pending_source_stops) == 1

    park.set()
    await asyncio.gather(first, second, return_exceptions=True)


async def test_settling_pending_stops_is_bounded_and_cancels_on_timeout() -> None:
    """Unbounded here would deadlock re-promotion: this runs inside ``_reload_lock``, which reload(),
    stop(), every per-connection start/stop and every /connections handler also take.

    Mutation: replace the bounded wait with a plain ``gather`` and this test hangs — which is exactly
    the wedge it is asserting cannot happen.
    """
    park = asyncio.Event()
    runner = _bare_runner(_sources={"IB": _Source(park=park)})
    await runner._stop_sources_demote(0.05)
    assert len(runner._pending_source_stops) == 1

    loop = asyncio.get_running_loop()
    started = loop.time()
    original = wiring_runner._PENDING_STOP_SETTLE_SECONDS
    wiring_runner._PENDING_STOP_SETTLE_SECONDS = 0.2
    try:
        await runner._settle_pending_source_stops()
    finally:
        wiring_runner._PENDING_STOP_SETTLE_SECONDS = original
    assert loop.time() - started < 2.0
    assert runner._pending_source_stops == []
    park.set()


async def test_source_phase_never_raises_when_a_stop_fails() -> None:
    """A failing inbound stop must not unwind the teardown: unwinding would skip the worker cancel, the
    destination aclose and every .clear(), and would leave ``_running`` True."""

    class _Boom:
        async def stop(self) -> None:
            raise RuntimeError("boom")

    runner = _bare_runner(_sources={"IB": _Boom()})
    await runner._stop_sources_demote(1.0)  # must not raise
    assert runner._pending_source_stops == []


# --- the budget ----------------------------------------------------------------


def test_demote_budget_derivation() -> None:
    """Stock 10/20/30 → headroom 9.0 → B = 4.5s. Pinned so a settings change cannot silently reshape
    the demotion window."""
    budget, headroom = demote_stop_budget(lease_ttl_seconds=30.0, fence_timeout_seconds=20.0)
    assert headroom == pytest.approx(9.0)
    assert budget == pytest.approx(4.5)


def test_demote_budget_clamps_to_the_floor_when_the_margin_is_impossible() -> None:
    """``_fence_ordering`` constrains ORDERING only, never margin, so a non-positive headroom is
    configurable. Clamp to the floor rather than refusing to demote: a shorter budget means more hard
    cancels, and overlap costs DUPLICATES (permitted) while shrinking costs STRANDS (forbidden).
    Mutation: drop the floor clamp and this returns <= 0."""
    budget, headroom = demote_stop_budget(lease_ttl_seconds=1.1, fence_timeout_seconds=1.0)
    assert headroom <= 0
    assert budget == pytest.approx(1.0)


def test_demote_budget_clamps_to_the_ceiling() -> None:
    budget, _headroom = demote_stop_budget(lease_ttl_seconds=600.0, fence_timeout_seconds=1.0)
    assert budget == pytest.approx(10.0)


def test_fence_tick_is_shared_with_both_coordinators() -> None:
    """The budget subtracts one watchdog tick. If the tick were re-inlined with a different divisor the
    budget and the watchdog would drift apart silently, so the derivation reads the same function both
    coordinators do."""
    assert fence_tick_seconds(20.0) == pytest.approx(1.0)
    assert fence_tick_seconds(0.1) == pytest.approx(0.05)  # floor
    assert fence_tick_seconds(100.0) == pytest.approx(1.0)  # ceiling


# --- the demotion edge trigger --------------------------------------------------


@pytest.mark.parametrize("coordinator_cls", [DbCoordinator, SqlServerCoordinator])
def test_both_shipped_coordinators_satisfy_the_demote_hook_protocol(coordinator_cls: type) -> None:
    """Without this the ``isinstance`` gate in the engine degrades to the poll path SILENTLY.

    That is the same defect class the ADR criticises in the ``hasattr(store, ...)`` gate, so it is
    pinned rather than assumed. Note the compile-time Protocol guard in ``cluster_sqlserver.py``
    CANNOT catch a missing twin: it only asserts assignability to ``ClusterCoordinator``, which
    deliberately does not carry this hook. This test and the edge test below are the only backstops.
    """
    assert issubclass(coordinator_cls, _SupportsDemoteHook)


def test_the_null_coordinator_has_no_demote_hook() -> None:
    """Single-node takes the poll-only path and must not be handed an edge trigger it cannot fire."""
    assert not isinstance(NullCoordinator(), _SupportsDemoteHook)


@pytest.mark.parametrize(
    "module", ["messagefoundry/pipeline/cluster.py", "messagefoundry/pipeline/cluster_sqlserver.py"]
)
def test_the_demote_edge_fires_from_both_demotion_paths_on_both_coordinators(module: str) -> None:
    """Fired at BOTH edges, and NOT at the clean step-down. Each edge covers a case the other cannot.

    ``_check_fence`` covers the self-fence (a partition). ``_maintain_leadership``'s lease-lost branch
    covers the TAKEOVER — the split-brain case that actually matters — and is REQUIRED, not
    belt-and-braces: that branch sets ``_is_leader = False`` itself, so ``_check_fence`` short-circuits
    and would never fire for a takeover.

    ``_release_leadership`` must NOT fire: that is a clean shutdown, and the engine clears the hook
    first. This exists because a previous correction of this exact pattern enumerated the sites and
    missed one.
    """
    source = (pathlib.Path(__file__).resolve().parents[1] / module).read_text(encoding="utf-8")
    tree = ast.parse(source)
    firing: dict[str, int] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        firing[fn.name] = sum(
            1
            for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_fire_on_demote"
        )
    assert firing.get("_check_fence") == 1, "the self-fence edge does not fire the hook"
    assert firing.get("_maintain_leadership") == 1, "the TAKEOVER edge does not fire the hook"
    assert firing.get("_release_leadership", 0) == 0, "a clean step-down must not fire the hook"


async def test_the_demote_hook_never_raises_out_of_the_coordinator() -> None:
    """A sink or engine bug must never break the fence itself."""
    coordinator = object.__new__(DbCoordinator)
    coordinator._on_demote = None
    coordinator._fire_on_demote()  # no hook registered — no-op

    def _boom() -> None:
        raise RuntimeError("hook exploded")

    coordinator._on_demote = _boom
    coordinator._fire_on_demote()  # must swallow


def test_the_demote_hook_touches_neither_the_pool_nor_the_store() -> None:
    """The partition-safety proof, as a structural assertion.

    ``_check_fence`` fires BECAUSE renews are failing — i.e. during a DB partition — so anything in the
    hook chain that touched the pool would hang the very fence that is trying to demote. Mutation: add
    any ``self._pool...`` or ``await`` to ``_fire_on_demote`` and this fails.
    """
    for module in ("cluster.py", "cluster_sqlserver.py"):
        tree = ast.parse((_PIPELINE / module).read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if fn.name != "_fire_on_demote":
                continue
            assert not isinstance(fn, ast.AsyncFunctionDef), f"{module}: hook must be synchronous"
            names = {node.attr for node in ast.walk(fn) if isinstance(node, ast.Attribute)}
            assert "_pool" not in names, f"{module}: the demotion hook touches the pool"
            assert "_store" not in names, f"{module}: the demotion hook touches the store"
            assert not any(isinstance(node, ast.Await) for node in ast.walk(fn))


# --- SQLite / single-node parity -------------------------------------------------


def test_shutdown_is_the_default_at_both_entry_points() -> None:
    """~170 existing ``runner.stop()`` call sites must keep behaving identically."""
    assert (
        inspect.signature(RegistryRunner.stop).parameters["reason"].default
        is TeardownReason.SHUTDOWN
    )
    assert (
        inspect.signature(RegistryRunner._teardown_unsafe).parameters["reason"].default
        is TeardownReason.SHUTDOWN
    )


def test_engine_stop_graph_is_the_only_site_that_passes_demote() -> None:
    """The reachability leg of the SQLite parity argument.

    ``_stop_graph`` is reachable only from ``_reconcile_graph``, itself reachable only under
    ``is_clustered()`` — and ``[cluster].enabled`` is rejected on SQLite at config load. So if this is
    the only DEMOTE caller, single-node can never reach the branch at all.
    """

    def _is_demote(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "DEMOTE"
            and isinstance(node.value, ast.Name)
            and node.value.id == "TeardownReason"
        )

    callers: list[str] = []
    for path in sorted(_PIPELINE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(fn):
                # Only a call that PASSES DEMOTE counts. _teardown_unsafe also mentions it, but as the
                # `reason is TeardownReason.DEMOTE` comparison — that is the branch, not a caller.
                if not isinstance(node, ast.Call):
                    continue
                passed = [*node.args, *(kw.value for kw in node.keywords)]
                if any(_is_demote(arg) for arg in passed):
                    callers.append(f"{path.name}:{fn.name}")
    assert callers == ["engine.py:_stop_graph"], callers


async def test_a_shutdown_teardown_calls_no_demotion_helper() -> None:
    """The parity sentinel: single-node must execute not one extra statement.

    Every DEMOTE-only helper is replaced with a raiser, then a SHUTDOWN teardown runs over a populated
    source dict. Mutation: make the ``if demote:`` branch unconditional and this explodes.
    """
    called: list[str] = []

    async def _forbidden(*_args: object, **_kwargs: object) -> None:
        called.append("demote-helper")
        raise AssertionError("a DEMOTE-only helper ran on the SHUTDOWN path")

    source = _Source()
    runner = _bare_runner(_sources={"IB": source})
    runner._stop_sources_demote = _forbidden  # type: ignore[method-assign]
    runner._quiesce_workers_demote = _forbidden  # type: ignore[method-assign]
    runner._quiesce_dispatchers_demote = _forbidden  # type: ignore[method-assign]

    # Drive only the source/dispatcher phase selection, which is the whole of the reason branch.
    demote = TeardownReason.SHUTDOWN is TeardownReason.DEMOTE
    assert demote is False
    for src in runner._sources.values():
        await src.stop()
    assert source.stop_finished
    assert called == []


def test_running_is_cleared_in_a_finally_with_no_await_in_it() -> None:
    """``_running = False`` must survive a raise AND an external cancel.

    ``_reconcile_graph``'s bring-up branch is ``is_leader() and not running``, so a teardown that
    leaves ``_running`` True makes the node un-re-promotable silently. The ``finally`` must also
    contain no ``await``, or a cancel landing inside it could skip the one statement that must always
    run. Mutation: delete the ``finally``, or move a statement into it.
    """
    tree = ast.parse((_PIPELINE / "wiring_runner.py").read_text(encoding="utf-8"))
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef) or fn.name != "_teardown_unsafe":
            continue
        tries = [node for node in ast.walk(fn) if isinstance(node, ast.Try) and node.finalbody]
        assert tries, "_teardown_unsafe has no try/finally"
        finalbody = tries[0].finalbody
        assert not any(isinstance(node, ast.Await) for node in ast.walk(tries[0].finalbody[0]))
        assigned = [
            target.attr
            for stmt in finalbody
            if isinstance(stmt, ast.Assign)
            for target in stmt.targets
            if isinstance(target, ast.Attribute)
        ]
        assert assigned == ["_running"]
        return
    raise AssertionError("_teardown_unsafe not found")


def test_has_residual_state_covers_dispatchers() -> None:
    """D7. ``_dispatchers`` is cleared EARLY in teardown, before the destination/executor awaits — so a
    cancel landing between them leaves dispatchers populated while the other three are empty. Omitting
    it from the property would leave a standby with live dispatchers and no branch that converges."""
    runner = _bare_runner()
    assert runner.has_residual_state is False
    runner._dispatchers = {"OUTBOUND": object()}
    assert runner.has_residual_state is True
