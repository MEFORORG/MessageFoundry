# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Subprocess isolation for Routers/Handlers (ADR 0087, BACKLOG #197).

Proves the crux parity property (``mode=off`` — and a benign ``subprocess`` round-trip — are
byte-identical to a direct in-process call) plus the isolation guarantees: a forbidden op is denied,
a runaway is capped without wedging intake, a sandboxed ``db_lookup``/``fhir_lookup`` fails closed,
the marshalled :class:`RunContext` reaches the worker, a ``__reduce__`` gadget returned by a Handler
never executes in the engine parent, a desynchronized/forged/pre-staged response frame can never
answer a later dispatch, and the engine's code-set tables — not the child's own re-read of
``codesets/`` — are what a sandboxed Handler resolves against. Synthetic HL7 only."""

from __future__ import annotations

import math
import os
import queue
import signal
import sys
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from messagefoundry.config.code_sets import CodeSet
from messagefoundry.config.response import CapturedResponse
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline._sandbox_codec import (
    _Blobs,
    _Reader,
    dec_run_context,
    enc_run_context,
    encode_request,
)
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.sandbox import (
    _EOF,
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
)
from messagefoundry.store.store import MessageStore

# A minimal, conformant synthetic ADT^A01 (no PHI — fabricated ids/names).
RAW = "MSH|^~\\&|SEND|F|RECV|F|20240101120000||ADT^A01|MSG00001|P|2.3\rPID|1||900001||DOE^JANE\r"

_GRAPH = """
from messagefoundry import (
    inbound, outbound, router, handler, MLLP, Send, SetState,
    db_lookup, current_environment, reference, response_get,
)

inbound("IB_T", MLLP(port=19311), router="r")
inbound("IB_GEN", MLLP(port=19313), router="r_gen")
inbound("IB_MUT", MLLP(port=19315), router="r_mut")
outbound("OB_T", MLLP(host="127.0.0.1", port=19312))


@router("r")
def r(msg):
    return "h_ok"


@router("r_mut")
def r_mut(msg):
    # CONTRACT-VIOLATING on purpose (CLAUDE.md §2: routers must be pure). In-process the predicate
    # below sees this mutation because it is handed the SAME object; across the pipe it cannot.
    msg.set("MSH-6", "ROUTER_TOUCHED")
    return ["h_sees_mutation"]


def _sees_mutation(msg):
    return msg.field("MSH-6") == "ROUTER_TOUCHED"


@handler("h_sees_mutation", accepts=_sees_mutation)
def h_sees_mutation(msg):
    return Send("OB_T", str(msg))


@router("r_gen")
def r_gen(msg):
    # A GENERATOR router is documented-supported (route_only routes the yielded values). It is not
    # picklable, so before the codec it dead-lettered every message under mode=subprocess.
    yield "h_ok"


class _Gadget:
    \"\"\"A Handler return value whose __reduce__ writes to the filesystem of whichever process
    deserializes it. Harmless under a non-executing codec; a full engine-parent escape under pickle.\"\"\"

    def __reduce__(self):
        import os

        return (os.makedirs, (__SENTINEL__,))


@handler("h_gadget")
def h_gadget(msg):
    return _Gadget()


@handler("h_gen_fanout")
def h_gen_fanout(msg):
    # A GENERATOR handler (BACKLOG #341). Its yields are lazy, so this also pins WHERE the child
    # materialises them, not just that it does.
    yield Send("OB_T", "GEN_A")
    yield Send("OB_T", "GEN_B")


@handler("h_set_fanout")
def h_set_fanout(msg):
    # A SET handler (BACKLOG #341). Six elements, because the contract this probes is the delivered
    # MULTISET: the child is a different PROCESS with its own hash seed, so the order it materialises
    # a set in is not the parent's.
    return {Send("OB_T", f"SET_{c}") for c in "ABCDEF"}


@handler("h_state")
def h_state(msg):
    return [SetState("ns", "tup", (1, 2)), SetState("ns", "nan", float("nan"))]


@handler("h_reply")
def h_reply(msg):
    rep = response_get("OB_T")
    return Send("OB_T", rep.body if rep is not None else "NOREPLY")


@handler("h_forge")
def h_forge(msg):
    # Write an EXTRA well-formed response frame straight onto fd 1 (the response pipe), then answer
    # normally. Without correlation the parent would consume this pre-staged frame as the NEXT
    # dispatch's answer.
    import os

    from messagefoundry.pipeline import _sandbox_codec as _codec

    frame = _codec.encode_ok(
        request_id="guess:1", phase="transform", name="h_ok", result=Send("OB_T", "FORGED")
    )
    os.write(1, len(frame).to_bytes(4, "big") + frame)
    return Send("OB_T", "REAL")


@handler("h_late_forge")
def h_late_forge(msg):
    # The forgery that a correlation check ALONE cannot stop: stage the frame LATER, after this
    # dispatch's own answer has been consumed, so it is sitting in the parent's queue when the NEXT
    # dispatch starts. A grandchild that inherited fd 1 and outlived proc.kill() can do exactly this at
    # any moment. The frame is addressed to a plausible next call (h_ok, transform) — only the id it
    # cannot know.
    import os
    import threading

    from messagefoundry.pipeline import _sandbox_codec as _codec

    def _stage():
        frame = _codec.encode_ok(
            request_id="guess:2", phase="transform", name="h_ok", result=Send("OB_T", "FORGED")
        )
        os.write(1, len(frame).to_bytes(4, "big") + frame)

    threading.Timer(1.5, _stage).start()
    return Send("OB_T", "REAL")


@handler("h_ref")
def h_ref(msg):
    # Reads a live reference snapshot the engine publishes via store.reference_view() — proving the
    # marshalled (formerly-mappingproxy) view reaches the child and is usable there.
    return Send("OB_T", reference("codes").get("A") or "MISS")


@handler("h_ok")
def h_ok(msg):
    msg.set("MSH-6", "TRANSFORMED")
    return Send("OB_T", str(msg))


@handler("h_env")
def h_env(msg):
    return Send("OB_T", current_environment() or "NONE")


@handler("h_socket")
def h_socket(msg):
    import socket  # forbidden inside the sandbox (ADR 0087)

    return Send("OB_T", str(msg))


@handler("h_busy")
def h_busy(msg):
    while True:  # pathological runaway — the wall cap must contain it
        pass


@handler("h_lookup")
def h_lookup(msg):
    db_lookup("SOME_DB", "select 1", ())  # live bridge — forbidden in the sandbox
    return Send("OB_T", str(msg))
"""


def _sentinel_path(config_dir: str | Path) -> Path:
    """Where the ``__reduce__`` gadget would land if anything deserialized it."""
    return Path(config_dir) / "PWNED_IN_THE_PARENT"


@pytest.fixture
def graph(tmp_path: Path) -> tuple[Registry, str]:
    source = _GRAPH.replace("__SENTINEL__", repr(str(_sentinel_path(tmp_path))))
    (tmp_path / "graph.py").write_text(source, encoding="utf-8")
    registry = load_config(tmp_path)
    return registry, str(tmp_path)


def _deliveries(registry: Registry, hname: str, **kw: object) -> list[tuple[str, str]]:
    ds, _, _, _ = transform_one(registry, hname, RAW, **kw)  # type: ignore[arg-type]
    return [(d.to, d.payload) for d in ds]


# --- (a) mode=off / benign subprocess byte-identical parity ------------------


def test_mode_off_session_is_byte_identical_and_never_spawns(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    ic = registry.inbound["IB_T"]
    off = SandboxSession(SandboxPolicy(mode=SandboxMode.OFF), config_dir=config_dir, env=None)
    # Router + Handler go through the OFF branch (in-process) — identical to sandbox=None.
    assert route_only(registry, ic, RAW, sandbox=off, run_context=RunContext()) == route_only(
        registry, ic, RAW
    )
    assert _deliveries(registry, "h_ok", sandbox=off, run_context=RunContext()) == _deliveries(
        registry, "h_ok"
    )
    # OFF never launches a child process (zero overhead).
    assert off._proc is None
    off.close()


def test_subprocess_parity_router_and_handler(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    ic = registry.inbound["IB_T"]
    names_ip = route_only(registry, ic, RAW)
    deliver_ip = _deliveries(registry, "h_ok")

    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        config_dir=config_dir,
        env=None,
    )
    try:
        names_sb = route_only(registry, ic, RAW, sandbox=session, run_context=RunContext())
        deliver_sb = _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext())
    finally:
        session.close()
    assert names_sb == names_ip == ["h_ok"]
    assert deliver_sb == deliver_ip  # byte-identical, incl. the in-child msg.set mutation


# --- (b) isolation-positive: a forbidden op is contained ----------------------


def test_forbidden_import_is_denied_and_worker_survives(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        config_dir=config_dir,
        env=None,
    )
    try:
        with pytest.raises(SandboxError, match="socket"):
            _deliveries(registry, "h_socket", sandbox=session, run_context=RunContext())
        # A denial is not a crash: the persistent worker is reused for the next (good) message,
        # producing the same output the in-process path would.
        assert _deliveries(
            registry, "h_ok", sandbox=session, run_context=RunContext()
        ) == _deliveries(registry, "h_ok")
    finally:
        session.close()


# --- (c) resource cap: a runaway is capped, intake is not wedged --------------


def test_busy_loop_is_wall_capped_and_recovers(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=1.0),
        config_dir=config_dir,
        env=None,
    )
    try:
        started = time.monotonic()
        with pytest.raises(SandboxError, match="wall cap"):
            _deliveries(registry, "h_busy", sandbox=session, run_context=RunContext())
        elapsed = time.monotonic() - started
        # Capped near the wall bound (not hung indefinitely) — the parent killed the runaway child.
        assert elapsed < 10.0
        # A fresh child respawns transparently for the next message (intake was never wedged).
        assert (
            _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext())[0][0] == "OB_T"
        )
    finally:
        session.close()


# --- (d) db_lookup / fhir_lookup are forbidden in the sandbox, fail-closed -----


def test_db_lookup_in_sandbox_fails_closed(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        config_dir=config_dir,
        env=None,
    )
    try:
        with pytest.raises(SandboxError, match="db_lookup/fhir_lookup is forbidden"):
            _deliveries(registry, "h_lookup", sandbox=session, run_context=RunContext())
    finally:
        session.close()


# --- RunContext is marshalled across the process boundary ---------------------


def test_run_context_reaches_the_worker(graph: tuple[Registry, str]) -> None:
    registry, config_dir = graph
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        config_dir=config_dir,
        env=None,
    )
    try:
        deliver = _deliveries(
            registry,
            "h_env",
            sandbox=session,
            run_context=RunContext(active_environment="prod"),
        )
    finally:
        session.close()
    # The handler read current_environment() — proving the marshalled RunContext activated in the child.
    assert deliver == [("OB_T", "prod")]


# --- the ENGINE's real RunContext (store-backed MappingProxyType views) marshals ----------------


async def test_subprocess_marshals_live_store_run_context(
    graph: tuple[Registry, str], tmp_path: Path
) -> None:
    """Regression for the DOA bug: the engine ALWAYS builds RunContext with
    ``reference_view``/``state_view`` = ``store.reference_view()``/``state_view()``, which return
    ``types.MappingProxyType`` — a mappingproxy is not picklable, so before the snapshot fix every
    subprocess dispatch raised ``SandboxError`` at marshal time and dead-lettered the message. This
    drives ``route_only``/``transform_one`` with the store's real live views + ``mode=subprocess`` and
    asserts the message routes and delivers (never a marshal-failure ``SandboxError``)."""
    registry, config_dir = graph
    ic = registry.inbound["IB_T"]
    store = await MessageStore.open(tmp_path / "sb.db")
    await store.write_reference_snapshot(name="codes", version="v1", rows={"A": "1"})
    try:
        # Built EXACTLY as RegistryRunner does — the views are live MappingProxyType windows.
        router_rc = RunContext(
            code_sets=registry.code_sets,
            reference_view=store.reference_view(),
            active_environment=None,
        )
        transform_rc = RunContext(
            code_sets=registry.code_sets,
            reference_view=store.reference_view(),
            state_view=store.state_view(),
            active_environment=None,
        )
        assert isinstance(
            router_rc.reference_view, MappingProxyType
        )  # the unpicklable engine shape
        assert isinstance(transform_rc.state_view, MappingProxyType)
        session = SandboxSession(
            SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
            config_dir=config_dir,
            env=None,
        )
        try:
            names = route_only(registry, ic, RAW, sandbox=session, run_context=router_rc)
            deliver = _deliveries(registry, "h_ref", sandbox=session, run_context=transform_rc)
        finally:
            session.close()
    finally:
        await store.close()
    assert names == ["h_ok"]  # the router routed — it did NOT dead-letter on a marshal failure
    assert deliver == [("OB_T", "1")]  # the snapshotted reference view reached and served the child


def _rc_round_trip(rc: RunContext) -> RunContext:
    """Marshal a RunContext through the real codec (the shape the parent puts on the wire)."""
    blobs = _Blobs()
    node = enc_run_context(rc, blobs)
    return dec_run_context(node, _Reader(blobs.items))


def test_run_context_codec_snapshots_mappingproxy_views() -> None:
    """Unit-level guard on the run-context marshalling: the store's live ``MappingProxyType`` views
    (both levels of the reference view) are snapshotted to plain dicts by construction, the
    ``state_view``'s ``(namespace, key)`` TUPLE keys survive as tuples, and the scalar fields ride
    through untouched. Replaces the old pickle round-trip — nothing is pickled any more."""
    rc = RunContext(
        reference_view=MappingProxyType({"codes": MappingProxyType({"A": "1"})}),
        state_view=MappingProxyType({("ns", "k"): "v"}),
        active_environment="prod",
        snapshot_on_send=True,
    )
    round_tripped = _rc_round_trip(rc)
    assert type(round_tripped.reference_view) is dict
    assert type(round_tripped.reference_view["codes"]) is dict
    assert type(round_tripped.state_view) is dict
    assert round_tripped.reference_view == {"codes": {"A": "1"}}
    assert round_tripped.state_view == {("ns", "k"): "v"}
    assert all(isinstance(k, tuple) for k in round_tripped.state_view)
    assert round_tripped.active_environment == "prod"
    assert round_tripped.snapshot_on_send is True
    # code_sets are deliberately NOT on the wire — the child substitutes its own bootstrap load.
    assert round_tripped.code_sets is None


# --- the IPC boundary itself (MFW2 codec) -------------------------------------


def _session(config_dir: str, **kw: object) -> SandboxSession:
    return SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        config_dir=config_dir,
        env=None,
        **kw,  # type: ignore[arg-type]
    )


def test_a_handler_returning_a_reduce_gadget_does_not_execute_in_the_engine(
    graph: tuple[Registry, str],
) -> None:
    """The confirmed defect, end to end through a real spawned worker.

    ``h_gadget`` returns an object whose ``__reduce__`` creates a directory. Under the old pickle pipe
    the ENGINE PARENT ran it while unpickling the response frame — a full address-space-boundary
    bypass by admin-authored Handler code, which is the exact thing the sandbox exists to prevent.
    Under MFW2 the gadget is an item ``_partition`` would ignore: it is described as ``{"o": "other"}``
    and rebuilt as an inert placeholder, so nothing runs and the message simply delivers nothing."""
    registry, config_dir = graph
    sentinel = _sentinel_path(config_dir)
    assert not sentinel.exists()
    session = _session(config_dir)
    try:
        deliveries, state_ops, meta_ops, declined = transform_one(
            registry, "h_gadget", RAW, sandbox=session, run_context=RunContext()
        )
        # Parity with mode=off, which drops an unrecognised return value the same way.
        assert (deliveries, state_ops, meta_ops, declined) == ([], [], [], [])
        assert transform_one(registry, "h_gadget", RAW) == (
            deliveries,
            state_ops,
            meta_ops,
            declined,
        )
        # And the worker survived — a described-but-ignored result is not a fault.
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext())
    finally:
        session.close()
    assert not sentinel.exists(), "a Handler's __reduce__ executed in the engine parent"


def test_a_generator_handler_delivers_under_mode_subprocess(graph: tuple[Registry, str]) -> None:
    """BACKLOG #341 across the process boundary. Before the shared materialization rule the child
    described a generator/tuple/set return as ``{"o": "other"}`` and the parent rebuilt an inert
    ``Ignored()``, so a fan-out that delivers N in-process delivered 0 under ``mode=subprocess``.
    Fixing only the parent's ``_partition`` would leave exactly that mode-dependent disposition."""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        sandboxed = _deliveries(registry, "h_gen_fanout", sandbox=session, run_context=RunContext())
    finally:
        session.close()
    assert sandboxed == [("OB_T", "GEN_A"), ("OB_T", "GEN_B")]
    assert sandboxed == _deliveries(registry, "h_gen_fanout")  # identical to mode=off


def test_a_set_handler_delivers_the_same_multiset_under_mode_subprocess(
    graph: tuple[Registry, str],
) -> None:
    """A ``set`` return crosses the boundary with every ``Send`` intact — and with its ORDER unpinned,
    deliberately (ADR 0087 AC-11).

    The child is a separate ``Popen`` with **no** inherited ``PYTHONHASHSEED``, and ``Send`` is a frozen
    dataclass hashed on its fields, so the child iterates a 6-element set in a different order than the
    parent would. Asserting an order here would pin a per-process accident and flake; asserting the
    multiset is the contract the engine actually offers. That the two modes do NOT necessarily agree on
    order is why `docs/CONNECTIONS.md` steers authors to a list/tuple when order matters.

    The counts are pinned at 6 so the comparison cannot pass by both sides being empty — which is the
    exact way this test would have "passed" before the fix, when a set delivered nothing in either mode.
    """
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        sandboxed = _deliveries(registry, "h_set_fanout", sandbox=session, run_context=RunContext())
    finally:
        session.close()
    off = _deliveries(registry, "h_set_fanout")
    assert len(sandboxed) == len(off) == 6
    assert sorted(sandboxed) == sorted(off)
    assert sorted(p for _, p in sandboxed) == [f"SET_{c}" for c in "ABCDEF"]


def test_generator_router_routes_under_mode_subprocess(graph: tuple[Registry, str]) -> None:
    """A generator Router is documented-supported and unpicklable, so ``mode=subprocess`` used to
    dead-letter every message it routed. The child now materialises the router result with
    ``_handler_names``' own logic, so it routes identically to ``mode=off``. This is a behaviour change
    in the DELIVERING direction, hence an explicit test rather than a side effect."""
    registry, config_dir = graph
    ic = registry.inbound["IB_GEN"]
    assert route_only(registry, ic, RAW) == ["h_ok"]
    session = _session(config_dir)
    try:
        assert route_only(registry, ic, RAW, sandbox=session, run_context=RunContext()) == ["h_ok"]
    finally:
        session.close()


def test_a_mutating_router_is_the_one_documented_mode_divergence(
    graph: tuple[Registry, str],
) -> None:
    """AC-15 — pins the single place ``[sandbox].mode`` is NOT transparent, so it cannot drift silently.

    Every dispatch marshals the payload, so the child rebuilds its own object; in-process the Router
    and every ``accepts=`` predicate share ONE object. A Router that *mutates* its payload — which
    CLAUDE.md §2 forbids — is therefore visible to the predicate under ``mode=off`` and invisible under
    ``mode=subprocess``, and the two modes route differently. This predates the codec (the original
    pickle pipe copied the payload per dispatch the same way); closing it would mean returning the
    payload from every router/predicate dispatch, roughly doubling the routing stage's wire cost to
    reproduce a documented authoring hazard. Asserted as an inequality **on purpose**: if a future
    change makes the modes agree here, this test fails and the ADR residual gets deleted deliberately
    rather than going stale."""
    registry, config_dir = graph
    ic = registry.inbound["IB_MUT"]
    assert route_only(registry, ic, RAW) == ["h_sees_mutation"]
    session = _session(config_dir)
    try:
        assert route_only(registry, ic, RAW, sandbox=session, run_context=RunContext()) == []
    finally:
        session.close()


def test_a_desynced_or_forged_response_is_rejected(graph: tuple[Registry, str]) -> None:
    """``h_forge`` writes an extra well-formed response frame onto the inherited fd 1 before answering.

    Without correlation the parent would take that pre-staged frame as the answer to the NEXT dispatch
    — for ``phase="accepts"`` that is a routing-verdict flip on a message the attacker never saw, the
    one failure with no ERROR and no disposition anomaly. A per-dispatch ``secrets`` id makes the
    forgery unguessable and the mismatch fatal to that worker. (The phase and name halves of the same
    check are pinned at frame level by
    ``test_sandbox_codec.py::test_hostile_frames_fail_closed[phase_mismatch|name_mismatch]``.)"""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        with pytest.raises(SandboxError, match="invalid frame"):
            _deliveries(registry, "h_forge", sandbox=session, run_context=RunContext())
        # The desynchronized worker was killed; the next message gets a clean child and the right answer.
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == (
            _deliveries(registry, "h_ok")
        )
    finally:
        session.close()


def test_a_frame_staged_between_dispatches_can_never_answer_the_next_one(
    graph: tuple[Registry, str],
) -> None:
    """The confirmed contract break: correlation ALONE does not stop a pre-staged answer.

    ``h_late_forge`` answers normally, then writes a second, perfectly well-formed ``ok`` frame a
    moment LATER — so it is queued when the next, unrelated dispatch begins. A derivable request id
    (a per-spawn nonce plus a counter) made that frame the next call's answer: a benign Handler's
    delivery silently replaced by attacker-chosen content on a message it never saw, with no ERROR and
    no disposition anomaly. Two things close it, and this test proves both: the id is now a fresh
    ``secrets`` token the worker only learns from the request itself, and a frame queued before a
    dispatch is fatal to the worker rather than consumed."""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        # The forging dispatch itself succeeds — its own answer was honest.
        assert _deliveries(registry, "h_late_forge", sandbox=session, run_context=RunContext()) == [
            ("OB_T", "REAL")
        ]
        time.sleep(2.5)  # let the staged frame land in the parent's queue
        # The next dispatch refuses to run against a pipe that already has a frame on it.
        with pytest.raises(SandboxError, match="unsolicited"):
            _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext())
        # ...and the victim message is never delivered attacker-chosen content: a clean child answers.
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == (
            _deliveries(registry, "h_ok")
        )
    finally:
        session.close()


def test_a_dead_peer_is_not_treated_as_a_forged_frame(graph: tuple[Registry, str]) -> None:
    """The unsolicited-frame guard must fail closed on a FRAME and stay open on a corpse.

    A frame is the exploit: only a writer on fd 1 can produce one, so it is fatal. ``_EOF`` is a
    parent-private singleton with **no wire form**, so a worker cannot manufacture one — it proves
    only that the peer is gone. Conflating the two fails closed against a signal carrying no trust
    information: a child that crashes in the instant *after* writing a correct, correlation-proven
    answer would lose a message it had already answered."""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        expected = _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext())
        proc = session._proc
        assert proc is not None

        # A dead peer: the worker is dropped (it is gone), but the answer in hand still stands.
        session._responses.put(_EOF)
        session._reject_unsolicited(proc, "after")  # must NOT raise
        assert session._proc is None

        # A frame in the very same slot is still fatal, and still named as unsolicited.
        # Rebind the queue first, for the same reason `_spawn` does: the kill above makes the dead
        # worker's reader thread hit EOF on a closed stdout and push a `_EOF` of its OWN. On a
        # fast-teardown platform that lands BEFORE the frame planted here, so `_reject_unsolicited`
        # — which drains exactly one item — would consume the benign corpse signal and correctly not
        # raise, failing this assertion for a reason that has nothing to do with the frame. Windows
        # tears down slowly enough to hide it; Linux does not. Dropping the dead generation's sink
        # makes the planted frame provably the first item.
        session._responses = queue.Queue()
        session._responses.put(b"\x00\x00\x00\x02{}")
        with pytest.raises(SandboxError, match="unsolicited"):
            session._reject_unsolicited(session._proc, "after")

        # Either way the next message is served by a clean child, identically to mode=off.
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == expected
    finally:
        session.close()


def test_request_ids_are_unpredictable_and_never_reused(
    graph: tuple[Registry, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The id has to be unguessable to code that has already seen an earlier one — a per-spawn nonce
    plus a counter let the Handler running dispatch N compute N+1's and pre-stage its answer."""
    registry, config_dir = graph
    seen: list[str] = []
    real_encode = codec.encode_request

    def _spy(*, request_id: str, **kw: Any) -> bytes:
        seen.append(request_id)
        return real_encode(request_id=request_id, **kw)

    monkeypatch.setattr(codec, "encode_request", _spy)
    session = _session(config_dir)
    try:
        for _ in range(3):
            _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext())
    finally:
        session.close()
    assert len(set(seen)) == 3
    assert all(len(rid) == 32 for rid in seen)  # secrets.token_hex(16), not a counter
    # No id is derivable from another: no shared prefix, no ordering relationship.
    assert len({rid[:8] for rid in seen}) == 3


def test_response_view_reaches_a_sandboxed_handler(graph: tuple[Registry, str]) -> None:
    """New capability, not a regression guard: ``response_view`` carries ``CapturedResponse`` objects,
    which used to live in ``messagefoundry.store`` — a FORBIDDEN import inside the child, raised from
    inside its frame read (outside any ``try``). So ``[sandbox].mode=subprocess`` plus a LOOPBACK
    inbound with a correlated reply was 100% non-functional. The record now lives in the store-free
    config layer, so the child rebuilds the identical class."""
    registry, config_dir = graph
    reply = CapturedResponse(
        message_id="m1",
        destination_name="OB_T",
        response_seq=1,
        outcome="ok",
        detail=None,
        captured_at=1.0,
        body="MSA|AA|MSG00001",
        headers={"x-trace": "abc"},
    )
    rc = RunContext(response_view={"OB_T": reply})
    session = _session(config_dir)
    try:
        deliver = _deliveries(registry, "h_reply", sandbox=session, run_context=rc)
    finally:
        session.close()
    assert deliver == [("OB_T", "MSA|AA|MSG00001")]
    # Identical to mode=off. In-process the CALLER activates the run-scoped providers (the sandbox
    # child re-establishes them on the far side of the pipe), so bracket the comparison run the same way.
    with run_contexts(rc, phase="transform"):
        assert deliver == _deliveries(registry, "h_reply", run_context=rc)


def test_setstate_tuple_and_nonfinite_values_survive_mode_subprocess(
    graph: tuple[Registry, str],
) -> None:
    """Two parity gaps a plain-JSON codec would have shipped as silent narrowings: a tuple value
    flattened to a list, and ``float('nan')`` (which ``SetState`` accepts today, because its validator
    calls ``json.dumps`` with the default ``allow_nan=True``) turned into a fresh dead-letter."""
    registry, config_dir = graph
    session = _session(config_dir)
    try:
        _, ops, _, _ = transform_one(
            registry, "h_state", RAW, sandbox=session, run_context=RunContext()
        )
    finally:
        session.close()
    by_key = {op.key: op.value for op in ops}
    assert by_key["tup"] == (1, 2) and isinstance(by_key["tup"], tuple)
    assert math.isnan(by_key["nan"])
    _, off_ops, _, _ = transform_one(registry, "h_state", RAW)
    assert [(o.namespace, o.key) for o in ops] == [(o.namespace, o.key) for o in off_ops]


# --- the code-set hoist keeps the engine authoritative ------------------------


def test_code_sets_reach_the_child_without_travelling_per_dispatch() -> None:
    """The tables ride the one-per-spawn boot frame; the per-dispatch request frame must carry none of
    their bytes (that redundancy was ~430 KB and ~4.6 ms per message)."""
    name = "SECRET_CODE_SET_NAME"
    rc = RunContext(code_sets={name: CodeSet(name, {"A": "SECRET_CODE_SET_VALUE"})})
    frame = encode_request(
        request_id="n:1",
        phase="router",
        name="r",
        payload=None,
        origin=(RAW, "hl7v2"),
        run_context=rc,
    )
    assert b"SECRET_CODE_SET_VALUE" not in frame
    assert name.encode() not in frame


def _codeset_graph(tmp_path: Path, mapped: str) -> Registry:
    (tmp_path / "codesets").mkdir(exist_ok=True)
    (tmp_path / "codesets" / "cs.csv").write_text(f"key,value\nA,{mapped}\n", encoding="utf-8")
    (tmp_path / "graph.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, MLLP, Send, code_set\n"
        'inbound("IB_C", MLLP(port=19331), router="r")\n'
        'outbound("OB_C", MLLP(host="127.0.0.1", port=19332))\n'
        '@router("r")\n'
        "def r(msg):\n"
        '    return "h"\n'
        '@handler("h")\n'
        "def h(msg):\n"
        '    return Send("OB_C", code_set("cs")["A"])\n'
        '@handler("h_gen_cs")\n'
        "def h_gen_cs(msg):\n"
        "    # A GENERATOR whose BODY reads a run-scoped provider. The read happens when something\n"
        "    # iterates the generator, so this probes WHERE that materialization runs in the child.\n"
        '    yield Send("OB_C", code_set("cs")["A"])\n',
        encoding="utf-8",
    )
    return load_config(tmp_path)


def test_code_sets_are_loaded_by_the_child_and_resolve(tmp_path: Path) -> None:
    """The positive half of the hoist: a call-time ``code_set(...)`` inside a sandboxed Handler
    resolves against the ENGINE's tables, with none of them on the per-dispatch wire."""
    registry = _codeset_graph(tmp_path, "MAPPED")
    session = _session(str(tmp_path), code_sets=registry.code_sets)
    try:
        ds, _, _, _ = transform_one(
            registry,
            "h",
            RAW,
            sandbox=session,
            run_context=RunContext(code_sets=registry.code_sets),
        )
    finally:
        session.close()
    assert [(d.to, d.payload) for d in ds] == [("OB_C", "MAPPED")]


def test_a_generator_handlers_body_runs_inside_the_childs_run_context(tmp_path: Path) -> None:
    """A generator Handler's body executes LAZILY — at the instant something materialises it. In the
    child that instant must fall INSIDE ``with run_contexts(...)``.

    The codec's ``enc_result`` is called from ``_respond``, *outside* that block, so materialising
    there would run the Handler body with no active run context: a ``code_set(...)`` inside a
    generator Handler would raise ``CodeSetError`` under ``mode=subprocess`` while working fine under
    ``mode=off``. That is a mode-dependent disposition — the exact class of failure ADR 0087's parity
    rule forbids, and the reason the worker materialises the result itself."""
    registry = _codeset_graph(tmp_path, "MAPPED")
    session = _session(str(tmp_path), code_sets=registry.code_sets)
    rc = RunContext(code_sets=registry.code_sets)
    try:
        ds, _, _, _ = transform_one(registry, "h_gen_cs", RAW, sandbox=session, run_context=rc)
    finally:
        session.close()
    assert [(d.to, d.payload) for d in ds] == [("OB_C", "MAPPED")]
    # And byte-identical to mode=off, which activates the same providers around the same call.
    with run_contexts(rc, phase="transform"):
        off, _, _, _ = transform_one(registry, "h_gen_cs", RAW, run_context=rc)
    assert [(d.to, d.payload) for d in ds] == [(d.to, d.payload) for d in off]


def test_an_unreloaded_codeset_edit_does_not_brick_the_inbound(tmp_path: Path) -> None:
    """Regression for the fail-closed cure that was worse than the disease.

    Hoisting the tables to the child's OWN bootstrap load is fail-OPEN (an operator who edits
    ``codesets/`` without a ``POST /config/reload`` would get a value the engine never published), and
    pinning a digest to detect that turned it into a hard, permanent outage: every message on the
    inbound dead-lettered forever after the next ROUTINE respawn (a wall-cap kill, a worker crash),
    burning a full config load per attempt. Sending the engine's tables in the boot frame removes both
    — the child cannot diverge because it is not the source. The sequence below is the real one:
    dispatch, edit the file on disk with no reload, force a respawn, dispatch again."""
    registry = _codeset_graph(tmp_path, "ENGINE_VALUE")
    session = _session(str(tmp_path), code_sets=registry.code_sets)
    rc = RunContext(code_sets=registry.code_sets)
    try:
        first, _, _, _ = transform_one(registry, "h", RAW, sandbox=session, run_context=rc)
        assert [(d.to, d.payload) for d in first] == [("OB_C", "ENGINE_VALUE")]

        # An operator edits the crosswalk and does NOT reload; then anything routine drops the worker.
        (tmp_path / "codesets" / "cs.csv").write_text(
            "key,value\nA,EDITED_ON_DISK\n", encoding="utf-8"
        )
        session._kill(session._proc)  # exactly what a wall-cap kill or a crash does

        second, _, _, _ = transform_one(registry, "h", RAW, sandbox=session, run_context=rc)
    finally:
        session.close()
    # Still the engine's value, still delivering — byte-identical to mode=off, which reads the live
    # registry the same way.
    assert [(d.to, d.payload) for d in second] == [("OB_C", "ENGINE_VALUE")]
    # In-process the CALLER activates the run-scoped providers (the sandbox child re-establishes them
    # on the far side of the pipe), so bracket the comparison run the same way.
    with run_contexts(rc, phase="transform"):
        off, _, _, _ = transform_one(registry, "h", RAW, run_context=rc)
    assert [(d.to, d.payload) for d in second] == [(d.to, d.payload) for d in off]


def test_the_engines_code_sets_win_over_the_childs_own_load(graph: tuple[Registry, str]) -> None:
    """The same rule stated the other way: what the parent publishes is what the child serves, even
    when the child's own ``load_config`` found different tables (here: none at all)."""
    registry, config_dir = graph
    assert registry.code_sets == {}  # this graph ships none
    session = _session(config_dir, code_sets={"cs": CodeSet("cs", {"A": "1"})})
    try:
        # The bootstrap succeeds (no skew to detect) and the worker serves normally.
        assert _deliveries(registry, "h_ok", sandbox=session, run_context=RunContext()) == (
            _deliveries(registry, "h_ok")
        )
    finally:
        session.close()


# --- (BACKLOG #342) killing the worker reaps its whole process tree ----------

# A graph whose Handler spawns a GRANDCHILD that inherits fd 1 (the response pipe). `close_fds=False`
# plus un-redirected stdout makes the grandchild inherit the worker's fd 1 on BOTH platforms; it then
# sleeps well past the test, so absent a tree-reap it lingers as an orphan STILL HOLDING the pipe (the
# #342 defect). `subprocess`/`sys` are not in DEFAULT_FORBIDDEN_MODULES, so the Handler may import them.
_ORPHAN_GRAPH = """
from messagefoundry import inbound, outbound, router, handler, MLLP, Send

inbound("IB_O", MLLP(port=19351), router="r")
outbound("OB_O", MLLP(host="127.0.0.1", port=19352))


@router("r")
def r(msg):
    return "h_orphan"


@handler("h_orphan")
def h_orphan(msg):
    import subprocess
    import sys

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        close_fds=False,  # inherit the worker's open fds, fd 1 (the response pipe) among them
    )
    with open(__PIDFILE__, "w", encoding="utf-8") as fh:
        fh.write(str(child.pid))
    return Send("OB_O", "SPAWNED")
"""


def _orphan_graph(tmp_path: Path) -> tuple[Registry, str, Path]:
    """Write the orphan-spawning graph and return ``(registry, config_dir, pidfile)`` — mirrors the
    ``_codeset_graph`` pattern. ``pidfile`` is where the Handler records the grandchild's pid."""
    pidfile = tmp_path / "grandchild.pid"
    source = _ORPHAN_GRAPH.replace("__PIDFILE__", repr(str(pidfile)))
    (tmp_path / "graph.py").write_text(source, encoding="utf-8")
    return load_config(tmp_path), str(tmp_path), pidfile


def _pid_alive(pid: int) -> bool:
    """Whether ``pid`` names a live process — cross-platform, no third-party deps."""
    if sys.platform == "win32":
        import ctypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False  # no such pid (or already fully reaped)
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by someone else — still "alive"
    return True


def _best_effort_kill_pid(pid: int) -> None:
    """Kill ``pid`` if it is still around, swallowing every failure. Keeps a FALSIFY run (where the
    reap is disabled and the grandchild survives) from leaking a 30s sleeper."""
    try:
        if sys.platform == "win32":
            import ctypes

            process_terminate = 0x0001
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.OpenProcess(process_terminate, False, pid)
            if handle:
                try:
                    kernel32.TerminateProcess(handle, 1)
                finally:
                    kernel32.CloseHandle(handle)
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def test_worker_kill_reaps_the_whole_process_tree(tmp_path: Path) -> None:
    """Killing the worker must reap the WHOLE tree, not just the immediate child (BACKLOG #342).

    A Handler spawns a grandchild that inherits fd 1 (the response pipe). Before the fix a bare
    ``proc.kill()`` terminated only the worker, leaving the grandchild alive — an orphan still holding
    the pipe, so the pipe never reached EOF and the kill was incomplete. The fix reaps the tree: a
    Windows ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` job object (exercised locally, this host is
    Windows) or a POSIX new-session process group killed with ``killpg`` (exercised by the CI
    ubuntu-latest leg).

    The observable is platform-neutral: for THIS grandchild — which holds fd 1 until it exits —
    pipe-EOF is equivalent to "grandchild reaped", so the primary assert covers BOTH halves of the
    defect (pipe released AND no lingering process). ``_pid_alive`` re-checks the process half
    directly. See the FALSIFICATION recorded in the lane report: forcing
    ``_assign_kill_on_close_job`` to return ``None`` degrades the Windows path to a bare
    ``proc.kill()``, the grandchild survives, the pipe never EOFs, and this test goes red."""
    registry, config_dir, pidfile = _orphan_graph(tmp_path)
    session = _session(config_dir)
    grandchild_pid: int | None = None
    try:
        # Drive the Handler so the worker spawns the fd-1-holding grandchild.
        assert _deliveries(registry, "h_orphan", sandbox=session, run_context=RunContext()) == [
            ("OB_O", "SPAWNED")
        ]
        grandchild_pid = int(pidfile.read_text())
        proc = session._proc
        assert proc is not None
        responses = session._responses  # capture THIS generation's queue before the kill

        # The single funnel for a wall-cap kill / crash cleanup / shutdown.
        session._kill(proc)

        # PRIMARY: the response pipe reaches EOF only once EVERY holder of fd 1 is gone — the worker
        # AND the grandchild. The reader thread enqueues `_EOF` at that point.
        try:
            frame = responses.get(timeout=8.0)
        except queue.Empty:
            frame = None
        assert frame is _EOF, (
            "response pipe never reached EOF -- a grandchild still holds it; the worker tree "
            "was not reaped"
        )
        # SECONDARY: the process half, asserted directly -- POLLED, not sampled once.
        #
        # THE ONE-SHOT FORM WAS A RACE AGAINST AN EVENTUALLY-CONSISTENT CONDITION, and the window
        # exists on BOTH platforms by DIFFERENT mechanisms -- which matters, because the observed
        # CI failures were on ubuntu and the first version of this comment explained only Windows.
        #
        # The primary above accepts pipe EOF, which arrives the instant the last holder of fd 1
        # releases it -- i.e. DURING the grandchild's teardown. Then:
        #
        #   POSIX (where the failures actually happened): `_pid_alive` is `os.kill(pid, 0)` at
        #   :925-931, False ONLY on ProcessLookupError. SIGKILL closes the fds at once, so the pipe
        #   EOFs and the primary passes -- but the pid lingers as a ZOMBIE until it is re-parented
        #   and reaped, and a zombie is still visible to `os.kill(pid, 0)`. Reaping waits on the
        #   subreaper being SCHEDULED, which is exactly what degrades on a loaded runner.
        #
        #   Windows: `_pid_alive` answers through `GetExitCodeProcess`, which keeps reporting
        #   STILL_ACTIVE until the process object is signalled.
        #
        # Either way there is a real window in which the pipe has EOF'd and the pid still reads
        # alive, and checking once inside it fails a test whose subject is fine.
        #
        # THE PRIMARY WAS ALREADY BOUNDED (8s) AND THIS WAS NOT -- the same assertion pair, one
        # tolerant of scheduling and one not. On a loaded 4-CPU runner the window widens and only
        # the intolerant half fires.
        #
        # POLL, DON'T SAMPLE-AND-HOPE is the house idiom, established in
        # tests/test_connscale_cpu_probe.py for exactly this class: that test's comment records it
        # "used to be `time.sleep(1.0)` then ONE `sample_proc()`" before the same defect was found.
        # The deadline is generous because a false RED here costs a queue and a false GREEN costs
        # nothing this test is for -- a surviving grandchild never exits, so no wait rescues it.
        reap_deadline = time.monotonic() + 10.0
        while _pid_alive(grandchild_pid) and time.monotonic() < reap_deadline:
            time.sleep(0.05)
        assert not _pid_alive(grandchild_pid), (
            "the grandchild survived the worker kill (polled to a 10s deadline, so this is a "
            "SURVIVING process rather than one still being reaped)"
        )
    finally:
        if grandchild_pid is not None:
            _best_effort_kill_pid(grandchild_pid)
        session.close()
