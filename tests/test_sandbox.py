# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Subprocess isolation for Routers/Handlers (ADR 0087, BACKLOG #197).

Proves the crux parity property (``mode=off`` — and a benign ``subprocess`` round-trip — are
byte-identical to a direct in-process call) plus the isolation guarantees: a forbidden op is denied,
a runaway is capped without wedging intake, a sandboxed ``db_lookup``/``fhir_lookup`` fails closed,
and the marshalled :class:`RunContext` reaches the worker. Synthetic HL7 only."""

from __future__ import annotations

import time
from pathlib import Path
from types import MappingProxyType

import pytest

from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    _picklable_run_context,
)
from messagefoundry.store.store import MessageStore

# A minimal, conformant synthetic ADT^A01 (no PHI — fabricated ids/names).
RAW = "MSH|^~\\&|SEND|F|RECV|F|20240101120000||ADT^A01|MSG00001|P|2.3\rPID|1||900001||DOE^JANE\r"

_GRAPH = """
from messagefoundry import (
    inbound, outbound, router, handler, MLLP, Send,
    db_lookup, current_environment, reference,
)

inbound("IB_T", MLLP(port=19311), router="r")
outbound("OB_T", MLLP(host="127.0.0.1", port=19312))


@router("r")
def r(msg):
    return "h_ok"


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


@pytest.fixture
def graph(tmp_path: Path) -> tuple[Registry, str]:
    (tmp_path / "graph.py").write_text(_GRAPH, encoding="utf-8")
    registry = load_config(tmp_path)
    return registry, str(tmp_path)


def _deliveries(registry: Registry, hname: str, **kw: object) -> list[tuple[str, str]]:
    ds, _, _ = transform_one(registry, hname, RAW, **kw)  # type: ignore[arg-type]
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


def test_picklable_run_context_snapshots_mappingproxy_views() -> None:
    """Unit-level guard on the snapshot helper: it converts the store's unpicklable
    ``MappingProxyType`` views (both levels of the reference view) to plain, picklable dicts while
    preserving content, and leaves the scalar fields untouched."""
    import pickle

    rc = RunContext(
        reference_view=MappingProxyType({"codes": MappingProxyType({"A": "1"})}),
        state_view=MappingProxyType({("ns", "k"): "v"}),
        active_environment="prod",
    )
    with pytest.raises(TypeError):
        pickle.dumps(rc)  # the live engine shape is DOA across the pipe

    safe = _picklable_run_context(rc)
    round_tripped = pickle.loads(pickle.dumps(safe))  # now marshals
    assert type(safe.reference_view) is dict and type(safe.reference_view["codes"]) is dict
    assert type(safe.state_view) is dict
    assert round_tripped.reference_view == {"codes": {"A": "1"}}
    assert round_tripped.state_view == {("ns", "k"): "v"}
    assert round_tripped.active_environment == "prod"
