# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``accepts=`` Router-stage seam (ADR 0084, BACKLOG #213).

A Handler may declare a **pure** ``accepts=`` predicate evaluated in the ROUTER stage, before any
routed row is materialized: a declining handler then costs **0** transactions instead of the 2 an
in-handler ``return []`` pays (ADR 0051: ``txn/msg = 3 + 2H + 2N`` with ``H`` = handlers the ROUTER
SELECTS, so the seam turns ``H`` into ``H_accepted``).

Gates asserted here:
  * **AC-7** — no predicate anywhere ⇒ byte-identical to today (same names, same routed rows).
  * **AC-1** — a decline happens BEFORE the routed row exists (the store never sees the handler).
  * **AC-4** — a predicate that RAISES is a router-stage CONTENT error (dead-letter/``ERROR``), never
    a silent decline — asserted on BOTH the async path and the fused twin (ADR 0071).
  * **AC-3** — ``db_lookup``/``fhir_lookup`` inside a predicate raises (router-stage purity).
  * ADR 0087 — a predicate runs INSIDE the sandbox child, not engine-side.
  * ADR 0057 — post-decline the surviving count is what gates the inline fast-path.

Synthetic HL7 only (fabricated ids/names — no PHI).
"""

from __future__ import annotations

import asyncio
import functools
import re
import threading
from collections.abc import AsyncIterator, Generator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.db_lookup import DbLookupError, db_lookup
from messagefoundry.config.fhir_lookup import FhirLookupError, fhir_lookup
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.response import response_get
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.state import state_get
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    accepts_verdict,
    load_config,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import route_message, route_only
from messagefoundry.pipeline.dryrun_trace import trace_dry_run
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
)
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxItem, OutboxStatus, Stage

# A conformant synthetic ADT^A01 (fabricated MRN/name).
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||900001||DOE^JANE\r"
ORU = "MSH|^~\\&|S|F|R|RF|20260101||ORU^R01|MSG2|P|2.5.1\rPID|1||900002||ROE^RICHARD\r"
# MSH-3 = ESC — the sandbox graph's router routes this one to the escaping predicate.
ESC = "MSH|^~\\&|ESC|F|R|RF|20260101||ADT^A01|MSG3|P|2.5.1\rPID|1||900003||POE^PAT\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "accepts.db")
    yield s
    await s.close()


def _is_adt(msg: Any) -> bool:
    """A pure peek — the sanctioned shape of an `accepts=` predicate."""
    return bool(msg["MSH-9.1"] == "ADT")


def _reg(
    tmp_path: Path,
    *,
    handlers: dict[str, Any] | None = None,
    accepts: dict[str, Any] | None = None,
    router: Any = None,
    inline: bool = False,
) -> Registry:
    """One FILE inbound ``IB`` → router ``r`` → the given handlers → one FILE outbound ``OB``.

    FILE (not MLLP) so nothing binds a port — these tests drive the worker bodies directly."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            inline=inline,
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path / "out"), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    hs = handlers or {"h": lambda m: Send("OB", str(m))}
    reg.add_router("r", router or (lambda m: sorted(hs)))
    acc = accepts or {}
    for hname, fn in hs.items():
        reg.add_handler(hname, fn, acc.get(hname))
    reg.validate()
    return reg


def _hub(tmp_path: Path, *, selected: int = 20, accepting: int = 4) -> Registry:
    """The reference ADT hub of ADR 0084 §1: the Router SELECTS ``selected`` handlers, only
    ``accepting`` of them declare a predicate that says yes — the rest decline at routing time."""
    handlers: dict[str, Any] = {}
    accepts: dict[str, Any] = {}
    for i in range(selected):
        handlers[f"h{i:02d}"] = lambda m: Send("OB", str(m))
        # h00..h03 accept; the rest decline. Bound at definition (not captured by reference) so each
        # predicate is a distinct pure function.
        accepts[f"h{i:02d}"] = (lambda verdict: lambda m: verdict)(i < accepting)
    return _reg(tmp_path, handlers=handlers, accepts=accepts)


async def _claimed(store: MessageStore, raw: str = ADT) -> OutboxItem:
    """Persist one message at the ingress stage (RECEIVED, pre-ACK) and claim its row — exactly the
    state the router worker's per-item body expects."""
    await store.enqueue_ingress(channel_id="IB", raw=raw, control_id="MSG1", message_type="ADT^A01")
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    return item


async def _routed_rows(store: MessageStore, message_id: str) -> list[str]:
    cur = await store._db.execute(
        "SELECT handler_name FROM queue WHERE message_id=? AND stage=? ORDER BY rowid",
        (message_id, Stage.ROUTED.value),
    )
    return [r["handler_name"] for r in await cur.fetchall()]


# --- AC-7: no predicate ⇒ byte-identical ------------------------------------


def test_no_accepts_is_byte_identical(tmp_path: Path) -> None:
    reg = _reg(tmp_path, handlers={"a": lambda m: Send("OB", str(m)), "b": lambda m: None})
    assert reg.handler_accepts == {}  # the sparse table stays empty — nothing declared one
    ic = reg.inbound["IB"]
    # route_only early-outs on the empty table: the Router's selection passes through untouched.
    assert route_only(reg, ic, ADT) == ["a", "b"]
    assert route_message(reg, ic, ADT).handlers == ["a", "b"]


async def test_no_accepts_materializes_every_routed_row(
    store: MessageStore, tmp_path: Path
) -> None:
    reg = _reg(tmp_path, handlers={"a": lambda m: Send("OB", str(m)), "b": lambda m: None})
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    item = await _claimed(store)
    await runner._process_ingress_item("IB", item)
    assert await _routed_rows(store, item.message_id) == ["a", "b"]  # both, as today
    fetched = await store.get_message(item.message_id)
    assert fetched is not None
    assert fetched["status"] == MessageStatus.ROUTED.value


# --- AC-1: the decline lands BEFORE a routed row exists ----------------------


async def test_accepts_declines_before_a_routed_row_exists(
    store: MessageStore, tmp_path: Path
) -> None:
    """The ADR 0084 forcing case: SELECT 20, accept 4. The 16 decliners must never reach the store —
    that is the whole seam (each routed row they'd have cost is 2 durable transactions)."""
    reg = _hub(tmp_path, selected=20, accepting=4)
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

    seen: list[list[str]] = []
    real = store.route_handoff

    async def _spy(**kw: Any) -> bool:
        seen.append([h for h, _ in kw["handlers"]])
        return await real(**kw)

    store.route_handoff = _spy  # type: ignore[method-assign]

    item = await _claimed(store)
    await runner._process_ingress_item("IB", item)

    # The store was ASKED to materialize exactly the 4 accepting handlers — the 16 decliners were
    # filtered inside route_only, so no routed row for them ever existed to be rolled back.
    assert seen == [["h00", "h01", "h02", "h03"]]
    assert await _routed_rows(store, item.message_id) == ["h00", "h01", "h02", "h03"]
    fetched = await store.get_message(item.message_id)
    assert fetched is not None
    assert fetched["status"] == MessageStatus.ROUTED.value
    # ADR 0051's 2H term: 4 routed rows, not 20 (txn/msg 51 -> 19 for the reference hub).
    assert len(await _routed_rows(store, item.message_id)) == 4


def test_accepts_filters_in_the_shared_routing_core(tmp_path: Path) -> None:
    """The filter lives in route_only, so every consumer of the routing core inherits it — the live
    async path, the fused twin, dry-run/check/Test Bench and the traced dry-run all call this."""
    reg = _reg(
        tmp_path,
        handlers={"adt": lambda m: Send("OB", str(m)), "oru": lambda m: Send("OB", str(m))},
        accepts={"adt": _is_adt, "oru": lambda m: not _is_adt(m)},
    )
    ic = reg.inbound["IB"]
    assert route_only(reg, ic, ADT) == ["adt"]
    assert route_only(reg, ic, ORU) == ["oru"]
    # And the recomposed dry-run agrees (only the accepted handler transforms + delivers).
    assert route_message(reg, ic, ADT).handlers == ["adt"]
    assert len(route_message(reg, ic, ADT).deliveries) == 1


# --- AC-2 (dry-run half): all-declined is UNROUTED, and it is still a message -----------------


def test_all_declined_dry_runs_unrouted(tmp_path: Path) -> None:
    from messagefoundry.pipeline.dryrun import disposition_for

    reg = _reg(
        tmp_path,
        handlers={"h": lambda m: Send("OB", str(m))},
        accepts={"h": lambda m: False},
    )
    outcome = route_message(reg, reg.inbound["IB"], ADT)
    assert outcome.handlers == [] and outcome.deliveries == []
    # No handler took the message — the ratified §4 semantic (UNROUTED, not FILTERED).
    assert disposition_for(outcome) is MessageStatus.UNROUTED


# --- AC-4: a raising predicate is a CONTENT error, never a silent decline -----


def _boom(msg: Any) -> bool:
    raise ValueError("predicate boom")


def test_accepts_raise_propagates_out_of_route_only(tmp_path: Path) -> None:
    # The call sits BARE: a swallowed exception would silently decline the handler — an accept-and-drop
    # with no ERROR, no dead-letter, no disposition (CLAUDE.md §12). It must escape, like a Router raise.
    reg = _reg(tmp_path, handlers={"h": lambda m: Send("OB", str(m))}, accepts={"h": _boom})
    with pytest.raises(ValueError, match="predicate boom"):
        route_only(reg, reg.inbound["IB"], ADT)


async def _router_stage_state(store: MessageStore, mid: str) -> tuple[str, list[tuple[str, str]]]:
    """(messages.status, [(stage, status)]) — the full router-stage outcome of one message."""
    msg = await store.get_message(mid)
    assert msg is not None
    status = msg["status"]
    cur = await store._db.execute(
        "SELECT stage, status FROM queue WHERE message_id=? ORDER BY rowid", (mid,)
    )
    return str(status), [(r["stage"], r["status"]) for r in await cur.fetchall()]


async def test_accepts_raise_is_a_content_error(store: MessageStore, tmp_path: Path) -> None:
    """AC-4, async live path: the raise hits the router worker's CONTENT boundary → the message is
    dead-lettered at the router stage and finalizes ERROR — a first-class logged disposition, listable
    and replayable. Never a silent decline (that would be an accept-and-drop, CLAUDE.md §12).

    The strongest form of the AC is *equivalence*: a predicate raise must be indistinguishable from a
    Router raise, since it flows through the same boundary. Assert exactly that."""
    pred_reg = _reg(tmp_path, handlers={"h": lambda m: Send("OB", str(m))}, accepts={"h": _boom})
    router_reg = _reg(tmp_path, handlers={"h": lambda m: Send("OB", str(m))}, router=_boom)

    async def _run(reg: Registry) -> tuple[str, list[tuple[str, str]]]:
        item = await _claimed(store)
        await RegistryRunner(
            reg, store, egress=EgressSettings(deny_by_default=False)
        )._process_ingress_item("IB", item)
        assert await _routed_rows(store, item.message_id) == []  # no routed row materialized
        return await _router_stage_state(store, item.message_id)

    from_predicate = await _run(pred_reg)
    from_router = await _run(router_reg)

    assert from_predicate == from_router  # indistinguishable — the same CONTENT boundary
    status, rows = from_predicate
    assert status == MessageStatus.ERROR.value
    # dead-lettered at the stage that raised (the router stage consumes the ingress row)
    assert rows == [(Stage.INGRESS.value, OutboxStatus.DEAD.value)]

    # ...and it stays listable in the tracking view (counted and logged, not dropped). The DLQ view is
    # delivery-scoped by design (store._dead_filter), so a router-stage failure surfaces here.
    errored = await store.list_messages(status=MessageStatus.ERROR.value, allowed_channels=None)
    assert len(errored) == 2


class _FakeSyncPool:
    """A stand-in for the SQL-Server sync handoff pool (the fused twin never reaches it here)."""

    def __init__(self) -> None:
        self.acquired = 0

    @contextmanager
    def acquire(self) -> Iterator[Any]:
        self.acquired += 1
        yield object()


async def test_accepts_raise_is_a_content_error_on_the_fused_twin(
    store: MessageStore, tmp_path: Path
) -> None:
    """AC-4, fused twin (ADR 0071). The filter lives in route_only, so the fused path's CONTENT
    boundary classifies a predicate raise as ``route_exc`` for free — the handoff is never attempted."""
    reg = _reg(tmp_path, handlers={"h": lambda m: Send("OB", str(m))}, accepts={"h": _boom})
    runner = RegistryRunner(
        reg, store, claim_mode="pooled", egress=EgressSettings(deny_by_default=False)
    )
    fake_pool = _FakeSyncPool()
    store.sync_handoff_pool = lambda stage: fake_pool  # type: ignore[attr-defined]
    runner._fuse_route_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    item = OutboxItem(
        id="ing-1",
        message_id="m-1",
        channel_id="IB",
        destination_name=None,
        payload=ADT,
        attempts=1,
        stage=Stage.INGRESS.value,
    )
    try:
        result = await runner._fused_route_and_handoff("IB", reg.inbound["IB"], item)
    finally:
        runner._fuse_route_executor.shutdown(wait=True)
    assert isinstance(result.route_exc, ValueError)  # CONTENT, not INFRA
    assert result.handoff_exc is None
    assert result.handed_off is False and result.names == []
    assert fake_pool.acquired == 0  # the predicate raised before any handoff was attempted


async def test_fused_twin_declines_without_materializing_a_row(
    store: MessageStore, tmp_path: Path
) -> None:
    """The fused twin picks the seam up with zero changes of its own: it hands off only the survivors,
    and an all-declined message falls to UNROUTED on its existing disposition line."""
    reg = _hub(tmp_path, selected=20, accepting=4)
    runner = RegistryRunner(
        reg, store, claim_mode="pooled", egress=EgressSettings(deny_by_default=False)
    )
    handed: list[list[str]] = []

    def _route_handoff_sync(conn: Any, **kw: Any) -> bool:
        handed.append([h for h, _ in kw["handlers"]])
        return True

    store.sync_handoff_pool = lambda stage: _FakeSyncPool()  # type: ignore[attr-defined]
    store.route_handoff_sync = _route_handoff_sync  # type: ignore[attr-defined]
    runner._fuse_route_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    item = OutboxItem(
        id="ing-2",
        message_id="m-2",
        channel_id="IB",
        destination_name=None,
        payload=ADT,
        attempts=1,
        stage=Stage.INGRESS.value,
    )
    try:
        result = await runner._fused_route_and_handoff("IB", reg.inbound["IB"], item)
    finally:
        runner._fuse_route_executor.shutdown(wait=True)
    assert handed == [["h00", "h01", "h02", "h03"]]
    assert result.names == ["h00", "h01", "h02", "h03"]
    assert result.disposition is MessageStatus.ROUTED


async def test_fused_twin_all_declined_is_unrouted(store: MessageStore, tmp_path: Path) -> None:
    reg = _hub(tmp_path, selected=20, accepting=0)
    runner = RegistryRunner(
        reg, store, claim_mode="pooled", egress=EgressSettings(deny_by_default=False)
    )
    store.sync_handoff_pool = lambda stage: _FakeSyncPool()  # type: ignore[attr-defined]
    store.route_handoff_sync = lambda conn, **kw: True  # type: ignore[attr-defined]
    runner._fuse_route_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    item = OutboxItem(
        id="ing-3",
        message_id="m-3",
        channel_id="IB",
        destination_name=None,
        payload=ADT,
        attempts=1,
        stage=Stage.INGRESS.value,
    )
    try:
        result = await runner._fused_route_and_handoff("IB", reg.inbound["IB"], item)
    finally:
        runner._fuse_route_executor.shutdown(wait=True)
    assert result.names == []
    assert result.disposition is MessageStatus.UNROUTED  # §4 ruling, inherited for free
    assert result.wake_target is None  # nothing to wake — no routed row


# --- AC-3: a live lookup inside a predicate raises (router-stage purity) ------


def test_accepts_lookup_raises(tmp_path: Path) -> None:
    """A predicate runs in the ROUTER stage, where the sanctioned non-pure inputs already raise (ADR
    0010/0043) — routing must re-derive identically on an at-least-once re-run. The prohibition is by
    construction, not a new guard."""

    def _db(msg: Any) -> bool:
        db_lookup("SOME_DB", "select 1", {})
        return True

    def _fhir(msg: Any) -> bool:
        fhir_lookup("SOME_FHIR", "Patient/1")  # #1243: read-by-id; the flat '?'-query form is gone
        return True

    reg = _reg(
        tmp_path,
        handlers={"d": lambda m: Send("OB", str(m)), "f": lambda m: Send("OB", str(m))},
        accepts={"d": _db, "f": _fhir},
        router=lambda m: ["d"],
    )
    ic = reg.inbound["IB"]
    # Run under the live router phase, exactly as the router worker does.
    with run_contexts(RunContext(), phase="router"), pytest.raises(DbLookupError):
        route_only(reg, ic, ADT)

    reg2 = _reg(
        tmp_path,
        handlers={"f": lambda m: Send("OB", str(m))},
        accepts={"f": _fhir},
        router=lambda m: ["f"],
    )
    with run_contexts(RunContext(), phase="router"), pytest.raises(FhirLookupError):
        route_only(reg2, reg2.inbound["IB"], ADT)


async def test_accepts_lookup_dead_letters_on_the_live_path(
    store: MessageStore, tmp_path: Path
) -> None:
    """AC-3's disposition half: the raise is classified a router-stage ERROR, never a silent decline."""

    def _db(msg: Any) -> bool:
        db_lookup("SOME_DB", "select 1", {})
        return True

    reg = _reg(tmp_path, handlers={"h": lambda m: Send("OB", str(m))}, accepts={"h": _db})
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    item = await _claimed(store)
    await runner._process_ingress_item("IB", item)
    fetched = await store.get_message(item.message_id)
    assert fetched is not None
    assert fetched["status"] == MessageStatus.ERROR.value


# --- ADR 0057: the inline fast-path now gates on the POST-decline count -------


async def test_accepts_makes_a_multi_select_message_inline_eligible(
    store: MessageStore, tmp_path: Path
) -> None:
    """A behavior change worth pinning: ADR 0057's per-message M-single gate (``len(names) == 1``) now
    sees the SURVIVING count. A message the Router selects 3 handlers for, of which `accepts=` keeps
    exactly 1, becomes inline-eligible where it wasn't — the routed stage collapses and the message
    costs 5 commits instead of 7. Correct (the seam's whole point is that a declined handler was never
    going to run) and a bonus on top of the 2 transactions saved per decline."""
    reg = _reg(
        tmp_path,
        handlers={
            "a": lambda m: Send("OB", str(m)),
            "b": lambda m: Send("OB", str(m)),
            "c": lambda m: Send("OB", str(m)),
        },
        accepts={"b": lambda m: False, "c": lambda m: False},  # 'a' has no predicate → always kept
        inline=True,
    )
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    runner._recompute_inline_ok()  # no live lookups + ack_after=ingest + FILE ⇒ eligible
    assert runner._inline_ok["IB"] is True

    item = await _claimed(store)
    await runner._process_ingress_item("IB", item)

    # Fused: the routed stage was collapsed entirely — no routed row was ever written, and the outbound
    # row exists. (Without the seam the Router's 3 names would have failed M-single and taken the split
    # path, materializing 3 routed rows.)
    assert await _routed_rows(store, item.message_id) == []
    outbound = await store.outbox_for(item.message_id)
    assert [o["destination_name"] for o in outbound] == ["OB"]
    fetched = await store.get_message(item.message_id)
    assert fetched is not None
    assert fetched["status"] == MessageStatus.ROUTED.value


# --- registry surface --------------------------------------------------------


def test_handler_accepts_is_a_sparse_parallel_table(tmp_path: Path) -> None:
    """`handlers` must keep mapping name -> the BARE fn: reachability/impact analysis, the CLI, the
    sandbox worker and the support bundle all introspect `fn.__code__` directly."""

    def h(m: Any) -> Send:
        return Send("OB", str(m))

    reg = _reg(tmp_path, handlers={"h": h, "plain": h}, accepts={"h": _is_adt})
    assert reg.handlers["h"] is h  # not wrapped, not a record
    assert reg.handlers["h"].__code__ is h.__code__  # the introspection contract holds
    assert set(reg.handler_accepts) == {"h"}  # sparse: only the declaring handler


def test_orphan_accepts_fails_validate(tmp_path: Path) -> None:
    # An armed-looking predicate keyed to no handler would silently never run — fail closed.
    reg = _reg(tmp_path)
    reg.handler_accepts["ghost"] = _is_adt
    with pytest.raises(WiringError, match="unknown handler 'ghost'"):
        reg.validate()


def test_handler_decorator_registers_accepts(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, MLLP, Send\n"
        "\n"
        "inbound('IB_T', MLLP(port=19411), router='r')\n"
        "outbound('OB_T', MLLP(host='127.0.0.1', port=19412))\n"
        "\n"
        "@router('r')\n"
        "def r(msg):\n"
        "    return ['h_adt', 'h_all']\n"
        "\n"
        "def _adt_only(msg):\n"
        "    return msg['MSH-9.1'] == 'ADT'\n"
        "\n"
        "@handler('h_adt', accepts=_adt_only)\n"
        "def h_adt(msg):\n"
        "    return Send('OB_T', str(msg))\n"
        "\n"
        "@handler('h_all')\n"
        "def h_all(msg):\n"
        "    return Send('OB_T', str(msg))\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert set(reg.handler_accepts) == {"h_adt"}
    ic = reg.inbound["IB_T"]
    assert route_only(reg, ic, ADT) == ["h_adt", "h_all"]
    assert route_only(reg, ic, ORU) == ["h_all"]  # the ADT-only handler declined


def test_shard_filter_carries_the_predicates(tmp_path: Path) -> None:
    """A field-by-field Registry rebuild that omits `handler_accepts` would leave every engine SHARD
    routing handlers the unsharded engine declines — a silent cost + disposition regression."""
    reg = _hub(tmp_path, selected=20, accepting=4)
    sharded = filter_registry_for_shard(reg, "default")
    assert sharded.handler_accepts == reg.handler_accepts
    assert route_only(sharded, sharded.inbound["IB"], ADT) == ["h00", "h01", "h02", "h03"]


# --- ADR 0087: the predicate is user code — it must run in the sandbox CHILD ---

_SANDBOX_GRAPH = """
from messagefoundry import inbound, outbound, router, handler, MLLP, Send


def _escapes(msg):
    import socket  # forbidden INSIDE the sandbox — importable in the parent

    return True


def _pure(msg):
    return msg["MSH-9.1"] == "ADT"


inbound("IB_T", MLLP(port=19511), router="r")
outbound("OB_T", MLLP(host="127.0.0.1", port=19512))


@router("r")
def r(msg):
    # MSH-3 picks which handler is considered, so ONE graph serves both the escape test and the
    # pure-parity test. (The parent can't just swap registry.routers: the sandbox child loads its
    # OWN registry from config_dir — which is exactly the property under test.)
    return ["h_escape"] if msg["MSH-3"] == "ESC" else ["h_pure"]


@handler("h_escape", accepts=_escapes)
def h_escape(msg):
    return Send("OB_T", str(msg))


@handler("h_pure", accepts=_pure)
def h_pure(msg):
    return Send("OB_T", str(msg))
"""


@pytest.fixture
def sandbox_graph(tmp_path: Path) -> tuple[Registry, str]:
    (tmp_path / "graph.py").write_text(_SANDBOX_GRAPH, encoding="utf-8")
    return load_config(tmp_path), str(tmp_path)


def test_accepts_runs_inside_the_sandbox_child(sandbox_graph: tuple[Registry, str]) -> None:
    """The predicate evaluates at ROUTING time, so without an explicit sandbox phase it would run
    engine-side in the parent — the one piece of config code escaping the forbidden-import/resource
    caps. `import socket` is legal in the parent and denied in the child, so a SandboxError is proof
    the predicate crossed the process boundary."""
    registry, config_dir = sandbox_graph
    ic = registry.inbound["IB_T"]
    # In-process (the parity default) the escaping predicate imports socket happily — NOT contained.
    assert route_only(registry, ic, ESC) == ["h_escape"]

    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        inbound="IB_T",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        with pytest.raises(SandboxError, match="socket"):
            route_only(registry, ic, ESC, sandbox=session, run_context=RunContext())
    finally:
        session.close()


def test_pure_accepts_is_byte_identical_through_the_sandbox(
    sandbox_graph: tuple[Registry, str],
) -> None:
    """The benign round-trip: a pure predicate marshalled to the child returns the same verdict as
    in-process (parity — the sandbox changes isolation, never the routing decision)."""
    registry, config_dir = sandbox_graph
    ic = registry.inbound["IB_T"]  # a non-"ESC" MSH-3 routes to h_pure only

    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        inbound="IB_T",
        config_dir=config_dir,
        env=None,
        graph=None,
    )
    try:
        assert route_only(registry, ic, ADT, sandbox=session, run_context=RunContext()) == [
            "h_pure"
        ]
        assert route_only(registry, ic, ORU, sandbox=session, run_context=RunContext()) == []
    finally:
        session.close()


# --- payload sharing ---------------------------------------------------------


def test_predicates_share_the_routers_payload_and_cannot_reach_a_handler(tmp_path: Path) -> None:
    """Zero extra parse: every predicate sees the SAME object the Router did (a per-predicate deep copy
    on a 20-handler hub would re-spend the work the seam recovers). Isolation is structural — the
    handoff carries the original RAW string and transform_one re-parses per handler — so even a
    predicate that misbehaves and mutates cannot leak into a handler's Message."""
    seen: list[int] = []

    def _mutating(msg: Message) -> bool:
        seen.append(id(msg))
        msg.set("MSH-3", "TAMPERED")  # contract violation — pinned as UNABLE to leak downstream
        return True

    def _observer(msg: Message) -> bool:
        seen.append(id(msg))
        return True

    delivered: list[str | None] = []

    def _h(msg: Message) -> Send:
        delivered.append(msg["MSH-3"])
        return Send("OB", str(msg))

    reg = _reg(
        tmp_path,
        handlers={"a": _h, "b": _h},
        accepts={"a": _mutating, "b": _observer},
    )
    route_message(reg, reg.inbound["IB"], ADT)
    assert len(seen) == 2 and seen[0] == seen[1]  # one shared payload, not two parses
    # Each handler got a FRESH Message parsed from the original raw — the tamper never reached them.
    assert delivered == ["S", "S"]


def test_accepts_is_pure_across_a_replay(tmp_path: Path) -> None:
    """At-least-once: a router-handoff re-run must re-derive the IDENTICAL surviving set, or a crash
    could route differently. A pure predicate makes this hold by construction."""
    reg = _hub(tmp_path, selected=20, accepting=4)
    ic = reg.inbound["IB"]
    first = route_only(reg, ic, ADT)
    for _ in range(5):
        assert route_only(reg, ic, ADT) == first


def test_route_only_is_thread_safe_under_concurrent_messages(tmp_path: Path) -> None:
    """The router worker runs route_only off the event loop (asyncio.to_thread), so predicates run on
    worker threads. They hold no shared state, so concurrent messages route independently."""
    reg = _reg(
        tmp_path,
        handlers={"adt": lambda m: Send("OB", str(m)), "oru": lambda m: Send("OB", str(m))},
        accepts={"adt": _is_adt, "oru": lambda m: not _is_adt(m)},
    )
    ic = reg.inbound["IB"]

    async def _run() -> list[list[str]]:
        return list(
            await asyncio.gather(
                *(
                    asyncio.to_thread(route_only, reg, ic, raw)
                    for raw in (ADT, ORU) * 10  # interleaved
                )
            )
        )

    results = asyncio.run(_run())
    assert results == [["adt"], ["oru"]] * 10


# --- PIPE-9: accepts= static fail-closed guards, NEGATIVE branches (ADR 0084) ---
#
# test_orphan_accepts_fails_validate (above) hits the `hname not in handlers` branch, which returns
# BEFORE _check_accepts_predicate runs. These key the bad predicate to the REAL default handler "h"
# so validate() clears the orphan check and reaches the two static guards.


def _reads_run_scoped_state(msg: Any) -> bool:
    # Names ``state_get`` so the literal lands in ``__code__.co_names`` for the static scan. The body is
    # never executed (validate() only inspects the code object), so the call args are immaterial.
    return state_get("ns", "k", default=None) is not None


def _reads_run_scoped_response(msg: Any) -> bool:
    # Same idea for ``response_get`` (the other fail-OPEN run-scoped accessor).
    return response_get("OB", default=None) is not None


def test_non_callable_accepts_fails_validate(tmp_path: Path) -> None:
    # ``accepts=True`` — the intended default handed in by mistake, a plausible typo — clears the orphan
    # check yet ``pred(msg)`` would raise ``'bool' object is not callable`` on the FIRST message,
    # dead-lettering every message on that inbound. Fail closed at load/check time instead.
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = True  # type: ignore[assignment]  # keyed to the REAL handler
    with pytest.raises(WiringError, match="not callable"):
        reg.validate()


def test_state_get_accepts_fails_validate(tmp_path: Path) -> None:
    # A predicate whose code names ``state_get`` would read an EMPTY view in the router phase (it fails
    # OPEN, returning its default) and could silently invert a suppression/dedup filter migrated from a
    # Handler. Refused statically, naming the offending accessor.
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = _reads_run_scoped_state
    with pytest.raises(WiringError) as exc:
        reg.validate()
    assert "run-scoped state" in str(exc.value)
    assert "state_get" in str(exc.value)  # the message names the accessor it rejected


def test_response_get_accepts_fails_validate(tmp_path: Path) -> None:
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = _reads_run_scoped_response
    with pytest.raises(WiringError) as exc:
        reg.validate()
    assert "run-scoped state" in str(exc.value)
    assert "response_get" in str(exc.value)


# --- BACKLOG #5514: an async predicate, and a run-scoped read reached indirectly ---


async def _async_accepts(msg: Any) -> bool:
    return False  # never awaited by the router stage: its coroutine reads as True


class _AsyncCallable:
    async def __call__(self, msg: Any) -> bool:
        return False


class _StateCallable:
    def __call__(self, msg: Any) -> bool:
        return state_get("ns", "k", default=None) is not None


def _accepts_with(msg: Any, getter: Any) -> bool:
    # The accessor arrives as an argument, so its name is not in this code object's co_names.
    return getter("ns", "k", default=None) is not None


def _accepts_with_default(msg: Any, getter: Any = state_get) -> bool:
    return getter("ns", "k", default=None) is not None


def _closure_over(getter: Any) -> Any:
    def pred(msg: Any) -> bool:
        return getter("OB", default=None) is not None

    return pred


def _helper_reads_state(msg: Any) -> bool:
    return state_get("ns", "k", default=None) is not None


def _calls_a_helper(msg: Any) -> bool:
    return _helper_reads_state(msg)


def _inner_def_reads_state(msg: Any) -> bool:
    def inner() -> bool:
        return state_get("ns", "k", default=None) is not None

    return inner()


def _sync_pred(msg: Any) -> bool:
    return True


class _AsyncAdapter:
    """A class-based wrapper: update_wrapper sets __wrapped__ on the instance, which must not hide
    its own __call__ from the walk."""

    def __init__(self, fn: Any) -> None:
        functools.update_wrapper(self, fn)

    async def __call__(self, msg: Any) -> bool:
        return False


class _StateAdapter:
    def __init__(self, fn: Any) -> None:
        functools.update_wrapper(self, fn)

    def __call__(self, msg: Any) -> bool:
        return state_get("ns", "k", default=None) is not None


# A module-level alias that is a partial of the accessor, not the accessor itself.
_sg = functools.partial(state_get, "ns")


def _calls_a_partial_alias(msg: Any) -> bool:
    return _sg("k", default=None) is not None


def _helper_without_a_module() -> Any:
    """A function made by exec with globals that lack __name__, so its __module__ is None."""
    namespace: dict[str, Any] = {}
    exec("def helper(msg):\n    return True\n", namespace)  # noqa: S102 -- a fixed literal
    helper = namespace["helper"]
    assert helper.__module__ is None
    return helper


_no_module_helper = _helper_without_a_module()


def _calls_a_module_less_helper(msg: Any) -> bool:
    return bool(_no_module_helper(msg))


def _generator_accepts(msg: Any) -> Any:
    yield False  # a generator object, which also reads as True


@functools.lru_cache(maxsize=8)
def _cached_state_read(key: str) -> bool:
    return state_get("ns", key, default=None) is not None


def _calls_a_cached_helper(msg: Any) -> bool:
    return _cached_state_read("k")


class _Looped:
    """Callables whose __wrapped__ chain is a cycle; the walk must stop, not hang."""

    __call__ = staticmethod(_sync_pred)


_loop_a, _loop_b = _Looped(), _Looped()
_loop_a.__wrapped__ = _loop_b  # type: ignore[attr-defined]
_loop_b.__wrapped__ = _loop_a  # type: ignore[attr-defined]


class _RaisingClassProbe:
    enabled = True

    @property  # type: ignore[misc]
    def __class__(self) -> type:  # noqa: PLE0237 -- a lazy proxy's class lookup can raise
        raise RuntimeError("synthetic: proxy not ready")


_PROXY = _RaisingClassProbe()


def _reads_a_proxy(msg: Any) -> bool:
    # ``_PROXY.enabled`` is a (global, attribute) load, which captured_values tests with isinstance.
    return bool(_PROXY.enabled)


@pytest.mark.parametrize(
    "pred",
    [
        _async_accepts,
        functools.partial(_async_accepts),
        _AsyncCallable(),
        _AsyncAdapter(_sync_pred),
        _generator_accepts,
    ],
    ids=["async_def", "partial_of_async", "async_call_instance", "async_update_wrapper", "gen"],
)
def test_an_async_accepts_fails_validate(tmp_path: Path, pred: Any) -> None:
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = pred
    with pytest.raises(WiringError, match="is async"):
        reg.validate()


@pytest.mark.parametrize(
    ("pred", "accessor"),
    [
        (functools.partial(_accepts_with, getter=state_get), "state_get"),
        (functools.partial(state_get, "ns"), "state_get"),
        (_accepts_with_default, "state_get"),
        (_closure_over(response_get), "response_get"),
        (_StateCallable(), "state_get"),
        (_calls_a_helper, "state_get"),
        (_inner_def_reads_state, "state_get"),
        (_StateAdapter(_sync_pred), "state_get"),
        (_calls_a_partial_alias, "state_get"),
        (_calls_a_cached_helper, "state_get"),
    ],
    ids=[
        "partial_kw",
        "partial_of_accessor",
        "default",
        "closure",
        "instance",
        "helper",
        "inner",
        "update_wrapper",
        "partial_alias",
        "lru_cache_helper",
    ],
)
def test_an_indirect_run_scoped_read_fails_validate(
    tmp_path: Path, pred: Any, accessor: str
) -> None:
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = pred
    with pytest.raises(WiringError, match="run-scoped state") as exc:
        reg.validate()
    assert accessor in str(exc.value)


@pytest.mark.parametrize(
    "pred",
    [
        _is_adt,
        functools.partial(_accepts_with, getter=lambda *a, **k: None),
        _closure_over(lambda *a, **k: None),
        _calls_a_module_less_helper,  # a helper whose __module__ is None must not crash validate
        _loop_a,  # a __wrapped__ cycle must end the walk, not hang validate
    ],
    ids=["plain", "partial_harmless", "closure_harmless", "module_less_helper", "wrapped_cycle"],
)
def test_a_pure_indirect_accepts_still_validates(tmp_path: Path, pred: Any) -> None:
    # The control: the walk must not refuse a predicate that reaches no accessor.
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = pred
    reg.validate()


def test_a_walk_that_raises_is_a_configuration_problem(tmp_path: Path) -> None:
    # Author code that runs during the walk (an object's own __class__) and raises is refused as a
    # WiringError naming the exception type only, never a raw traceback out of validate().
    reg = _reg(tmp_path)
    reg.handler_accepts["h"] = _reads_a_proxy
    with pytest.raises(WiringError, match="could not be inspected") as exc:
        reg.validate()
    assert "RuntimeError" in str(exc.value)
    assert "proxy not ready" not in str(exc.value)


# --- BACKLOG #5514: a plain predicate that RETURNS an awaitable or a generator ---
# The static check refuses an `async def` predicate, but a plain function that returns a coroutine or
# a generator passes it. Read as a truth value, that object is True, so the handler would accept every
# message. The verdict is refused at run time instead, as a router-stage error.


async def _verdict_coro() -> bool:
    return False


def _returns_coroutine(msg: Any) -> Any:
    return _verdict_coro()


def _verdict_gen() -> Iterator[bool]:
    yield False


def _returns_generator(msg: Any) -> Any:
    return _verdict_gen()


async def _verdict_agen() -> AsyncIterator[bool]:
    yield False


class _Awaitable:
    """An awaitable that is not a coroutine, such as a Future-like object."""

    def __await__(self) -> Iterator[None]:
        yield None


# The refusal leaves the verdict unclosed (the predicate may share it), so a coroutine a predicate made
# draws Python's "never awaited" warning when it is collected. The traced path collects it later, in
# the cyclic collector, which can run during another test of this module.
pytestmark = pytest.mark.filterwarnings(
    "ignore:coroutine '_verdict_coro' was never awaited:RuntimeWarning"
)

_STATIC_PASSING_VERDICTS = [
    pytest.param(_returns_coroutine, id="coroutine"),
    pytest.param(_returns_generator, id="generator"),
    pytest.param(lambda m: _verdict_agen(), id="async-generator"),
    pytest.param(lambda m: _Awaitable(), id="awaitable"),
    pytest.param(lambda m: filter(None, []), id="filter-iterator"),
    pytest.param(lambda m: re.finditer("ESC", str(m)), id="finditer"),
]


@pytest.mark.parametrize("pred", _STATIC_PASSING_VERDICTS)
def test_an_awaitable_or_iterator_verdict_passes_validate_but_raises(
    tmp_path: Path, pred: Any
) -> None:
    reg = _reg(tmp_path, accepts={"h": pred})  # the static check does not see it
    with pytest.raises(TypeError, match="accepts= predicate for handler 'h' returned an object"):
        route_only(reg, reg.inbound["IB"], ADT)


# --- PR 3177 hold (c): the refusal must not consume or close a verdict the predicate may share ---


def test_a_shared_generator_is_still_usable_after_the_refusal(tmp_path: Path) -> None:
    def counter() -> Generator[int]:
        n = 0
        while True:
            n += 1
            yield n

    shared = counter()
    assert next(shared) == 1
    reg = _reg(tmp_path, accepts={"h": lambda m: shared})
    with pytest.raises(TypeError, match="handler 'h' returned an object of type generator"):
        route_only(reg, reg.inbound["IB"], ADT)
    assert trace_dry_run(reg, ADT, inbound="IB")["disposition"] == MessageStatus.ERROR.value
    # Neither path advanced it or closed it: the next value is the one after the test's own read.
    assert next(shared) == 2
    shared.close()


def test_a_shared_coroutine_can_still_be_awaited_after_the_refusal(tmp_path: Path) -> None:
    shared = _verdict_coro()
    reg = _reg(tmp_path, accepts={"h": lambda m: shared})
    with pytest.raises(TypeError, match="handler 'h' returned an object of type coroutine"):
        route_only(reg, reg.inbound["IB"], ADT)
    assert asyncio.run(shared) is False  # a closed coroutine raises RuntimeError here


def test_a_started_generator_is_refused_without_running_its_finally(tmp_path: Path) -> None:
    ran: list[str] = []

    def gen() -> Generator[bool]:
        try:
            yield False
        finally:
            ran.append("finally")

    g = gen()
    next(g)
    reg = _reg(tmp_path, accepts={"h": lambda m: g})
    with pytest.raises(TypeError, match="handler 'h' returned an object of type generator"):
        route_only(reg, reg.inbound["IB"], ADT)
    assert ran == []  # the test still holds it, so the refusal did not finalize it
    g.close()
    assert ran == ["finally"]


def test_an_unshared_refused_generator_is_finalized_before_route_only_returns(
    tmp_path: Path,
) -> None:
    # The refusal keeps no reference to the verdict, so a generator nothing else holds is collected
    # at once, on the calling thread, not wherever the TypeError dies.
    ran: list[str] = []

    def gen() -> Generator[bool]:
        try:
            yield False
        finally:
            ran.append(threading.current_thread().name)

    def pred(msg: Any) -> Any:
        g = gen()
        next(g)
        return g

    reg = _reg(tmp_path, accepts={"h": pred})
    with pytest.raises(TypeError, match="handler 'h' returned an object of type generator") as exc:
        route_only(reg, reg.inbound["IB"], ADT)
    # While the exception, and so its traceback, is still alive.
    assert ran == [threading.current_thread().name]
    del exc


@pytest.mark.parametrize("pred", _STATIC_PASSING_VERDICTS)
def test_an_awaitable_or_iterator_verdict_raises_on_the_traced_path(
    tmp_path: Path, pred: Any
) -> None:
    reg = _reg(tmp_path, accepts={"h": pred})
    out = trace_dry_run(reg, ADT, inbound="IB", show_phi=True)
    assert out["disposition"] == MessageStatus.ERROR.value
    assert out["handlers"] == []
    assert "returned an object" in (out["error"] or "")
    assert out["accepts_declined"] == []  # a refused verdict records no decline


@pytest.mark.parametrize("pred", _STATIC_PASSING_VERDICTS)
async def test_an_awaitable_or_iterator_verdict_dead_letters(
    store: MessageStore, tmp_path: Path, pred: Any
) -> None:
    ran: list[str] = []

    def h(m: Any) -> Send:
        ran.append("h")
        return Send("OB", str(m))

    reg = _reg(tmp_path, handlers={"h": h}, accepts={"h": pred})
    item = await _claimed(store)
    await RegistryRunner(
        reg, store, egress=EgressSettings(deny_by_default=False)
    )._process_ingress_item("IB", item)
    assert await _routed_rows(store, item.message_id) == []
    status, rows = await _router_stage_state(store, item.message_id)
    assert status == MessageStatus.ERROR.value
    assert rows == [(Stage.INGRESS.value, OutboxStatus.DEAD.value)]
    assert ran == []


@pytest.mark.parametrize("pred", _STATIC_PASSING_VERDICTS)
async def test_an_awaitable_or_iterator_verdict_is_a_content_error_on_the_fused_twin(
    store: MessageStore, tmp_path: Path, pred: Any
) -> None:
    reg = _reg(tmp_path, accepts={"h": pred})
    runner = RegistryRunner(
        reg, store, claim_mode="pooled", egress=EgressSettings(deny_by_default=False)
    )
    fake_pool = _FakeSyncPool()
    store.sync_handoff_pool = lambda stage: fake_pool  # type: ignore[attr-defined]
    runner._fuse_route_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    item = OutboxItem(
        id="ing-1",
        message_id="m-1",
        channel_id="IB",
        destination_name=None,
        payload=ADT,
        attempts=1,
        stage=Stage.INGRESS.value,
    )
    try:
        result = await runner._fused_route_and_handoff("IB", reg.inbound["IB"], item)
    finally:
        runner._fuse_route_executor.shutdown(wait=True)
    assert isinstance(result.route_exc, TypeError)  # CONTENT, not INFRA
    assert result.handed_off is False and result.names == []
    assert fake_pool.acquired == 0


@pytest.mark.parametrize(
    ("verdict", "expected"), [(True, ["h"]), (False, []), (1, ["h"]), ("", []), (None, [])]
)
def test_a_plain_verdict_is_unchanged(tmp_path: Path, verdict: object, expected: list[str]) -> None:
    reg = _reg(tmp_path, accepts={"h": lambda m: verdict})
    assert route_only(reg, reg.inbound["IB"], ADT) == expected
    assert trace_dry_run(reg, ADT, inbound="IB")["handlers"] == expected


class _SizedIterator:
    """An iterator whose class defines ``__len__``: it has a truth value of its own."""

    def __init__(self, n: int) -> None:
        self.n = n

    def __iter__(self) -> _SizedIterator:
        return self

    def __next__(self) -> int:
        raise StopIteration

    def __len__(self) -> int:
        return self.n


@pytest.mark.parametrize(("n", "expected"), [(0, []), (1, ["h"])])
def test_an_iterator_with_its_own_truth_value_is_read_by_it(
    tmp_path: Path, n: int, expected: list[str]
) -> None:
    reg = _reg(tmp_path, accepts={"h": lambda m: _SizedIterator(n)})
    assert route_only(reg, reg.inbound["IB"], ADT) == expected


_SANDBOX_AWAITABLE_GRAPH = """
import re

from messagefoundry import inbound, outbound, router, handler, MLLP, Send


async def _coro():
    return False


def _gen():
    yield False


async def _agen():
    yield False


inbound("IB_T", MLLP(port=19513), router="r")
outbound("OB_T", MLLP(host="127.0.0.1", port=19514))


@router("r")
def r(msg):
    return ["h_" + msg["MSH-3"]]


@handler("h_coro", accepts=lambda m: _coro())
def h_coro(msg):
    return Send("OB_T", str(msg))


@handler("h_gen", accepts=lambda m: _gen())
def h_gen(msg):
    return Send("OB_T", str(msg))


@handler("h_agen", accepts=lambda m: _agen())
def h_agen(msg):
    return Send("OB_T", str(msg))


@handler("h_filter", accepts=lambda m: filter(None, []))
def h_filter(msg):
    return Send("OB_T", str(msg))


class _Awaitable:
    def __await__(self):
        yield None


@handler("h_awaitable", accepts=lambda m: _Awaitable())
def h_awaitable(msg):
    return Send("OB_T", str(msg))


@handler("h_finditer", accepts=lambda m: re.finditer("ESC", str(m)))
def h_finditer(msg):
    return Send("OB_T", str(msg))
"""


def test_an_awaitable_or_iterator_verdict_raises_in_the_sandbox_child(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(_SANDBOX_AWAITABLE_GRAPH, encoding="utf-8")
    registry = load_config(tmp_path)
    ic = registry.inbound["IB_T"]
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=15.0),
        inbound="IB_T",
        config_dir=str(tmp_path),
        env=None,
        graph=None,
    )
    try:
        # The six shapes of _STATIC_PASSING_VERDICTS, each across the process boundary.
        for kind in ("coro", "gen", "agen", "filter", "awaitable", "finditer"):
            raw = ADT.replace("|S|F|", f"|{kind}|F|")
            hname = f"h_{kind}"
            # "sandbox failed accepts" is the parent's text for an error the CHILD reported, so the
            # refusal ran across the process boundary rather than in the parent.
            with pytest.raises(
                SandboxError,
                match=f"sandbox failed accepts '{hname}'.*'{hname}' returned an object",
            ):
                route_only(registry, ic, raw, sandbox=session, run_context=RunContext())
    finally:
        session.close()


# --- BACKLOG #5514 follow-up: the refusal text carries author-controlled class names ---


def _crlf_awaitable() -> object:
    return type("Evil\r\nINJECTED line", (), {"__await__": lambda self: iter(())})()


def _crlf_iterator() -> object:
    return type(
        "Evil\r\nINJECTED line", (), {"__iter__": lambda self: self, "__next__": lambda self: 0}
    )()


@pytest.mark.parametrize("make", [_crlf_awaitable, _crlf_iterator], ids=["awaitable", "iterator"])
def test_a_crafted_class_name_reaches_the_refusal_text_escaped(make: Any) -> None:
    with pytest.raises(TypeError) as exc:
        accepts_verdict("h", make())
    text = str(exc.value)
    assert "\r" not in text and "\n" not in text
    assert "Evil" in text and "INJECTED line" in text  # escaped, not dropped


def test_the_refusal_text_does_not_demand_a_strict_bool() -> None:
    # None, an int, a str and re.Match are still read by their truth value, so "it must return a
    # bool" would be false; the text names the rule the code applies.
    with pytest.raises(TypeError) as exc:
        accepts_verdict("h", filter(None, []))
    assert "must return a bool" not in str(exc.value)
    assert "truth value is the verdict" in str(exc.value)
    assert accepts_verdict("h", re.search("x", "x")) is True
    assert accepts_verdict("h", None) is False
