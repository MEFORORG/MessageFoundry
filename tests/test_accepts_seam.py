# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from messagefoundry.config.db_lookup import DbLookupError, db_lookup
from messagefoundry.config.fhir_lookup import FhirLookupError, fhir_lookup
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    load_config,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import route_message, route_only
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
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
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
    runner = RegistryRunner(reg, store)
    item = await _claimed(store)
    await runner._process_ingress_item("IB", item)
    assert await _routed_rows(store, item.message_id) == ["a", "b"]  # both, as today
    assert (await store.get_message(item.message_id))["status"] == MessageStatus.ROUTED.value


# --- AC-1: the decline lands BEFORE a routed row exists ----------------------


async def test_accepts_declines_before_a_routed_row_exists(
    store: MessageStore, tmp_path: Path
) -> None:
    """The ADR 0084 forcing case: SELECT 20, accept 4. The 16 decliners must never reach the store —
    that is the whole seam (each routed row they'd have cost is 2 durable transactions)."""
    reg = _hub(tmp_path, selected=20, accepting=4)
    runner = RegistryRunner(reg, store)

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
    assert (await store.get_message(item.message_id))["status"] == MessageStatus.ROUTED.value
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
    status = (await store.get_message(mid))["status"]
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
        await RegistryRunner(reg, store)._process_ingress_item("IB", item)
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
    errored = await store.list_messages(status=MessageStatus.ERROR.value)
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
    runner = RegistryRunner(reg, store, claim_mode="pooled")
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
    runner = RegistryRunner(reg, store, claim_mode="pooled")
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
    runner = RegistryRunner(reg, store, claim_mode="pooled")
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
        fhir_lookup("SOME_FHIR", "Patient?identifier=1")
        return True

    reg = _reg(
        tmp_path,
        handlers={"d": lambda m: Send("OB", str(m)), "f": lambda m: Send("OB", str(m))},
        accepts={"d": _db, "f": _fhir},
        router=lambda m: ["d"],
    )
    ic = reg.inbound["IB"]
    # Run under the live router phase, exactly as the router worker does.
    with run_contexts(RunContext(), phase="router"):
        with pytest.raises(DbLookupError):
            route_only(reg, ic, ADT)

    reg2 = _reg(
        tmp_path,
        handlers={"f": lambda m: Send("OB", str(m))},
        accepts={"f": _fhir},
        router=lambda m: ["f"],
    )
    with run_contexts(RunContext(), phase="router"):
        with pytest.raises(FhirLookupError):
            route_only(reg2, reg2.inbound["IB"], ADT)


async def test_accepts_lookup_dead_letters_on_the_live_path(
    store: MessageStore, tmp_path: Path
) -> None:
    """AC-3's disposition half: the raise is classified a router-stage ERROR, never a silent decline."""

    def _db(msg: Any) -> bool:
        db_lookup("SOME_DB", "select 1", {})
        return True

    reg = _reg(tmp_path, handlers={"h": lambda m: Send("OB", str(m))}, accepts={"h": _db})
    runner = RegistryRunner(reg, store)
    item = await _claimed(store)
    await runner._process_ingress_item("IB", item)
    assert (await store.get_message(item.message_id))["status"] == MessageStatus.ERROR.value


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
    runner = RegistryRunner(reg, store)
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
    assert (await store.get_message(item.message_id))["status"] == MessageStatus.ROUTED.value


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
        config_dir=config_dir,
        env=None,
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
        config_dir=config_dir,
        env=None,
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

    delivered: list[str] = []

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
