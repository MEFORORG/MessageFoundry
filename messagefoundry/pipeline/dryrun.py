# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Dry-run a wiring Registry against messages — pure routing/handling, no I/O.

Runs a message through an inbound connection's Router and Handler(s) exactly as the engine would,
but with **no store, connectors, network, or ACK** — capturing the routing decision, the disposition
(RECEIVED/UNROUTED/FILTERED/ERROR), and the payload each Handler *would* send. This powers the IDE
Test Bench and the ``dryrun`` CLI. The routing core (:func:`route_message`) is shared with the live
engine (:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner`) so both route identically.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.wiring import (
    META_MAX_BYTES,
    META_MAX_KEYS,
    HandlerAccepts,
    HandlerFn,
    InboundConnection,
    Registry,
    RouterFn,
    Send,
    SetMeta,
    SetState,
    StateValue,
)
from messagefoundry.parsing import (
    HL7PeekError,
    Message,
    Peek,
    RawMessage,
    normalize,
    split_batch,
    summarize,
    validate,
)
from messagefoundry.pipeline.sandbox import SandboxMode, SandboxSession, run_sandboxed
from messagefoundry.store import MessageStatus

__all__ = [
    "DeliveryPreview",
    "StateOpPreview",
    "MetaOpPreview",
    "RouteOutcome",
    "DryRunResult",
    "TraceHook",
    "route_message",
    "route_only",
    "transform_one",
    "disposition_for",
    "dry_run",
    "select_inbound",
    "read_messages",
    "read_message_sets",
    "split_messages",
]

log = logging.getLogger(__name__)


class TraceHook(Protocol):
    """An optional observer the traced dry-run (ADR 0072) passes in to wrap the Router/Handler call.

    When a ``tracer`` is supplied, :func:`route_only` / :func:`transform_one` invoke the Router/Handler
    **through** the hook instead of calling it directly, so the hook can install ``sys.settrace`` around
    exactly that call. The hook is a *pure observer* — it returns the callable's result unchanged and
    re-raises any exception — so the traced path is byte-identical to the default (``tracer=None``). The
    concrete implementation lives in :mod:`messagefoundry.pipeline.dryrun_trace`; this Protocol keeps
    ``dryrun`` free of any dependency on it (one-way import)."""

    def trace_router(
        self, fn: RouterFn, name: str, payload: Message | RawMessage
    ) -> list[str] | str | None: ...

    def trace_handler(
        self, fn: HandlerFn, name: str, payload: Message | RawMessage
    ) -> Send | SetState | SetMeta | list[Send | SetState | SetMeta] | None: ...

    def trace_accepts(
        self, pred: HandlerAccepts, name: str, payload: Message | RawMessage
    ) -> bool: ...


def _handler_names(result: list[str] | str | None) -> list[str]:
    if result is None:
        return []
    return [result] if isinstance(result, str) else list(result)


def _partition(
    result: Send | SetState | SetMeta | list[Send | SetState | SetMeta] | None,
) -> tuple[list[Send], list[SetState], list[SetMeta]]:
    """Split a Handler's return into (deliveries, state writes, metadata writes) — ADR 0005 + ADR 0081.

    A Handler may return :class:`Send`\\ s, :class:`SetState`\\ s and/or :class:`SetMeta`\\ s (a single
    value, a mixed list, or ``None``). ``Send``-only returns yield ``([...], [], [])`` — backward
    compatible."""
    if result is None:
        return [], [], []
    items = result if isinstance(result, list) else [result]
    sends = [it for it in items if isinstance(it, Send)]
    state_ops = [it for it in items if isinstance(it, SetState)]
    meta_ops = [it for it in items if isinstance(it, SetMeta)]
    return sends, state_ops, meta_ops


def _payload(raw: str | bytes, content_type: str) -> Message | RawMessage:
    """The object a Router/Handler receives (ADR 0004): a mutable HL7 :class:`Message` for ``hl7v2``,
    or a verbatim :class:`RawMessage` (``.raw``/``.text``/``.json()``) for any other ``content_type``.

    Each call yields a **fresh** object. For ``hl7v2`` that isolation is load-bearing: a Handler
    *mutates* its :class:`Message`, so every consumer must get its own parse (one parse per consumer
    is also cheaper than parse-once-then-deep-copy — python-hl7's parse beats deep-copying its nested
    list tree). A :class:`RawMessage` is read-only, so it is safe to *share* across consumers of the
    same message (see :func:`_shareable_payload`)."""
    if content_type == ContentType.HL7V2.value:
        return Message.parse(raw)
    return RawMessage(raw if isinstance(raw, str) else raw.decode("utf-8"), content_type)


def _shareable_payload(raw: str | bytes, content_type: str) -> Message | RawMessage | None:
    """A single payload object safe to reuse across a router + every handler of *one* message, or
    ``None`` when no such object exists and each consumer must build its own.

    A non-HL7 :class:`RawMessage` is treated as read-only *by convention* (a Router/Handler/predicate
    reads ``.raw``/``.text``/``.json()`` and returns a fresh output string; ``.raw`` is a plain writable
    attribute, so the contract is enforced by the no-mutation rule, not by the type), so one instance
    serves the whole fan-out — building it once avoids re-decoding/re-constructing it per handler on a
    high-fan-out non-HL7 feed. Because it IS shared, a consumer that broke the convention and mutated
    ``.raw`` would be visible to later consumers of the same message. An HL7 :class:`Message` is *mutable*
    (Handlers transform it in place), so it cannot be shared: this returns ``None`` and each consumer
    re-parses (the optimal isolation strategy — see :func:`_payload`)."""
    if content_type == ContentType.HL7V2.value:
        return None
    return RawMessage(raw if isinstance(raw, str) else raw.decode("utf-8"), content_type)


@dataclass(frozen=True)
class DeliveryPreview:
    """What a Handler would deliver (no send happens).

    ``to`` names a known **outbound** connection (the body is delivered there) **or** a **pass-through
    (PT) inbound** (ADR 0013, generalized) — an internal inbound whose own Router re-routes the body.
    ``is_passthrough`` distinguishes the two so the transform handoff produces an outbound row vs. a
    re-ingressed child INGRESS row on the PT channel; it defaults ``False`` so every existing outbound
    delivery is byte-identical."""

    to: str
    payload: str
    is_passthrough: bool = False


@dataclass(frozen=True)
class StateOpPreview:
    """A state write a Handler would declare (ADR 0005) — captured for the dry-run, applied nowhere.

    ``value`` is the would-be-stored value; it may carry PHI (e.g. an MRN→anon mapping), so the CLI
    gates it behind ``--show-phi`` exactly like a delivery payload."""

    namespace: str
    key: str
    value: Any


@dataclass(frozen=True)
class MetaOpPreview:
    """A per-message metadata write a Handler would declare (ADR 0081, BACKLOG #150) — captured for the
    dry-run, applied nowhere. ``value`` may carry PHI, so the CLI gates it behind ``--show-phi`` exactly
    like a delivery payload / state write."""

    key: str
    value: str


def _accepted(
    registry: Registry,
    names: list[str],
    payload: Message | RawMessage,
    *,
    tracer: TraceHook | None,
    sandbox: SandboxSession | None,
    run_context: RunContext | None,
) -> list[str]:
    """Drop the handlers whose ``accepts=`` predicate declines this message (ADR 0084).

    A handler with no predicate is always kept, so this is identity on today's graphs. The predicates
    of one message all see the **same** ``payload`` object the Router just ran on — the point of the
    seam is to spend *zero* extra work at routing time, and a per-predicate re-parse would re-spend the
    very transactions it exists to recover.

    A predicate MUST NOT mutate the payload (the Router shares the object; mutation would make routing
    order-dependent — :data:`~messagefoundry.config.wiring.HandlerAccepts` states the contract). For an
    **HL7** feed a mutation additionally cannot LEAK downstream: :func:`route_message` shares nothing for
    HL7 (``_shareable_payload`` returns ``None``), so ``route_handoff`` carries the ORIGINAL RAW string
    and :func:`transform_one` re-parses each surviving handler a fresh :class:`Message`. For a **non-HL7**
    feed that structural isolation does NOT hold: ``_shareable_payload`` returns ONE writable
    :class:`RawMessage` shared across the router, every predicate, and every handler — a mutating
    predicate WOULD reach a downstream handler in dry-run (this is the same pre-existing sharing hazard a
    mutating Router has). So on non-HL7 the no-mutation contract is load-bearing, not merely advisory.

    The predicate call sits **bare** — deliberately. Wrapping it in ``except Exception: continue`` would
    turn a broken predicate into a silent decline: the handler quietly stops receiving messages with no
    ``ERROR``, no dead-letter, and no operator-visible disposition — an accept-and-drop (CLAUDE.md §12).
    A raise must propagate out of :func:`route_only` exactly as a Router raise does, into the caller's
    router-stage CONTENT error boundary (dead-letter / ``ERROR``; AC-4).
    """
    kept: list[str] = []
    for hname in names:
        pred = registry.handler_accepts.get(hname)
        if pred is None:
            kept.append(hname)
            continue
        if sandbox is not None and sandbox.mode is SandboxMode.SUBPROCESS:
            # ADR 0087 parity: the predicate is user code and must run under the SAME isolation as the
            # Router/Handler it sits beside. Evaluating it here in the parent would let a predicate
            # reach the imports and resources the sandbox exists to deny.
            verdict = bool(
                run_sandboxed(
                    pred,
                    payload,
                    phase="accepts",
                    name=hname,
                    run_context=run_context,
                    session=sandbox,
                )
            )
        elif tracer is not None:
            verdict = tracer.trace_accepts(pred, hname, payload)
        else:
            verdict = pred(payload)
        if verdict:
            kept.append(hname)
    return kept


@dataclass(frozen=True)
class RouteOutcome:
    """The result of running a Router + its Handlers (without validation/disposition)."""

    handlers: list[str]  # handler names the Router selected ([] = routed nowhere)
    deliveries: list[DeliveryPreview]
    state_ops: list[StateOpPreview] = field(default_factory=list)  # declared writes (ADR 0005)
    meta_ops: list[MetaOpPreview] = field(default_factory=list)  # metadata writes (ADR 0081)

    @property
    def routed(self) -> bool:
        return bool(self.handlers)


def route_only(
    registry: Registry,
    ic: InboundConnection,
    raw: str | bytes,
    *,
    payload: Message | RawMessage | None = None,
    tracer: TraceHook | None = None,
    sandbox: SandboxSession | None = None,
    run_context: RunContext | None = None,
) -> list[str]:
    """Run ``ic``'s Router and return the handler name(s) it selected (``[]`` = routed nowhere).

    The **router half** of the split routing core (ADR 0001 Step B): it decides *which* handlers take
    the message but runs no transform. Every selected handler is validated to exist — a router naming
    an unknown handler (typo / renamed / removed handler) fails closed **here** (``ValueError``) rather
    than producing a routed-stage row no transform worker can run; on the live path the router worker
    dead-letters/NAK-equivalents it, and dry-run / ``messagefoundry check`` surface the bad name
    (review M-7). The live engine's router worker calls this; the combined :func:`route_message` does too.

    A selected handler that declared an ``accepts=`` predicate (ADR 0084) is then given the chance to
    **decline** the message — the returned list holds only the handlers that will actually take it, so
    a decline never materializes a routed row (0 transactions, not 2). See :func:`_accepted`.

    ``payload`` is an optional pre-built Router input: when given it is used **as-is** instead of
    parsing ``raw`` (a caller that already built the read-only :class:`RawMessage` — see
    :func:`_shareable_payload` — passes it to skip a redundant construct). The caller is responsible
    for the payload being a faithful, *isolated-where-mutable* view of ``raw``; ``None`` (the default)
    keeps the self-parsing behavior, so every existing call site is byte-identical.

    ``tracer`` (ADR 0072) is an optional observer: when given, the Router is invoked **through**
    ``tracer.trace_router`` (which installs ``sys.settrace`` around the call) instead of called directly.
    The hook returns the Router's result unchanged, so the routing decision is byte-identical.

    ``sandbox`` (ADR 0087) optionally isolates the Router in a subprocess: with ``None`` or
    ``mode=off`` the Router runs in-process byte-identically (and the ``tracer`` composes); with
    ``mode=subprocess`` the call is marshalled to the persistent worker (``run_context`` is marshalled
    with it) and a forbidden op / resource-cap / crash raises :class:`SandboxError` — the fail-closed
    handler-name validation below still runs **engine-side** on the returned result.
    """
    route = registry.routers[ic.router]
    if payload is None:
        payload = _payload(raw, ic.content_type.value)
    raw_result: list[str] | str | None
    if sandbox is not None and sandbox.mode is SandboxMode.SUBPROCESS:
        raw_result = cast(
            "list[str] | str | None",
            run_sandboxed(
                route,
                payload,
                phase="router",
                name=ic.router,
                run_context=run_context,
                session=sandbox,
            ),
        )
    else:
        raw_result = (
            route(payload) if tracer is None else tracer.trace_router(route, ic.router, payload)
        )
    names = _handler_names(raw_result)
    for hname in names:
        if hname not in registry.handlers:
            raise ValueError(f"router {ic.router!r} returned unknown handler {hname!r}")
    # ADR 0084: give each selected handler that declared an `accepts=` predicate the chance to decline
    # BEFORE its routed row exists. Filtering HERE — in the shared routing core — rather than in the
    # router worker is what makes the seam total: all four consumers of route_only (the async live
    # router worker, the fused route twin, dry-run/`check`/Test Bench, and the traced dry-run) pick it
    # up, along with each one's disposition line and CONTENT error boundary, with no change to any of
    # them. A graph with no predicates early-outs on one dict truthiness check (AC-7: byte-identical).
    if not registry.handler_accepts:
        return names
    return _accepted(
        registry, names, payload, tracer=tracer, sandbox=sandbox, run_context=run_context
    )


def transform_one(
    registry: Registry,
    hname: str,
    raw: str | bytes,
    content_type: str = ContentType.HL7V2.value,
    *,
    payload: Message | RawMessage | None = None,
    tracer: TraceHook | None = None,
    sandbox: SandboxSession | None = None,
    run_context: RunContext | None = None,
) -> tuple[list[DeliveryPreview], list[StateOpPreview], list[MetaOpPreview]]:
    """Run **one** Handler on its own freshly-built payload; return ``(deliveries, state_ops, meta_ops)``.

    The **transform half** of the split routing core (ADR 0001 Step B): a single handler, its own
    payload (a :class:`Message`, or a :class:`RawMessage` when ``content_type`` is non-HL7 — so one
    handler's transforms can't leak into another's), with every ``Send`` target validated against the
    outbound registry. An unknown outbound fails closed **here** (``ValueError``): an undeliverable
    target would otherwise enqueue an outbound row no worker drains (silent accept-and-strand).

    A Handler may also return :class:`~messagefoundry.config.wiring.SetState` ops (ADR 0005); they are
    split out (``state_ops``) and applied exactly-once by the store inside the transform handoff (the
    live transform worker passes them to ``transform_handoff(state_ops=...)``). The caller guarantees
    ``hname`` is registered (:func:`route_only` validated it); the live engine's transform worker calls
    this per routed-stage row.

    ``payload`` is an optional pre-built Handler input; ``None`` (the default) self-parses ``raw``, so
    every existing call site is byte-identical. **Only pass a payload that is safe for this handler to
    mutate in isolation** — a read-only :class:`RawMessage` (see :func:`_shareable_payload`) qualifies
    and may be shared across a message's handlers; a mutable HL7 :class:`Message` must *not* be reused
    across handlers (the caller passes ``None`` for HL7 so each handler re-parses its own).

    ``tracer`` (ADR 0072) is an optional observer: when given, the Handler is invoked **through**
    ``tracer.trace_handler`` (which installs ``sys.settrace`` around the call) instead of called
    directly. The hook returns the Handler's result unchanged, so the deliveries are byte-identical.
    """
    handle: HandlerFn = registry.handlers[hname]
    if payload is None:
        payload = _payload(raw, content_type)
    raw_result: Send | SetState | SetMeta | list[Send | SetState | SetMeta] | None
    if sandbox is not None and sandbox.mode is SandboxMode.SUBPROCESS:
        raw_result = cast(
            "Send | SetState | SetMeta | list[Send | SetState | SetMeta] | None",
            run_sandboxed(
                handle,
                payload,
                phase="transform",
                name=hname,
                run_context=run_context,
                session=sandbox,
            ),
        )
    else:
        raw_result = (
            handle(payload) if tracer is None else tracer.trace_handler(handle, hname, payload)
        )
    sends, ops, meta = _partition(raw_result)
    # Cap the handler's metadata contribution (ADR 0081): a runaway bag would bloat the encrypted
    # column. Over-cap is a transform-time code error → the transform worker dead-letters the row.
    if len(meta) > META_MAX_KEYS:
        raise ValueError(
            f"handler {hname!r} returned {len(meta)} SetMeta ops (> {META_MAX_KEYS} per message)"
        )
    meta_bytes = sum(len(m.key.encode()) + len(m.value.encode()) for m in meta)
    if meta_bytes > META_MAX_BYTES:
        raise ValueError(
            f"handler {hname!r} SetMeta payload is {meta_bytes} bytes (> {META_MAX_BYTES} per message)"
        )
    deliveries: list[DeliveryPreview] = []
    for send in sends:
        # A Send.to names a known OUTBOUND (deliver there) OR a pass-through (PT) INBOUND (ADR 0013,
        # generalized — re-ingress the body through that internal inbound's own Router). Either fails
        # closed HERE if unknown: an undeliverable target would otherwise enqueue a row no worker drains
        # (silent accept-and-strand). A non-PT inbound is NOT a valid target (only an outbound or a PT).
        tic = registry.inbound.get(send.to)
        is_pt = tic is not None and tic.spec.type is ConnectorType.PT
        if not is_pt and send.to not in registry.outbound:
            raise ValueError(
                f"handler {hname!r} sent to unknown outbound/pass-through connection {send.to!r}"
            )
        out_payload = send.message if isinstance(send.message, str) else send.message.encode()
        deliveries.append(DeliveryPreview(to=send.to, payload=out_payload, is_passthrough=is_pt))
    state_ops = [StateOpPreview(namespace=op.namespace, key=op.key, value=op.value) for op in ops]
    meta_ops = [MetaOpPreview(key=m.key, value=m.value) for m in meta]
    return deliveries, state_ops, meta_ops


def _dry_run_reference_view(registry: Registry) -> dict[str, Mapping[str, Any]]:
    """Best-effort preview of reference snapshots for a dry-run (ADR 0006): load each FILE-backed
    declaration with a literal path. DB-backed or ``env()``-path sets can't be materialized without a
    store/environment, so they're omitted (a read of one then raises, as a preview error)."""
    view: dict[str, Mapping[str, Any]] = {}
    for spec in registry.references.values():
        if spec.source.kind != "file":
            continue
        path = spec.source.settings.get("path")
        if not isinstance(path, str):  # an env() ref — unresolved in a pure dry-run
            continue
        try:
            view[spec.name] = dict(load_code_set(path))
        except CodeSetError:
            continue
    return view


def route_message(
    registry: Registry,
    ic: InboundConnection,
    raw: str | bytes,
    *,
    ingest_time: float | None = None,
    tracer: TraceHook | None = None,
    sandbox: SandboxSession | None = None,
) -> RouteOutcome:
    """Run ``ic``'s Router then the named Handlers; return what they selected and would send.

    ``ingest_time`` (epoch seconds) is the value a Handler's ``current_ingest_time()`` resolves to in
    this preview; the CLI passes ``time.time()`` so a now-defaulting transform previews realistically. It
    is ``None`` (the default) for a pure call, where ``current_ingest_time()`` returns ``None``.

    Convenience recomposition of :func:`route_only` + :func:`transform_one` for the dry-run / Test
    Bench / CLI preview, which want the whole routing outcome in one shot. The live **staged** engine
    instead runs the two halves at *separate* stages (router worker → transform worker), so it and the
    dry-run path route identically. Each handler still gets its own :class:`Message` (via
    :func:`transform_one`). Router/Handler exceptions propagate to the caller.

    ``tracer`` (ADR 0072) is threaded to :func:`route_only` / :func:`transform_one` so the traced
    dry-run can observe each Router/Handler call; it is a pure observer, so the outcome is byte-identical.
    """
    # Publish the graph's code sets so a call-time code_set(...) inside a Router/Handler resolves
    # during a dry-run / Test Bench / `messagefoundry check` preview (the loader only had them active
    # at import time). The live staged engine activates them in its workers; this mirrors it.
    #
    # State (ADR 0005): there is no store/cache in a dry-run, so publish an in-memory view that
    # *accumulates this run's own declared writes* — so a later handler's state_get(...) sees what an
    # earlier handler in the same simulated message declared (a self-consistent preview), mirroring how
    # the live cache would reflect committed writes. It is local to this call (no global side effect).
    sim_state: dict[tuple[str, str], StateValue] = {}
    # Reference sets (ADR 0006): there is no store/sync in a dry-run, so build a best-effort preview
    # view from the graph's FILE-backed declarations (literal paths) so a reference(...) read resolves
    # during `check`/Test Bench. DB-backed or env()-path sets can't be reached in a pure dry-run and are
    # simply absent (a read of one then raises, surfaced as that message's preview error).
    sim_reference = _dry_run_reference_view(registry)
    deliveries: list[DeliveryPreview] = []
    state_ops: list[StateOpPreview] = []
    meta_ops: list[MetaOpPreview] = []
    # Activate the same run-scoped providers the live engine uses (via the shared run_context registry),
    # so router + handlers resolve identically here and in the staged engine. Dry-run runs router and
    # transform in one block, so it uses the transform (superset) phase; it has no live environment, so
    # active_environment=None — current_environment() then returns None, exactly as when dry-run left the
    # environment unset. A provider that needs live infrastructure (db_lookup) refuses to run here.
    rc = RunContext(
        code_sets=registry.code_sets,
        reference_view=sim_reference,
        state_view=sim_state,
        active_environment=None,
        ingest_time=ingest_time,
        # #162: a dry-run/preview has no persisted message, so message_id stays None — the
        # unmapped-capture drain has no id to key by (and the default sink is None here anyway).
    )
    with run_contexts(rc, phase="transform"):
        ct = ic.content_type.value
        # Parse-once on the per-message fan-out: for a non-HL7 feed the payload is a read-only
        # RawMessage, so build it ONCE and reuse it for the router and every handler instead of
        # re-decoding/re-constructing it N+1 times. For HL7 this is None (Handlers mutate their
        # Message in place — see _shareable_payload — so each consumer re-parses its own, which is
        # also cheaper than parse-once-then-deep-copy). Value-identical either way.
        shared = _shareable_payload(raw, ct)
        names = route_only(
            registry, ic, raw, payload=shared, tracer=tracer, sandbox=sandbox, run_context=rc
        )
        for hname in names:
            ds, ops, meta = transform_one(
                registry,
                hname,
                raw,
                ct,
                payload=shared,
                tracer=tracer,
                sandbox=sandbox,
                run_context=rc,
            )
            deliveries.extend(ds)
            for op in ops:
                sim_state[(op.namespace, op.key)] = op.value  # visible to subsequent handlers
            state_ops.extend(ops)
            meta_ops.extend(meta)
    return RouteOutcome(
        handlers=names, deliveries=deliveries, state_ops=state_ops, meta_ops=meta_ops
    )


def disposition_for(outcome: RouteOutcome) -> MessageStatus:
    """Classify a routing outcome for the **dry-run / Test Bench preview**.

    A delivering outcome maps to ``RECEIVED`` — the preview's entry-state ("accepted; would route to
    ≥1 destination"), since a pure simulation can't know the eventual delivery result. The live staged
    engine records the post-router state differently for the same outcome: the ingress worker persists
    ``ROUTED`` (then ``PROCESSED`` once delivered), because ``RECEIVED`` now means "committed at ingress,
    awaiting routing." So this is a deliberate preview-vs-live difference, not a shared mapping — the
    live path does NOT call this function (see ``RegistryRunner._ingress_worker``)."""
    if outcome.deliveries:
        return MessageStatus.RECEIVED
    return MessageStatus.UNROUTED if not outcome.routed else MessageStatus.FILTERED


@dataclass(frozen=True)
class DryRunResult:
    """Outcome of dry-running one message against an inbound connection."""

    inbound: str
    disposition: MessageStatus
    raw: str
    message_type: str | None = None
    control_id: str | None = None
    summary: str | None = None
    handlers: list[str] = field(default_factory=list)
    deliveries: list[DeliveryPreview] = field(default_factory=list)
    state_ops: list[StateOpPreview] = field(default_factory=list)  # declared writes (ADR 0005)
    meta_ops: list[MetaOpPreview] = field(default_factory=list)  # metadata writes (ADR 0081)
    error: str | None = None


def select_inbound(registry: Registry, name: str | None = None) -> InboundConnection:
    """Pick which inbound connection (Router) to simulate; defaults to the sole one."""
    if name is not None:
        try:
            return registry.inbound[name]
        except KeyError:
            raise ValueError(f"no such inbound connection: {name!r}") from None
    if len(registry.inbound) == 1:
        return next(iter(registry.inbound.values()))
    raise ValueError(
        "config has multiple inbound connections; choose one: "
        + ", ".join(sorted(registry.inbound))
    )


def _dry_run_raw(
    registry: Registry,
    ic: InboundConnection,
    raw: str | bytes,
    *,
    tracer: TraceHook | None = None,
) -> DryRunResult:
    """Dry-run a non-HL7 inbound (ADR 0004): no HL7 peek/validate; route the body as a RawMessage."""
    text = raw if isinstance(raw, str) else raw.decode("utf-8")
    try:
        outcome = route_message(registry, ic, text, ingest_time=time.time(), tracer=tracer)
    except Exception as exc:  # a router/handler script raised
        return DryRunResult(
            inbound=ic.name,
            disposition=MessageStatus.ERROR,
            raw=text,
            message_type=ic.content_type.value,
            error=f"router/handler error: {exc}",
        )
    return DryRunResult(
        inbound=ic.name,
        disposition=disposition_for(outcome),
        raw=text,
        message_type=ic.content_type.value,
        handlers=outcome.handlers,
        deliveries=outcome.deliveries,
        state_ops=outcome.state_ops,
    )


def dry_run(
    registry: Registry,
    raw: str | bytes,
    *,
    inbound: str | None = None,
    tracer: TraceHook | None = None,
) -> DryRunResult:
    """Parse → (strict-validate) → route one message, returning disposition + would-send payloads.

    Mirrors the engine's disposition logic with **no side effects**.

    ``tracer`` (ADR 0072) is an optional observer threaded to the routing core so the traced dry-run
    (:func:`messagefoundry.pipeline.dryrun_trace.trace_dry_run`) can capture the Router/Handler execution;
    it does not change the disposition or would-send payloads (byte-identical to ``tracer=None``).
    """
    ic = select_inbound(registry, inbound)
    if ic.content_type is not ContentType.HL7V2:
        return _dry_run_raw(registry, ic, raw, tracer=tracer)
    text = normalize(raw)

    try:
        peek = Peek.parse(text)
    except HL7PeekError as exc:
        return DryRunResult(
            inbound=ic.name, disposition=MessageStatus.ERROR, raw=text, error=f"parse error: {exc}"
        )

    mt, cid, summ = peek.message_type, peek.control_id, (summarize(peek) or None)

    if ic.validation.strict:
        result = validate(text, expected_version=ic.validation.hl7_version)
        if not result.ok:
            return DryRunResult(
                inbound=ic.name,
                disposition=MessageStatus.ERROR,
                raw=text,
                message_type=mt,
                control_id=cid,
                summary=summ,
                error="; ".join(result.errors)[:200],
            )

    try:
        outcome = route_message(registry, ic, text, ingest_time=time.time(), tracer=tracer)
    except Exception as exc:  # a router/handler script raised
        return DryRunResult(
            inbound=ic.name,
            disposition=MessageStatus.ERROR,
            raw=text,
            message_type=mt,
            control_id=cid,
            summary=summ,
            error=f"router/handler error: {exc}",
        )

    return DryRunResult(
        inbound=ic.name,
        disposition=disposition_for(outcome),
        raw=text,
        message_type=mt,
        control_id=cid,
        summary=summ,
        handlers=outcome.handlers,
        deliveries=outcome.deliveries,
        state_ops=outcome.state_ops,
    )


def split_messages(raw: bytes) -> list[str]:
    """Split a possibly-batched HL7 payload into individual messages on ``MSH`` boundaries.

    A real file connection delivers each ``MSH``-delimited message separately; mirror that so a
    dry-run / commit-check sees every message in a batch file, not just the first. Delegates to the
    shared :func:`messagefoundry.parsing.split.split_batch` so the live File-source ingress split
    (transports/file.py) and this dry-run / ``messagefoundry check`` path stay byte-identical.
    """
    return split_batch(raw)


def read_messages(paths: list[str]) -> list[tuple[str, str, str]]:
    """Resolve ``paths`` (files and/or directories) to ``(label, file_path, content)`` per message.

    Directories contribute their ``*.hl7`` files (sorted); batch files yield one entry per message
    (``"name [i]"``). Raises ``FileNotFoundError`` for a missing path and ``ValueError`` for a
    directory with no ``*.hl7`` files.
    """
    out: list[tuple[str, str, str]] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            files = sorted(path.glob("*.hl7"))
            if not files:
                raise ValueError(f"no *.hl7 files in {path}")
        elif path.is_file():
            files = [path]
        else:
            raise FileNotFoundError(f"no such file or directory: {path}")
        for f in files:
            messages = split_messages(f.read_bytes())
            if len(messages) == 1:
                out.append((f.name, str(f), messages[0]))
            else:
                out.extend((f"{f.name} [{i}]", str(f), m) for i, m in enumerate(messages, 1))
    return out


def read_message_sets(
    root: str | Path, inbound_names: Collection[str]
) -> list[tuple[str, str, str, str | None]]:
    """Like :func:`read_messages` but **recursive** and feed-aware, for ``messagefoundry check`` (#11).

    A fixture whose top-level subdirectory under ``root`` names an inbound connection
    (``root/IB_FOO/…``) is *pinned* to that inbound (its 4th tuple field is ``"IB_FOO"``), so it is
    dry-run only against that feed; a fixture directly under ``root``, or under a subdirectory that
    names no inbound, is *unmapped* (``None``) and the caller dry-runs it against **every** inbound —
    the all-×-all fallback. Returns ``(label, file_path, content, target_inbound | None)`` per message
    (a batch file yields one entry per message). A single-file ``root`` is one unmapped fixture.
    Raises ``FileNotFoundError`` for a missing ``root``.
    """
    names = set(inbound_names)
    root_path = Path(root)
    pairs: list[tuple[Path, str | None]] = []
    if root_path.is_dir():
        for f in sorted(root_path.rglob("*.hl7")):
            parts = f.relative_to(root_path).parts
            # parts[0] is the top-level component under root: a feed name (pin) when it's a real
            # subdir matching an inbound, else the bare filename (a top-level fixture → unmapped).
            target = parts[0] if len(parts) >= 2 and parts[0] in names else None
            pairs.append((f, target))
    elif root_path.is_file():
        pairs.append((root_path, None))
    else:
        raise FileNotFoundError(f"no such file or directory: {root_path}")
    out: list[tuple[str, str, str, str | None]] = []
    for f, target in pairs:
        messages = split_messages(f.read_bytes())
        if len(messages) == 1:
            out.append((f.name, str(f), messages[0], target))
        else:
            out.extend((f"{f.name} [{i}]", str(f), m, target) for i, m in enumerate(messages, 1))
    return out
