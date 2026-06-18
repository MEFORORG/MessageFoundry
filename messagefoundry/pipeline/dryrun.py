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
from typing import Any

from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.models import ContentType
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.wiring import (
    HandlerFn,
    InboundConnection,
    Registry,
    Send,
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
from messagefoundry.store import MessageStatus

__all__ = [
    "DeliveryPreview",
    "StateOpPreview",
    "RouteOutcome",
    "DryRunResult",
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


def _handler_names(result: list[str] | str | None) -> list[str]:
    if result is None:
        return []
    return [result] if isinstance(result, str) else list(result)


def _partition(
    result: Send | SetState | list[Send | SetState] | None,
) -> tuple[list[Send], list[SetState]]:
    """Split a Handler's return into its (deliveries, state writes) — ADR 0005.

    A Handler may now return :class:`Send`\\ s and/or :class:`SetState`\\ s (a single value, a mixed
    list, or ``None``). ``Send``-only returns yield ``([...], [])`` — backward compatible."""
    if result is None:
        return [], []
    items = result if isinstance(result, list) else [result]
    sends = [it for it in items if isinstance(it, Send)]
    state_ops = [it for it in items if isinstance(it, SetState)]
    return sends, state_ops


def _payload(raw: str | bytes, content_type: str) -> Message | RawMessage:
    """The object a Router/Handler receives (ADR 0004): a mutable HL7 :class:`Message` for ``hl7v2``,
    or a verbatim :class:`RawMessage` (``.raw``/``.text``/``.json()``) for any other ``content_type``."""
    if content_type == ContentType.HL7V2.value:
        return Message.parse(raw)
    return RawMessage(raw if isinstance(raw, str) else raw.decode("utf-8"), content_type)


@dataclass(frozen=True)
class DeliveryPreview:
    """What a Handler would deliver to an outbound connection (no send happens)."""

    to: str
    payload: str


@dataclass(frozen=True)
class StateOpPreview:
    """A state write a Handler would declare (ADR 0005) — captured for the dry-run, applied nowhere.

    ``value`` is the would-be-stored value; it may carry PHI (e.g. an MRN→anon mapping), so the CLI
    gates it behind ``--show-phi`` exactly like a delivery payload."""

    namespace: str
    key: str
    value: Any


@dataclass(frozen=True)
class RouteOutcome:
    """The result of running a Router + its Handlers (without validation/disposition)."""

    handlers: list[str]  # handler names the Router selected ([] = routed nowhere)
    deliveries: list[DeliveryPreview]
    state_ops: list[StateOpPreview] = field(default_factory=list)  # declared writes (ADR 0005)

    @property
    def routed(self) -> bool:
        return bool(self.handlers)


def route_only(registry: Registry, ic: InboundConnection, raw: str | bytes) -> list[str]:
    """Run ``ic``'s Router and return the handler name(s) it selected (``[]`` = routed nowhere).

    The **router half** of the split routing core (ADR 0001 Step B): it decides *which* handlers take
    the message but runs no transform. Every selected handler is validated to exist — a router naming
    an unknown handler (typo / renamed / removed handler) fails closed **here** (``ValueError``) rather
    than producing a routed-stage row no transform worker can run; on the live path the router worker
    dead-letters/NAK-equivalents it, and dry-run / ``messagefoundry check`` surface the bad name
    (review M-7). The live engine's router worker calls this; the combined :func:`route_message` does too.
    """
    route = registry.routers[ic.router]
    names = _handler_names(route(_payload(raw, ic.content_type.value)))
    for hname in names:
        if hname not in registry.handlers:
            raise ValueError(f"router {ic.router!r} returned unknown handler {hname!r}")
    return names


def transform_one(
    registry: Registry, hname: str, raw: str | bytes, content_type: str = ContentType.HL7V2.value
) -> tuple[list[DeliveryPreview], list[StateOpPreview]]:
    """Run **one** Handler on its own freshly-built payload; return ``(deliveries, state_ops)``.

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
    """
    handle: HandlerFn = registry.handlers[hname]
    sends, ops = _partition(handle(_payload(raw, content_type)))
    deliveries: list[DeliveryPreview] = []
    for send in sends:
        if send.to not in registry.outbound:
            raise ValueError(f"handler {hname!r} sent to unknown outbound connection {send.to!r}")
        payload = send.message if isinstance(send.message, str) else send.message.encode()
        deliveries.append(DeliveryPreview(to=send.to, payload=payload))
    state_ops = [StateOpPreview(namespace=op.namespace, key=op.key, value=op.value) for op in ops]
    return deliveries, state_ops


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
    # Activate the same run-scoped providers the live engine uses (via the shared run_context registry),
    # so router + handlers resolve identically here and in the staged engine. Dry-run runs router and
    # transform in one block, so it uses the transform (superset) phase; it has no live environment, so
    # active_environment=None — current_environment() then returns None, exactly as when dry-run left the
    # environment unset. A provider that needs live infrastructure (db_lookup) refuses to run here.
    with run_contexts(
        RunContext(
            code_sets=registry.code_sets,
            reference_view=sim_reference,
            state_view=sim_state,
            active_environment=None,
            ingest_time=ingest_time,
        ),
        phase="transform",
    ):
        names = route_only(registry, ic, raw)
        ct = ic.content_type.value
        for hname in names:
            ds, ops = transform_one(registry, hname, raw, ct)
            deliveries.extend(ds)
            for op in ops:
                sim_state[(op.namespace, op.key)] = op.value  # visible to subsequent handlers
            state_ops.extend(ops)
    return RouteOutcome(handlers=names, deliveries=deliveries, state_ops=state_ops)


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


def _dry_run_raw(registry: Registry, ic: InboundConnection, raw: str | bytes) -> DryRunResult:
    """Dry-run a non-HL7 inbound (ADR 0004): no HL7 peek/validate; route the body as a RawMessage."""
    text = raw if isinstance(raw, str) else raw.decode("utf-8")
    try:
        outcome = route_message(registry, ic, text, ingest_time=time.time())
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


def dry_run(registry: Registry, raw: str | bytes, *, inbound: str | None = None) -> DryRunResult:
    """Parse → (strict-validate) → route one message, returning disposition + would-send payloads.

    Mirrors the engine's disposition logic with **no side effects**.
    """
    ic = select_inbound(registry, inbound)
    if ic.content_type is not ContentType.HL7V2:
        return _dry_run_raw(registry, ic, raw)
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
        outcome = route_message(registry, ic, text, ingest_time=time.time())
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
