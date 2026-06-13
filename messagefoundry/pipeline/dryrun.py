"""Dry-run a wiring Registry against messages — pure routing/handling, no I/O.

Runs a message through an inbound connection's Router and Handler(s) exactly as the engine would,
but with **no store, connectors, network, or ACK** — capturing the routing decision, the disposition
(RECEIVED/UNROUTED/FILTERED/ERROR), and the payload each Handler *would* send. This powers the IDE
Test Bench and the ``dryrun`` CLI. The routing core (:func:`route_message`) is shared with the live
engine (:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner`) so both route identically.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from messagefoundry.config.models import ContentType
from messagefoundry.config.wiring import HandlerFn, InboundConnection, Registry, Send
from messagefoundry.parsing import (
    HL7PeekError,
    Message,
    Peek,
    RawMessage,
    normalize,
    summarize,
    validate,
)
from messagefoundry.store import MessageStatus

__all__ = [
    "DeliveryPreview",
    "RouteOutcome",
    "DryRunResult",
    "route_message",
    "route_only",
    "transform_one",
    "disposition_for",
    "dry_run",
    "select_inbound",
    "read_messages",
    "split_messages",
]

log = logging.getLogger(__name__)


def _handler_names(result: list[str] | str | None) -> list[str]:
    if result is None:
        return []
    return [result] if isinstance(result, str) else list(result)


def _sends(result: Send | list[Send] | None) -> list[Send]:
    if result is None:
        return []
    return [result] if isinstance(result, Send) else list(result)


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
class RouteOutcome:
    """The result of running a Router + its Handlers (without validation/disposition)."""

    handlers: list[str]  # handler names the Router selected ([] = routed nowhere)
    deliveries: list[DeliveryPreview]

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
) -> list[DeliveryPreview]:
    """Run **one** Handler on its own freshly-built payload and return what it would send.

    The **transform half** of the split routing core (ADR 0001 Step B): a single handler, its own
    payload (a :class:`Message`, or a :class:`RawMessage` when ``content_type`` is non-HL7 — so one
    handler's transforms can't leak into another's), with every ``Send`` target validated against the
    outbound registry. An unknown outbound fails closed **here** (``ValueError``): an undeliverable
    target would otherwise enqueue an outbound row no worker drains (silent accept-and-strand). The
    caller guarantees ``hname`` is registered (:func:`route_only` validated it); the live engine's
    transform worker calls this per routed-stage row.
    """
    handle: HandlerFn = registry.handlers[hname]
    deliveries: list[DeliveryPreview] = []
    for send in _sends(handle(_payload(raw, content_type))):
        if send.to not in registry.outbound:
            raise ValueError(f"handler {hname!r} sent to unknown outbound connection {send.to!r}")
        payload = send.message if isinstance(send.message, str) else send.message.encode()
        deliveries.append(DeliveryPreview(to=send.to, payload=payload))
    return deliveries


def route_message(registry: Registry, ic: InboundConnection, raw: str | bytes) -> RouteOutcome:
    """Run ``ic``'s Router then the named Handlers; return what they selected and would send.

    Convenience recomposition of :func:`route_only` + :func:`transform_one` for the dry-run / Test
    Bench / CLI preview, which want the whole routing outcome in one shot. The live **staged** engine
    instead runs the two halves at *separate* stages (router worker → transform worker), so it and the
    dry-run path route identically. Each handler still gets its own :class:`Message` (via
    :func:`transform_one`). Router/Handler exceptions propagate to the caller.
    """
    names = route_only(registry, ic, raw)
    ct = ic.content_type.value
    deliveries = [d for hname in names for d in transform_one(registry, hname, raw, ct)]
    return RouteOutcome(handlers=names, deliveries=deliveries)


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
        outcome = route_message(registry, ic, text)
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
        outcome = route_message(registry, ic, text)
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
    )


def split_messages(raw: bytes) -> list[str]:
    """Split a possibly-batched HL7 payload into individual messages on ``MSH`` boundaries.

    A real file connection delivers each ``MSH``-delimited message separately; mirror that so a
    dry-run / commit-check sees every message in a batch file, not just the first.
    """
    text = normalize(raw)  # \r-delimited
    # Split before each non-leading MSH segment. Match `\rMSH` without the field separator so a
    # batch whose MSH-1 isn't `|` (e.g. `MSH^...`) still splits per-message instead of parsing as
    # one giant message — after \r a segment id is always 3 chars, so only MSH starts with "MSH".
    chunks = re.split(r"(?=\rMSH)", text)
    messages = [c.lstrip("\r") for c in chunks if c.strip()]
    return messages or [text]


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
