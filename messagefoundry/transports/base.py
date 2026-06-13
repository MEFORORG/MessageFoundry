"""Transport connector interfaces + registry.

A *source* receives inbound messages and (for request/response transports like MLLP)
returns a reply to the sender. A *destination* delivers one already-transformed payload
and either returns normally (delivered) or raises :class:`DeliveryError` (the pipeline
then reschedules per the channel's retry policy).

Connectors are keyed by :class:`~messagefoundry.config.models.ConnectorType` in a small
registry, so adding a transport never touches the channel model or the pipeline — you
register a builder here (or, later, from a plugin).
"""

from __future__ import annotations

import abc
from typing import Awaitable, Callable

from messagefoundry.config.models import ConnectorType, Destination, Source

__all__ = [
    "InboundHandler",
    "DeliveryError",
    "NegativeAckError",
    "SourceConnector",
    "DestinationConnector",
    "register_source",
    "register_destination",
    "build_source",
    "build_destination",
]

# A source hands each inbound message (raw bytes, MLLP framing already stripped) to this
# callback and sends whatever it returns back to the sender. Return ``None`` for
# fire-and-forget transports (e.g. file) that have no reply channel.
InboundHandler = Callable[[bytes], Awaitable[str | None]]


class DeliveryError(Exception):
    """A destination failed to deliver. Triggers retry/backoff in the pipeline.

    The base class is a **transport failure** (connect/IO/timeout) — transient, so the pipeline
    retries it. A *partner* rejection (a negative HL7 ACK) is the more specific
    :class:`NegativeAckError`, which the delivery worker can treat differently (permanent rejects
    fail-fast instead of blocking the lane forever). Any non-``DeliveryError`` exception escaping a
    connector's ``send`` is treated as an **internal/code error** — see the failure-policy split in
    :class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner`.
    """


class NegativeAckError(DeliveryError):
    """The partner accepted the bytes but **rejected the message** with a negative HL7 ACK.

    Distinct from a transport failure: the message reached the peer, which said no. ``code`` is the
    logical MSA-1 outcome (``"AE"`` application error / ``"AR"`` application reject — enhanced-mode
    ``CE``/``CR`` are normalized to these). ``permanent`` is ``True`` for a **reject** (``AR``/``CR``):
    the partner will never accept this message, so the worker dead-letters it immediately rather than
    holding the FIFO lane hostage to a head that can't succeed. ``AE`` (transient error) stays
    ``permanent=False`` and is retried like a transport failure.
    """

    def __init__(self, message: str, *, code: str, permanent: bool) -> None:
        super().__init__(message)
        self.code = code
        self.permanent = permanent


class SourceConnector(abc.ABC):
    """Inbound connector. ``start`` sets the source up, begins delivering received
    messages to ``handler`` in the background, and **returns once the source is live**
    (bound/listening or polling) — so a caller can rely on it being ready. ``stop`` shuts
    it down and awaits any background task it owns."""

    @abc.abstractmethod
    async def start(self, handler: InboundHandler) -> None: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...


class DestinationConnector(abc.ABC):
    """Outbound connector. ``send`` delivers one payload or raises
    :class:`DeliveryError`. ``aclose`` releases any held resources (no-op by default)."""

    @abc.abstractmethod
    async def send(self, payload: str) -> None: ...

    async def aclose(self) -> None:
        return None


# --- registry ----------------------------------------------------------------

SourceBuilder = Callable[[Source], SourceConnector]
DestinationBuilder = Callable[[Destination], DestinationConnector]

_SOURCES: dict[ConnectorType, SourceBuilder] = {}
_DESTINATIONS: dict[ConnectorType, DestinationBuilder] = {}


def register_source(kind: ConnectorType, builder: SourceBuilder) -> None:
    _SOURCES[kind] = builder


def register_destination(kind: ConnectorType, builder: DestinationBuilder) -> None:
    _DESTINATIONS[kind] = builder


def build_source(config: Source) -> SourceConnector:
    try:
        builder = _SOURCES[config.type]
    except KeyError:
        raise ValueError(f"no source connector registered for {config.type.value!r}") from None
    return builder(config)


def build_destination(config: Destination) -> DestinationConnector:
    try:
        builder = _DESTINATIONS[config.type]
    except KeyError:
        raise ValueError(f"no destination connector registered for {config.type.value!r}") from None
    return builder(config)
