# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connector configuration models — the transport-level building blocks.

A :class:`Source`/:class:`Destination` is a transport endpoint (type + free-form
``settings`` validated by the connector plugin) plus delivery behaviour. The code-first
wiring layer (:mod:`messagefoundry.config.wiring`) builds these from a connection's
``ConnectionSpec`` to resolve connectors via the registry; routing/filtering/transforming
is done in code-first Router/Handler scripts, not here.

These models are intentionally transport-agnostic: adding a new transport never requires
touching this file.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ConnectorType(str, Enum):
    """Built-in transport connectors. Plugins may register additional values."""

    MLLP = "mllp"
    TCP = "tcp"  # raw TCP with configurable delimiter framing (X12 over TCP, ADR 0003)
    FILE = "file"
    REST = "rest"  # generic HTTP destination (ADR 0003)
    DATABASE = "database"  # SQL destination — SQL Server first (ADR 0003)
    SOAP = "soap"  # SOAP / web-service destination over HTTP (ADR 0003)
    REMOTEFILE = "remotefile"  # remote-file transport — SFTP / FTP / FTPS (source + destination)
    TIMER = "timer"  # clock-driven source — emits a configured body on a schedule (source only, ADR 0011)
    X12 = "x12"  # raw-TCP X12 EDI — ISA/IEA-framed (no transport sentinel), source + destination (ADR 0012)
    LOOPBACK = "loopback"  # inert inbound — messages arrive only via ingress_handoff (re-ingress, ADR 0013)
    # DATABASE also has an inbound poll source (DatabasePoll, ADR 0003 §3 + 0004); REMOTEFILE is both
    # source and destination. TIMER is source-only (it generates, never delivers). REST/SOAP sources
    # (HTTP listeners) and TCP/FHIR are future.


class ContentType(str, Enum):
    """The payload format of an inbound connection (ADR 0004 — payload-agnostic ingress).

    ``HL7V2`` (the default, so every existing config is unchanged) gets the full HL7 peek / optional
    strict-validate / HL7-ACK ingress path and is routed to Routers/Handlers as a mutable
    :class:`~messagefoundry.parsing.message.Message`. Any other value **skips** HL7 parsing/validation/
    ACK: the decoded body is committed verbatim and routed as a
    :class:`~messagefoundry.parsing.message.RawMessage` (``.raw`` / ``.text`` / ``.json()``)."""

    HL7V2 = "hl7v2"
    JSON = "json"
    XML = "xml"
    TEXT = "text"
    X12 = "x12"  # ASC X12 EDI, relayed opaquely (no structured parse) — routes as RawMessage


class AckMode(str, Enum):
    """HL7 acknowledgement mode for MLLP/TCP sources."""

    ORIGINAL = "original"  # MSA generated from the inbound message
    ENHANCED = "enhanced"  # application + commit acks (MSH-15/16)
    NONE = "none"


class AckAfter(str, Enum):
    """**When** an inbound connection sends its ACK, in the staged pipeline (ADR 0001).

    ``INGEST`` (default): ACK-on-receipt — the ACK is sent as soon as the raw message is durably
    committed to the ingress stage, before routing/transform/delivery run (decoupling intake from a
    slow downstream). ``DELIVERED``: defer the ACK until outbound delivery succeeds (end-to-end
    confirmation). ``DELIVERED`` is **not yet implemented** in Step A — wiring it raises
    ``WiringError`` (it needs the listener to hold/replay the ACK from the delivery worker); the enum
    + threading exist so the follow-up is a small change. Distinct from
    :class:`AckMode` (which selects the ACK *code* family, not its timing)."""

    INGEST = "ingest"
    DELIVERED = "delivered"


class OrderingMode(str, Enum):
    """How an outbound connection's queue is drained.

    ``FIFO`` (default): strict in-order per outbound connection — the worker delivers the oldest
    enqueued message and **blocks the head on failure** (a stuck message holds the lane until it
    succeeds, dead-letters, or is purged) so HL7 dependencies (ADT→ORM→ORU) are never reordered.
    ``UNORDERED``: the legacy throughput mode — claim a batch and rotate past a failing message
    (a failure backs off and later messages proceed), trading order for parallelism within the
    connection.
    """

    FIFO = "fifo"
    UNORDERED = "unordered"


class InternalErrorPolicy(str, Enum):
    """What an outbound delivery worker does when an **internal/code error** (a non-``DeliveryError``
    exception escaping a connector's ``send`` — our bug, not the partner's) hits a message.

    ``CONTINUE`` (default): error-and-continue — dead-letter the offending row (replayable) and move
    on, so a code bug can't wedge the whole lane. ``STOP``: halt the connection's delivery worker and
    raise a ``connection_stopped`` alert, leaving the message queued for replay — for operators who
    would rather a lane freeze (and page someone) than auto-dead-letter on an unexpected error.
    Partner rejections (``NegativeAckError``) and transport failures are unaffected — this governs
    only the engine-internal-error case.
    """

    CONTINUE = "continue"
    STOP = "stop"


class Source(BaseModel):
    """An inbound connector endpoint."""

    type: ConnectorType
    settings: dict[str, Any] = Field(default_factory=dict)
    ack_mode: AckMode = AckMode.ORIGINAL


class RetryPolicy(BaseModel):
    """Outbound delivery retry/backoff. ``max_attempts`` is the number of delivery attempts before a
    failure dead-letters; ``None`` (the default) means **retry forever** — the conservative posture
    for transient failures (transport errors, ``AE`` NAKs), so nothing is silently lost. Under FIFO a
    forever-retrying head blocks its lane until it succeeds or an operator purges it (a permanent
    ``AR`` reject is the exception — it fails fast, see
    :class:`~messagefoundry.transports.base.NegativeAckError`). Set a finite ``max_attempts`` to opt
    back into retry-then-dead-letter."""

    max_attempts: int | None = None
    backoff_seconds: float = 5.0
    backoff_multiplier: float = 2.0
    max_backoff_seconds: float = 300.0


class BuildupThreshold(BaseModel):
    """When to raise a ``queue_buildup`` alert for an outbound lane (its backlog is not draining — a
    retry-forever head blocking the lane is the classic cause).

    A lane crosses the threshold when its **pending depth** reaches ``max_depth`` *or* its **oldest
    pending message's age** reaches ``max_oldest_seconds``. ``None`` disables that dimension; both
    ``None`` disables buildup alerting for the connection. The age dimension defaults on (a head stuck
    over five minutes is a problem in any environment); depth is opt-in (a healthy ceiling depends on
    the connection's throughput, so there's no safe universal default)."""

    max_depth: int | None = None
    max_oldest_seconds: float | None = 300.0


class Destination(BaseModel):
    """An outbound connector endpoint. Each outbound connection queues independently
    so a slow/failed one never blocks the others."""

    name: str
    type: ConnectorType
    settings: dict[str, Any] = Field(default_factory=dict)
    retry: RetryPolicy = Field(default_factory=RetryPolicy)
    # Shadow / parallel-run mode (#15): when True the delivery worker runs the full pipeline + count-
    # and-log but SUPPRESSES the real egress (no bytes/SQL leave the box) and finalizes the message
    # PROCESSED, so a shadow instance can process real traffic without double-delivering to live
    # partners. A deployment-wide [shadow].simulate_all_egress forces this on for every outbound.
    simulate: bool = False


class Validation(BaseModel):
    """Parse/validate behaviour. Tolerant by default — non-conformant messages
    still route; ``strict`` runs full hl7apy profile validation and NACKs on failure."""

    hl7_version: str | None = None  # e.g. "2.5.1"; None = infer from MSH-12
    strict: bool = False
    profile: str | None = None  # path to a conformance profile, optional
