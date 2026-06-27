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

from collections.abc import Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
    PT = "passthrough"  # internal pass-through inbound — a Handler Sends here; its own router re-routes (ADR 0013 generalized)
    FHIR = "fhir"  # FHIR REST destination — POST/PUT a resource or transaction Bundle to a server (ADR 0022)
    DIMSE = "dimse"  # raw DICOM upper-layer — C-STORE SCP source + C-STORE SCU/C-ECHO destination (ADR 0025)
    DICOMWEB = "dicomweb"  # DICOMweb STOW-RS over HTTP — outbound store/send destination (ADR 0025 Phase 2)
    # DATABASE also has an inbound poll source (DatabasePoll, ADR 0003 §3 + 0004); REMOTEFILE is both
    # source and destination. TIMER is source-only (it generates, never delivers). REST/SOAP sources
    # (HTTP listeners) and TCP are future. (FHIR is destination-only here; its inbound facade is ADR 0023.)
    # DIMSE is the C-STORE SCP source (gated by the TCP egress arm as a raw socket) AND the C-STORE SCU
    # destination; DICOMWEB is the STOW-RS destination (gated by the HTTP egress arm, like REST/SOAP/FHIR).
    # An inbound DICOMweb (STOW-RS) receiver is destination-only here — it awaits the HTTP listener (ADR 0023).


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
    FHIR = (
        "fhir"  # HL7 FHIR JSON — routed as RawMessage; parsed on demand via parsing/fhir (ADR 0022)
    )
    BINARY = "binary"  # opaque byte payload — base64-carried over the str/TEXT substrate (ADR 0028)
    DICOM = "dicom"  # DICOM Part-10 object (binary) — base64-carried; parsed on demand via parsing/dicom (ADR 0025)

    @property
    def is_binary(self) -> bool:
        """Whether an inbound of this type carries **raw bytes** that must be base64-carried at the
        source boundary (ADR 0028) rather than decoded as text — a ``NUL``/non-UTF-8 body would be
        rejected (Postgres) or silently truncated (SQLite/SQL Server) by the ``str``/TEXT store.
        Byte-oriented codecs (DICOM, …) join this set; everything else routes as decoded text."""
        return self in _BINARY_CONTENT_TYPES


#: Content types whose inbound bodies are raw bytes, carried as base64 per ADR 0028. Kept as a set so
#: a byte-oriented codec (e.g. DICOM) opts in by adding its member — see :attr:`ContentType.is_binary`.
_BINARY_CONTENT_TYPES: frozenset[ContentType] = frozenset({ContentType.BINARY, ContentType.DICOM})


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


class SignatureAlgorithm(str, Enum):
    """JWS algorithm for opt-in per-connection outbound message signing (ASVS 4.1.5, ADR 0018) and for
    the SMART Backend Services ``client_assertion`` JWT (ADR 0024).

    All are produced with the **core** ``cryptography`` dependency (no new package). ``RS256``/``RS384``
    (RSASSA-PKCS1-v1_5) are **deterministic** — the same key + payload always yields the same signature;
    ``PS256`` (RSASSA-PSS) and ``ES256``/``ES384`` (ECDSA) are **randomized** (a fresh signature per
    call, like the WS-Security nonce, ADR 0015). ``RS384``/``ES384`` (SHA-384) are the two algorithms
    SMART Backend Services **SHALL** support for the client-assertion JWT (ADR 0024); the rest are
    SHA-256."""

    RS256 = "RS256"  # RSASSA-PKCS1-v1_5 + SHA-256 (RSA key; deterministic)
    PS256 = "PS256"  # RSASSA-PSS + SHA-256 (RSA key; randomized)
    ES256 = "ES256"  # ECDSA P-256 (secp256r1) + SHA-256 (EC key; randomized)
    RS384 = "RS384"  # RSASSA-PKCS1-v1_5 + SHA-384 (RSA key; deterministic) — SMART Backend Services (ADR 0024)
    ES384 = "ES384"  # ECDSA P-384 (secp384r1) + SHA-384 (EC key; randomized) — SMART Backend Services (ADR 0024)


class OutboundSigning(BaseModel):
    """Opt-in per-connection message signing for a **REST/SOAP outbound** (ASVS 4.1.5, ADR 0018).

    OFF unless configured. When set, the connector mints a **detached JWS** (RFC 7515 Appendix F) over
    the exact outbound payload bytes in ``send()`` — past the queue boundary, like the WS-Security
    timestamp/nonce (ADR 0015), so a retry re-mints it and routers/transforms stay pure — and carries it
    in the ``header_name`` HTTP header. The receiver verifies it against the matching **public** key,
    out-of-band per partner contract (the signing code's :func:`verify` counterpart does this). RSA
    (``RS256``/``PS256``) or ECDSA (``ES256``) via the core ``cryptography`` library — no new dependency.

    ``private_key`` is the signing key as **inline PEM** *(use* :func:`~messagefoundry.config.wiring.env`
    *for the secret)* **or a path to a PEM file** (the file, like a TLS key, is protected by OS perms).
    Put every secret — an inline key, or ``private_key_password`` for an encrypted key — in ``env()`` so
    it is never stored in config. The key never leaves the box; only the public-verifiable signature does.

    Authored code-first with :func:`~messagefoundry.transports.signing.with_signing` over a ``Rest()`` /
    ``Soap()`` spec, or assembled from flat ``sign_*`` connector settings via :meth:`from_settings`."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    algorithm: SignatureAlgorithm = SignatureAlgorithm.RS256
    private_key: str  # inline PEM (use env() for the secret) or a path to a PEM private-key file
    private_key_password: str | None = None  # passphrase for an encrypted key (secret — use env())
    key_id: str | None = None  # JWS 'kid' so the receiver can select the verifying key
    header_name: str = "X-JWS-Signature"  # the HTTP header that carries the detached JWS

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> OutboundSigning | None:
        """Build from flat ``sign_*`` connector settings, or ``None`` when signing isn't configured.

        Signing is OFF (``None``) unless ``sign_private_key`` is present, so every existing outbound is
        unchanged. The flat keys (vs a nested table) keep each value a top-level setting that ``env()``
        resolution and ``connections.toml`` decoding already handle. Recognized keys: ``sign_enabled``,
        ``sign_algorithm``, ``sign_private_key``, ``sign_private_key_password``, ``sign_key_id``,
        ``sign_header``. An unknown/typo'd field raises (``extra='forbid'``)."""
        key = settings.get("sign_private_key")
        if not key:
            return None
        data: dict[str, Any] = {"private_key": key}
        if "sign_enabled" in settings:
            data["enabled"] = settings["sign_enabled"]
        if settings.get("sign_algorithm"):
            data["algorithm"] = settings["sign_algorithm"]
        if settings.get("sign_private_key_password"):
            data["private_key_password"] = settings["sign_private_key_password"]
        if settings.get("sign_key_id"):
            data["key_id"] = settings["sign_key_id"]
        if settings.get("sign_header"):
            data["header_name"] = settings["sign_header"]
        return cls.model_validate(data)


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
    # ASVS 4.1.5 (ADR 0018): opt-in per-connection detached-JWS signing for REST/SOAP outbound. None
    # (the default) = OFF — every existing outbound is byte-identical. Assembled from the env-resolved
    # sign_* settings by the runner's _dest_config; the connector mints the signature in send().
    sign: OutboundSigning | None = None


class Validation(BaseModel):
    """Parse/validate behaviour. Tolerant by default — non-conformant messages
    still route; ``strict`` runs full hl7apy profile validation and NACKs on failure."""

    hl7_version: str | None = None  # e.g. "2.5.1"; None = infer from MSH-12
    strict: bool = False
    profile: str | None = None  # path to a conformance profile, optional
