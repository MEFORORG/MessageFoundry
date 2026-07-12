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
from datetime import datetime, time
from enum import Enum
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from messagefoundry.config.tls_policy import TrustAnchorPolicy


class ConnectorType(str, Enum):
    """Built-in transport connectors. Plugins may register additional values."""

    MLLP = "mllp"
    TCP = "tcp"  # raw TCP with configurable delimiter framing (X12 over TCP, ADR 0003)
    HTTP = (
        "http"  # inbound HTTP/1.1 listen source — connector-owned web-service receiver (ADR 0023)
    )
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
    EMAIL = (
        "email"  # SMTP-send outbound email destination — plain-text message via smtplib (ADR 0029)
    )
    # Direct-Project S/MIME-over-SMTP outbound destination — SIGN then ENCRYPT the PHI body to a
    # per-partner recipient cert, deliver over STARTTLS SMTP (ADR 0085, PR1 outbound only).
    DIRECT = "direct"
    # DATABASE also has an inbound poll source (DatabasePoll, ADR 0003 §3 + 0004); REMOTEFILE is both
    # source and destination. TIMER is source-only (it generates, never delivers). HTTP is the inbound
    # web-service LISTEN source (ADR 0023) — a connector-owned bound HTTP/1.1 socket, NOT a route in
    # api/ (that would break the one-way transports/ ↛ api/ rule); REST/SOAP/FHIR/DICOMWEB stay outbound
    # destinations and the inbound FHIR (#20) / DICOMweb STOW-RS (#24) facades are HTTP-source consumers.
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


class Priority(str, Enum):
    """Per-connection DR / priority tier (ADR 0048, #61). Governs **when a connection runs** (whether
    its listener binds / its connector builds in a given run of the engine under a DR run-profile),
    **never what it does** — routing/filtering stays code-first in Handlers. Layered as the same
    global-default + per-connection-override idiom proven for ``RetryPolicy`` / ``OrderingMode`` /
    per-connection retention (#34) / embedded-doc pruning (#47).

    An ``Enum`` is not orderable by default, so the tier carries an **explicit total order** (a backing
    ``rank``) so a threshold comparison is unambiguous. The total order is ``CRITICAL > NORMAL > LOW``;
    a DR run-profile starts a connection iff ``resolved.rank >= threshold.rank``. The signal is reusable
    beyond DR (load-shedding, ordered startup, alert severity), but ADR 0048 only specifies its DR
    run-profile use.
    """

    CRITICAL = "critical"
    NORMAL = "normal"
    LOW = "low"

    @property
    def rank(self) -> int:
        """The tier's place in the total order — higher = more critical. The DR run-profile compares
        ranks (``resolved.rank >= threshold.rank``) so the threshold semantics are unambiguous."""
        return {"critical": 2, "normal": 1, "low": 0}[self.value]


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


def _check_hop_attestation(attested: bool, reason: str | None) -> None:
    """Load-validate the per-connection insecure-hop attestation pair (#200, ADR 0092).

    A ``tls_hop_attested_reason`` is only meaningful alongside ``tls_hop_attested=true`` — a reason
    without the flag is a config mistake (the operator meant to attest but didn't), so it fails loud at
    load. A blank/whitespace-only reason is likewise rejected: an attestation that suppresses a would-be
    production-PHI refusal should carry a real justification for the audit trail."""
    if reason is not None and not attested:
        raise ValueError(
            "tls_hop_attested_reason is set without tls_hop_attested=true — set the flag to attest "
            "the hop is secure, or drop the reason"
        )
    if attested and reason is not None and not reason.strip():
        raise ValueError("tls_hop_attested_reason must be non-empty when provided")


class Source(BaseModel):
    """An inbound connector endpoint."""

    type: ConnectorType
    settings: dict[str, Any] = Field(default_factory=dict)
    ack_mode: AckMode = AckMode.ORIGINAL
    # Per-connection insecure-hop attestation (#200, ADR 0092): the operator affirms THIS connection's
    # transport hop is legitimately secure by other means (a proxy-terminated / trusted-segment hop),
    # so the posture-keyed hop-refusal gate ALLOWs it even on a production-PHI instance. Default False →
    # the gate keys purely on posture (every existing connection is byte-identical). A surgical opt-in
    # that replaces reliance on the blunt global MEFOR_ALLOW_INSECURE_TLS escape; audited by the cell
    # when it suppresses a would-be production refusal. `tls_hop_attested_reason` records why (audit).
    tls_hop_attested: bool = False
    tls_hop_attested_reason: str | None = None

    @model_validator(mode="after")
    def _validate_hop_attestation(self) -> Source:
        _check_hop_attestation(self.tls_hop_attested, self.tls_hop_attested_reason)
        return self


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


class StallThreshold(BaseModel):
    """When to raise a ``message_stall`` alert for an outbound lane (Corepoint "Max Message Stall"):
    the lane's **oldest undelivered message** has been waiting too long. Modeled on
    :class:`BuildupThreshold` but a single age dimension — it reuses the same oldest-pending age
    (``delivered_age``) that drives the connections dashboard, not a new metric.

    A lane crosses when its oldest pending message's age reaches ``max_oldest_seconds``. ``None`` (the
    default) **disables** the stall alert for the connection — deny-by-default/off unless an operator
    configures a threshold (it overlaps ``queue_buildup``'s age dimension, so it is opt-in to avoid
    double-paging by default). Resolution mirrors the other per-lane policies: per-connection
    ``stall=`` override > the ``[delivery]`` global default > built-in (off)."""

    max_oldest_seconds: float | None = None


class ActiveWindow(BaseModel):
    """One **active window** in a per-connection schedule (BACKLOG #147, ADR 0095).

    The window is a recurring time-of-day span on a set of weekdays, evaluated in its own IANA
    ``timezone`` (default ``UTC``) — so a feed can be scheduled in the site's local time regardless of
    the engine host's clock. ``days`` are ``datetime.weekday()`` ordinals (``0`` = Monday … ``6`` =
    Sunday). ``start``/``end`` are wall-clock times of day: a window with ``start < end`` is a same-day
    span (``[start, end)``, end-exclusive); a window with ``start > end`` **wraps past midnight** (e.g.
    ``22:00``–``06:00``) and is anchored on its **start** weekday, so the after-midnight tail belongs to
    the day the window began. ``start == end`` is rejected as ambiguous (an empty or 24-hour span — use
    a full-day window explicitly if that is meant).

    Whether being *inside* a window means the connection is **up** (an availability window) or **down**
    (a maintenance window) is decided by :attr:`Schedule.invert`, not here — a window only answers
    :meth:`contains`."""

    model_config = ConfigDict(extra="forbid")

    #: Weekdays the window's START falls on — ``datetime.weekday()`` ordinals (0=Mon … 6=Sun).
    days: frozenset[int] = Field(min_length=1)
    start: time  # inclusive local time-of-day the window opens
    end: time  # exclusive local time-of-day the window closes (wraps past midnight when <= start)
    timezone: str = "UTC"  # IANA tz name the start/end/days are evaluated in

    @field_validator("days")
    @classmethod
    def _check_days(cls, days: frozenset[int]) -> frozenset[int]:
        bad = sorted(d for d in days if d < 0 or d > 6)
        if bad:
            raise ValueError(
                f"active-window days must be datetime.weekday() ordinals 0..6 (0=Mon, 6=Sun); "
                f"got out-of-range {bad}"
            )
        return days

    @field_validator("timezone")
    @classmethod
    def _check_timezone(cls, tz: str) -> str:
        # Resolve the IANA name at load so a typo fails loud in dry-run / `messagefoundry check`,
        # not silently at the first schedule tick. ZoneInfo is stdlib (no new dependency).
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown IANA timezone {tz!r}: {exc}") from exc
        return tz

    @model_validator(mode="after")
    def _check_span(self) -> ActiveWindow:
        if self.start == self.end:
            raise ValueError(
                "active-window start and end must differ (start == end is ambiguous — use "
                "00:00..00:00 is not allowed; express a full day as a distinct start/end)"
            )
        return self

    def contains(self, now_utc: datetime) -> bool:
        """Whether ``now_utc`` (a timezone-aware UTC instant) lies within this window, evaluated in the
        window's own timezone. Same-day spans test ``start <= t < end`` on a matching weekday; a
        past-midnight span (``start > end``) matches either the evening tail on the start weekday
        (``t >= start``) OR the morning tail on the day AFTER a start weekday (``t < end``)."""
        local = now_utc.astimezone(ZoneInfo(self.timezone))
        t = local.timetz().replace(tzinfo=None)
        today = local.weekday()
        if self.start < self.end:
            return today in self.days and self.start <= t < self.end
        # Wrap past midnight: the evening portion is on the start day; the morning portion belongs to
        # the window that OPENED yesterday, so its anchor weekday is (today - 1) mod 7.
        yesterday = (today - 1) % 7
        return (today in self.days and t >= self.start) or (yesterday in self.days and t < self.end)


class Schedule(BaseModel):
    """A per-connection **active-window schedule** (BACKLOG #147, ADR 0095) the RegistryRunner honors to
    auto-start and auto-stop a connection on a time-of-day / day-of-week calendar.

    ``None`` on a connection (the default) means **always-on** — no scheduler task is created and the
    connection's lifecycle is byte-identical to before this feature. When set, the connection is
    considered *scheduled-up* whenever :meth:`is_active` is true and *scheduled-down* otherwise; the
    runner parks a scheduled-down connection with a **clean stop** (the same drain/stop the API uses,
    never a crash) and starts a scheduled-up one via the same start path.

    ``invert`` picks the polarity of the ``windows``: with ``invert=False`` (default) they are
    **availability** windows — the connection is UP *inside* any window and parked outside. With
    ``invert=True`` they are **maintenance** windows — the connection is parked *inside* any window and
    UP outside (the way to say "down every night 02:00–03:00 for the partner's maintenance")."""

    model_config = ConfigDict(extra="forbid")

    windows: list[ActiveWindow] = Field(min_length=1)
    invert: bool = False

    def is_active(self, now_utc: datetime) -> bool:
        """Whether the connection should be **up** at ``now_utc`` (a timezone-aware UTC instant). True
        when ``now_utc`` is inside some window (availability) — or OUTSIDE every window when
        ``invert`` makes the windows maintenance downtime."""
        inside = any(w.contains(now_utc) for w in self.windows)
        return (not inside) if self.invert else inside


class BatchConfig(BaseModel):
    """Opt-in per-outbound HL7 **batch aggregation** (BACKLOG #134 / ADR 0082): coalesce up to
    ``max_count`` consecutive outbound messages on this lane into ONE ``BHS``…``BTS`` envelope on a
    single send.

    The delivery worker claims the lane's contiguous FIFO head-prefix and triggers a send when **either**
    ``max_count`` rows are ready **or** the head row has waited ``max_wait_ms`` — whichever comes first
    (count-or-timeout **on the head**, so a partial batch never strands and strict FIFO never reorders).
    All N complete in one transaction. The envelope framing is **deterministic given a member set** (no
    clock — BHS-7 from the head's re-run-stable ingest time, BHS-11 from the head member's control id); a
    crash **before** the send re-runs cleanly, and a crash **after** the send re-sends the batch (which may
    coalesce newly-arrived rows into a larger envelope), so at-least-once relies on the partner being
    **per-message idempotent** (dedup by MSH-10) — the standard HL7-batch behaviour (ADR 0082).

    Constraints (enforced at wiring time, not here): **MLLP (HL7v2) outbounds only** — there is no
    BHS/BTS analogue for other transports — and **not** on a response-capturing / re-ingressing outbound
    (ADR 0013), since one batch-level ACK cannot fan out to N per-row captured replies. ``max_wait_ms``
    trades tail latency for envelope size."""

    model_config = ConfigDict(extra="forbid")

    # ge=2: framing a single message is not a batch. le=1000: an upper bound so the coalescing loop
    # (which holds the lane's processing slot for up to max_count sequential claims) can never pin a
    # slot unboundedly — a batch of 1000 messages is already very large.
    max_count: int = Field(ge=2, le=1000)
    max_wait_ms: int = Field(ge=1)  # head age-out (ms) that flushes a short batch


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
    # BACKLOG #107: opt-in per-outbound escape-hatch — emit the reserved HL7 structural separators
    # (field/component/repetition/subcomponent) as RAW bytes instead of their \F\ \S\ \R\ \T\ escape
    # sequences on serialize, for the rare partner that cannot decode HL7 escapes. Default False → every
    # existing outbound is BYTE-IDENTICAL. Enabling it DELIBERATELY produces non-conformant output (that
    # is the point); read via _dest_config from the outbound's env-resolved `hl7_raw_separators` setting
    # and applied in the MLLP connector's send() before framing (HL7v2/MLLP outbound only today).
    hl7_raw_separators: bool = False
    # Per-connection insecure-hop attestation (#200, ADR 0092) — see :class:`Source`. On an outbound the
    # attested hop is the egress crossing (e.g. a cleartext http hop into a trusted segment / a
    # proxy-terminated TLS hop): with `tls_hop_attested=true` the posture-keyed refusal gate ALLOWs it
    # even on production-PHI. Default False → keyed purely on posture (existing outbounds byte-identical).
    tls_hop_attested: bool = False
    tls_hop_attested_reason: str | None = None
    # #201 (ADR 0078 amendment): per-connection attestation that a revocation-checking PKI backs a
    # VERIFYING outbound TLS hop (MLLP-over-TLS / https REST-SOAP-FHIR). The engine performs no OCSP/CRL
    # (stdlib ssl has none), so an off-loopback production-PHI verified hop is REFUSED at construction /
    # check / dry-run unless this flag (or the blanket MEFOR_TLS_REVOCATION_ATTESTED env) is set — the
    # operator taking responsibility for revocation, exactly like the ADR 0078 in-process [api] gate.
    # Default False → keyed purely on posture (existing verifying outbounds are byte-identical). Distinct
    # from tls_hop_attested (which attests a CLEARTEXT/verify-off hop is secure by other means, #200).
    tls_revocation_attested: bool = False
    # #190 (ADR 0093): the instance-wide [tls] client trust-anchor policy, threaded by the runner's
    # _dest_config so the internal-outbound TLS context builders (MLLP/DICOM/FTPS) resolve the same
    # anchor at build_check AND live construction. Default = system/None → a no-op (the OS trust store
    # verifies the peer, byte-identical). A connection's own tls_ca_file always wins verbatim; the
    # policy only supplies the org internal CA to an internal hop that named none. NEVER disables
    # verification, so it composes with the connectors' fail-closed no-CA/verify-off/cleartext refusals.
    trust_anchor_policy: TrustAnchorPolicy = Field(default_factory=TrustAnchorPolicy)

    @model_validator(mode="after")
    def _validate_hop_attestation(self) -> Destination:
        _check_hop_attestation(self.tls_hop_attested, self.tls_hop_attested_reason)
        return self


class Validation(BaseModel):
    """Parse/validate behaviour. Tolerant by default — non-conformant messages
    still route; ``strict`` runs full hl7apy profile validation and NACKs on failure."""

    hl7_version: str | None = None  # e.g. "2.5.1"; None = infer from MSH-12
    strict: bool = False
    profile: str | None = None  # path to a conformance profile, optional
    # Wall-clock seconds a strict hl7apy validate may run before the message dead-letters (#89, DoS
    # backstop against a pathological body that makes hl7apy's structure/cardinality parse spin). A
    # slow-parse input can otherwise pin the listener; the timeout bounds it. ``None`` inherits the
    # engine default (``_STRICT_VALIDATE_TIMEOUT_SECONDS``); ``<= 0`` disables the backstop.
    strict_timeout_s: float | None = None
