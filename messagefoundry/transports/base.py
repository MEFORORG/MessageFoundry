# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import ClassVar, Protocol

from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source

# Re-exported, not defined here: the matcher moved to the neutral, stdlib-only
# ``messagefoundry.netaddr`` so the operator-surface allow-list
# ([security].allowed_client_networks, enforced in API middleware) can share ONE matcher and one
# CIDR syntax with the per-connection source_ip_allowlist. The API must not import transports/ and
# transports/ must not import api/, so the shared leaf lives at the package root. The five connector
# call sites (mllp/tcp/x12/dicom/http_listener) keep importing it from here, unchanged.
from messagefoundry.netaddr import peer_ip_allowed

__all__ = [
    "InboundHandler",
    "ConnectionEventSink",
    "IntakeAuditSink",
    "IntakeRateLimiter",
    "ProcessedFileLedger",
    "DeliveryError",
    "NegativeAckError",
    "SourceStartupError",
    "TestNotSupportedError",
    "DeliveryResponse",
    "SourceConnector",
    "DestinationConnector",
    "register_source",
    "register_destination",
    "build_source",
    "build_destination",
    "peer_ip_allowed",
    "probe_tcp_reachable",
]

# A source hands each inbound message (raw bytes, MLLP framing already stripped) to this
# callback and sends whatever it returns back to the sender. Return ``None`` for
# fire-and-forget transports (e.g. file) that have no reply channel.
InboundHandler = Callable[[bytes], Awaitable[str | None]]

# A source emits connection-lifecycle / transport events (Corepoint-style log, #46) to this OPTIONAL,
# store-agnostic sink: ``(kind, peer_host, reason)``. The runner injects it after build and binds the
# connection name + transport + direction; the source only knows the wire-level facts. ``None`` (the
# default) makes every emit site a no-op (byte-identical when off). Metadata only — never a raw frame
# or message body; the source passes a ``safe_exc``-scrubbed reason and the store scrubs again (#120).
ConnectionEventSink = Callable[[str, str | None, str | None], Awaitable[None]]

# A source reports an intake-authentication refusal to this OPTIONAL, store-agnostic sink (ADR 0154
# D6): ``(action, client, detail)``. The runner injects an adapter that writes a tamper-evident
# ``audit_log`` row binding the connection; the source knows only the wire-level facts.
#
# Why this exists alongside :data:`ConnectionEventSink`, which already carries the same refusal:
# ``connection_event`` is operator-disableable diagnostics, while ``audit_log`` is a hash chain an
# operator cannot silently switch off — and an authentication refusal on a PHI intake socket belongs
# in the record that survives someone turning diagnostics off.
#
# **No credential material ever crosses this seam** — not the value, not a prefix, not its length.
# ``detail`` carries the mode and the outcome only.
IntakeAuditSink = Callable[[str, str | None, str | None], Awaitable[None]]


class IntakeRateLimiter(Protocol):
    """The failed-attempt budget an intake-authenticating source consults (ADR 0154 D6).

    Injected by the runner as a **synchronous** predicate so ``transports/`` gains no ``auth/`` edge,
    and synchronous is honest: the underlying sliding window completes without awaiting, so it is
    atomic on the event loop.

    The three methods exist separately because the budget is charged on **failure only**. Consulting
    and charging in one call — which is what the shipped ``allow()`` does — would turn a
    brute-force bound into a per-peer throughput cap, silently refusing an authenticated partner's
    traffic pre-ingress, where it is not even counted.
    """

    def check(self, peer: str) -> bool:
        """Whether ``peer`` may make another attempt. **Read-only** — never records one."""
        ...

    def charge_failure(self, peer: str) -> None:
        """Record one FAILED attempt against ``peer``. Called only on the refusal branch."""
        ...

    def note_success(self, peer: str) -> None:
        """Record that ``peer`` authenticated successfully within the current window.

        This is what keeps the global arm from denying a legitimate partner (AC-19): a global
        failed-attempt budget refuses irrespective of key, so without this an attacker generating
        refusals from any address would exhaust the shared budget and lock out a peer that is
        authenticating correctly.
        """
        ...


class ProcessedFileLedger(Protocol):
    """The store-backed **process-in-place dedup ledger** a leave-in-place (``after_read='leave'``) poll
    source uses (ADR 0129, BACKLOG #142). The runner injects an adapter closing over the store + the
    inbound's channel id; the source passes only a **HASHED** ``file_key`` (a derived id — sha256 of the
    file's path + mtime/size), so ``transports/`` never imports the store and **no cleartext path crosses
    the seam** (a filename/path can embed an MRN). ``None`` on the source means no durable ledger (a
    direct caller / test), and the connector falls back to a bounded in-process cache. Same
    runtime-injection shape as :data:`ConnectionEventSink`.
    """

    async def is_processed(self, file_key: str) -> bool:
        """True iff this connection already ingested the file with this hashed ``file_key``."""
        ...

    async def mark_processed(self, file_key: str) -> None:
        """Record this file as ingested — called AFTER a successful emit (the file is the dedup unit)."""
        ...

    async def prune(self) -> None:
        """Bound the ledger's growth (age + count). Called at most once per poll tick, only when a new
        file was recorded, so a stable read-only share never churns the store."""
        ...


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

    ``credential_fault`` (BACKLOG #109, ADR 0095) marks a permanent failure that is a **bad
    credential / would lock out the partner account** (an auth rejection), as opposed to a bad
    *message*. The delivery worker treats it specially under the ``credential_fault_policy`` — STOP the
    lane and retain the backlog un-errored rather than dead-letter each queued row and hammer the
    partner's auth (which could trip an account lockout). Only meaningful when ``permanent`` is True.
    """

    def __init__(
        self, message: str, *, code: str, permanent: bool, credential_fault: bool = False
    ) -> None:
        super().__init__(message)
        self.code = code
        self.permanent = permanent
        self.credential_fault = credential_fault


class TestNotSupportedError(Exception):
    """A connector has no external resource to probe, so ``test_connection`` is a no-op it can't
    perform (e.g. a TIMER source, or a listen source that is already bound). Distinct from a
    :class:`DeliveryError` (a real reachability/auth failure) so the API can report "not supported"
    separately from "unreachable"."""

    __test__ = False  # not a pytest test class despite the "Test" prefix


class SourceStartupError(Exception):
    """A source's **opt-in at-start validation** (:meth:`SourceConnector.validate_startup`) failed — a
    File/RemoteFile connection whose ``validate_directory`` toggle is on, pointed at a directory that is
    **missing or unusable** at start (BACKLOG #114). Raised from the runner's bind path so ADR 0031
    isolates the connection as ``failed`` at start, instead of the default run-time deferral (a scan
    that logs-and-retries every poll). Distinct from :class:`DeliveryError` (a delivery outcome)."""


def encode_wire_body(payload: str, encoding: str, *, transport: str) -> bytes:
    """Encode an outbound payload to the bytes that go on the wire (or to disk), failing CONTENT-FREE.

    A bare ``payload.encode(encoding)`` raises ``UnicodeEncodeError``, which is a **``ValueError``** —
    so a connector's ``except (TimeoutError, OSError)`` does not catch it, and in several connectors
    the encode sits outside the ``try`` entirely. It escapes ``send()`` to the delivery worker's
    generic handler, which persists ``internal error: {safe_exc(exc)}`` into **``queue.last_error``**
    *and* **``message_events.detail``** — plaintext on a default (``IdentityCipher``) store. And
    ``str(UnicodeEncodeError)`` **names the offending character**::

        UnicodeEncodeError: 'ascii' codec can't encode character '\\xe9' in position 137

    That character is a character of the *message*: PHI, or a credential once a config secret can
    reach the body. ``safe_exc``/``redact`` scrub HL7 *shapes* and have no notion of either.

    So this names the codec and the **position** — an index, never the content — and raises
    ``from None``: the chained ``UnicodeEncodeError`` carries ``.object``, which is the **entire
    payload**, so any handler that walks ``__cause__`` would resurrect what we just refused to log.

    **Permanent** because it is: the same bytes will never encode on a retry, so it dead-letters
    rather than looping the lane forever. (``direct.py`` already had the right instinct — it catches
    ``ValueError`` around its encode and reports ``type(exc).__name__`` only — but it maps to a
    *transient* error, so an un-encodable body retries there instead of dead-lettering.)"""
    try:
        return payload.encode(encoding)
    except UnicodeEncodeError as exc:
        raise NegativeAckError(
            f"{transport}: payload is not encodable as {encoding!r} "
            f"(first offending character at position {exc.start})",
            code="encoding",
            permanent=True,
        ) from None


# The closed vocabulary for a captured reply's outcome (ADR 0013). Kept here, beside the transport
# contract, because the transport is what derives it (MLLP MSA-1, HTTP status, SOAP fault).
RESPONSE_OUTCOMES = frozenset({"accepted", "rejected", "unparseable", "no_reply"})


@dataclass(frozen=True)
class DeliveryResponse:
    """A captured reply from a request/response destination (ADR 0013 Increment 1).

    A capturing ``send`` returns one of these instead of ``None``; a non-capturing ``send`` returns
    ``None`` exactly as before (byte-identical). The transport hands back the **already-derived**
    outcome it computed anyway (the MSA-1 family, the HTTP status, a SOAP fault) so the store never
    re-parses the encrypted-at-rest body to reconstruct it.

    * ``body`` — the partner's reply text, already decoded by the transport (PHI; encrypted at rest).
    * ``outcome`` — one of :data:`RESPONSE_OUTCOMES`. ``accepted`` (a positive reply), ``rejected`` (a
      partner ``<Fault>``/negative content on an otherwise-OK transport), ``unparseable`` (a reply
      frame **was received** but its content could not be parsed — **never** "no reply was received",
      which is a retryable :class:`DeliveryError`), or ``no_reply`` (a successful round-trip with a
      deliberately empty payload — e.g. an empty 2xx).
    * ``detail`` — a short, possibly-PHI reason (``MSA-1=AA``, ``HTTP 201``); encrypted at rest.
    * ``headers`` — a captured **allow-listed** subset of the reply's HTTP response headers (BACKLOG
      #154, ADR 0013 amendment 2026-07-12). Empty ``{}`` by default (every non-HTTP / non-configured
      destination is byte-identical). Only the per-connection ``capture_response_headers`` names are
      ever captured (PHI gate: a partner reply header could carry sensitive data, so it is opt-in by
      name — never all headers). This is a **captured external value** (like the ``fhir_lookup``
      read-only carve-out): it is read off the wire at delivery and, unlike a pure transform output,
      reflects the partner's reply at that pass — the capture itself is deterministic per reply
      (the same names off the same reply → the same dict), so it re-ingresses re-run-stably from the
      immutable stored copy. Surfaced to a re-ingressed answer's Handler via
      ``response_get(dest).headers`` (ADR 0013 Increment 2).
    """

    body: str
    outcome: str
    detail: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)


class SourceConnector(abc.ABC):
    """Inbound connector. ``start`` sets the source up, begins delivering received
    messages to ``handler`` in the background, and **returns once the source is live**
    (bound/listening or polling) — so a caller can rely on it being ready. ``stop`` shuts
    it down and awaits any background task it owns.

    :attr:`polls_shared_resource` documents whether the source **polls a shared external
    resource** (a directory, a DB table, a remote dir) — intake that must be **single-node** in a
    cluster, since two nodes polling it would ingest the same file/row twice. It is ``False`` by
    default (a **listen** source like MLLP/TCP, which has its own per-node endpoint and no
    double-read problem) and set ``True`` on the poll sources. It is documentation + lets a caller
    log/identify poll sources; the actual single-node gating is done by ``leader_gate`` below."""

    # Documentation flag (see the class docstring): True on poll sources, False on listen sources.
    polls_shared_resource: ClassVar[bool] = False

    #: Optional connection-event sink (Corepoint-style log, #46), **injected by the runner after build**
    #: (not a builder arg, not a settings value — same runtime-injection shape as ``leader_gate`` is
    #: passed). A listen source (MLLP/TCP) calls it on accept / refuse / close; ``None`` (the default)
    #: makes every emit site a no-op, so a poll/file source that never sets it is byte-identical. Keeping
    #: it an injected awaitable keeps ``transports/`` free of any ``store``/``pipeline`` import.
    on_connection_event: ConnectionEventSink | None = None

    #: The inbound's declared payload format (ADR 0004), **injected by the runner after build** (same
    #: runtime-injection shape as ``on_connection_event`` — not a builder arg, since the transport
    #: :class:`~messagefoundry.config.models.Source` config carries no content_type; that lives on the
    #: wiring's ``InboundConnection``). A content-sniffing poll source (RemoteFileSource) uses it to
    #: gate the HL7-header quarantine to ``hl7v2`` drops only, so a legitimate X12/DICOM/binary drop is
    #: not wrongly rejected. ``None`` (the default) = unset → no content gating, so a direct caller /
    #: test that never sets it is byte-identical.
    content_type: ContentType | None = None

    #: Optional runner-injected process-in-place dedup ledger (ADR 0129, BACKLOG #142), backed by the
    #: store's ``processed_files`` table. A leave-in-place (``after_read='leave'``) poll source uses it to
    #: record each file it has ingested (by a HASHED key — never a cleartext filename) and skip it on a
    #: later poll, so a read-only share whose files another system owns can be polled without moving or
    #: deleting them. ``None`` (the default) = no durable ledger (a direct caller / test) → the source
    #: falls back to an in-process set. Same runtime-injection shape as :attr:`on_connection_event`;
    #: ``transports/`` stays store-agnostic.
    processed_ledger: ProcessedFileLedger | None = None

    #: Optional intake-authentication audit sink (ADR 0154 D6), **injected by the runner after build**
    #: — same runtime-injection shape as :attr:`on_connection_event`, and for the same reason: it keeps
    #: ``transports/`` free of any ``store`` import while still letting a refusal reach the
    #: tamper-evident ``audit_log``. ``None`` (the default) makes the emit site a no-op, so a direct
    #: caller or test that never sets it is byte-identical.
    on_intake_audit: IntakeAuditSink | None = None

    #: Optional intake-auth failed-attempt budget (ADR 0154 D6), **injected by the runner after build**.
    #: A synchronous predicate, so ``transports/`` gains no ``auth/`` edge. ``None`` (the default)
    #: disables rate limiting entirely — a direct caller or test is byte-identical, and an operator who
    #: sets ``intake_auth_rate_limit=None`` gets the same.
    intake_rate_limiter: IntakeRateLimiter | None = None

    @abc.abstractmethod
    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Begin delivering received messages to ``handler``; return once live.

        ``leader_gate`` is an **optional** predicate returning ``True`` when THIS node may poll a
        **shared external resource** (Track B Step 4b leader-gating). ``None`` (the default) means
        *always poll* — the single-node / direct-caller / test path, byte-identical to before the
        gate existed. A **poll** source (:attr:`polls_shared_resource` True) must SKIP its
        scan/select-and-process for a tick whenever the gate returns ``False`` (so only the leader
        reads the shared resource); the loop keeps ticking, so when this node later becomes leader
        the next tick scans. A **listen** source (MLLP/TCP) ignores it: it runs on every node."""
        ...

    @abc.abstractmethod
    async def stop(self) -> None: ...

    async def validate_startup(self) -> None:
        """Optional **opt-in** at-start validity check for the source's external resource, run by the
        runner in ``_start_inbound_unsafe`` right before the bind (BACKLOG #114). The **default is a
        no-op** — validation stays deferred to run time (byte-identical: a poll source that can't reach
        its resource logs-and-retries every poll rather than failing start). A poll source (FILE/
        REMOTEFILE) overrides it to **fail-fast** when its ``validate_directory`` setting is on: a
        missing/unusable directory raises :class:`SourceStartupError`, which the caller isolates as
        ADR-0031 ``failed`` at start. Unlike :meth:`test_connection` (the on-demand ``POST
        /connections/{name}/test`` probe, which may **create** the watch directory), this check must
        **not** create anything — a merely-missing directory must FAIL, not be fabricated and pass."""
        return None

    async def test_connection(self) -> None:
        """Probe the source's external resource for reachability — sending NO real data and writing no
        message — for the ``POST /connections/{name}/test`` API. Returns on success; raises
        :class:`DeliveryError` (or a subclass) on a connectivity/auth failure; raises
        :class:`TestNotSupportedError` (the default) when there is nothing external to probe (a listen
        source like MLLP/TCP is already bound; a TIMER source has no resource). Poll/dial-out sources
        (DATABASE, FILE, REMOTEFILE) override this with a real probe (a FILE probe may create the
        watch directory, as a real run would)."""
        raise TestNotSupportedError(f"{type(self).__name__} does not support connection testing")


class DestinationConnector(abc.ABC):
    """Outbound connector. ``send`` delivers one payload or raises :class:`DeliveryError`.

    ``send`` returns ``None`` for a one-way delivery (the default for every non-capturing outbound —
    byte-identical to before ADR 0013). A **response-capturing** outbound returns a
    :class:`DeliveryResponse` carrying the partner's reply; the delivery worker persists it inside the
    same transaction that marks the row done. ``aclose`` releases any held resources (no-op by default).

    ``metadata`` (BACKLOG #68) is this message's read-only **user** metadata bag (the ADR 0081 ``SetMeta``
    writes, decrypted), or ``None``. It rides the message as pure DATA — the delivery worker supplies it
    only when :attr:`consumes_metadata` is set, so the default path is byte-identical and pays no read.
    A connector interprets it for a per-message transport knob (the REST/FHIR destinations project
    ``http.header.*`` entries onto per-message request headers); every other connector ignores it.
    """

    #: Whether this connector wants the per-message user-metadata bag passed to :meth:`send` (#68). Left
    #: ``False`` by default so the delivery worker skips the metadata read entirely (byte-identical); a
    #: connector that consumes per-message metadata (REST/FHIR with ``dynamic_headers``) sets it ``True``.
    consumes_metadata: bool = False

    @abc.abstractmethod
    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None: ...

    async def aclose(self) -> None:
        return None

    async def test_connection(self) -> None:
        """Probe the downstream peer for reachability — sending NO real payload and writing no message
        — for the ``POST /connections/{name}/test`` API. Returns on success; raises
        :class:`DeliveryError` (or a subclass) on a connectivity/auth failure; raises
        :class:`TestNotSupportedError` (the default) when this destination can't be probed without
        delivering. Most destinations override this (a socket connect / ``SELECT 1`` / ``HEAD``); a
        FILE/REMOTEFILE probe may create the target directory, exactly as a real delivery would."""
        raise TestNotSupportedError(f"{type(self).__name__} does not support connection testing")


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


async def probe_tcp_reachable(host: str, port: int, timeout: float, label: str) -> None:
    """Open a TCP connection to ``host:port`` and immediately close it — a no-data reachability probe
    shared by the socket destinations (MLLP/TCP/X12) for ``test_connection``. Raises
    :class:`DeliveryError` if the connect fails or times out."""
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (TimeoutError, OSError) as exc:
        raise DeliveryError(f"{label} connect to {host}:{port} failed: {exc}") from exc
    writer.close()
    try:  # noqa: SIM105
        await writer.wait_closed()
    except OSError:
        pass
