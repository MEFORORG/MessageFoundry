# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Response schemas for the localhost API.

These are the wire contract the console (and any other client) sees — deliberately
separate from the internal SQLite rows and channel-config models so storage/runtime
changes don't leak into the API. Message *list* responses carry metadata only; the raw
body (PHI) appears only in the single-message detail view, which is audited.

A model that carries a PHI *property* subclasses :class:`~messagefoundry.api.phi_gate.PhiGatedModel`
and declares it in ``phi_gated_properties``: the property is then withheld from JSON until
:func:`~messagefoundry.api.field_authz.redact_unauthorized` releases what the caller may see, so a
route that forgets that call denies rather than exposes (BACKLOG #1045). Which permission unlocks
which property stays in :mod:`messagefoundry.api.field_authz`; the two are pinned to each other by
``tests/test_field_authz_fail_closed.py``.
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field

from messagefoundry.api.phi_gate import PhiGatedModel
from messagefoundry.api.validation import (
    MAX_EXPORT_IDS,
    MAX_MAP_ENTRIES,
    ConnectionName,
    ControlIdFilter,
    DisplayLabel,
    EmailAddress,
    FilesystemPath,
    IdempotencyKey,
    LogLevelName,
    MessageTypeFilter,
    ResourceId,
    SearchText,
    StatusFilter,
)
from messagefoundry.config.ai_policy import (
    AiDataScope,
    AiMode,
    DataClass,
    SecurityEnforcement,
)


class ChannelInfo(BaseModel):
    id: str
    name: str
    enabled: bool
    running: bool
    source_type: str
    destinations: list[str]


class MessageSummary(PhiGatedModel):
    # Withheld from JSON until released (BACKLOG #1045). MessageDetail INHERITS this declaration,
    # which is deliberate: a future subclass of a PHI-bearing model is gated by default.
    phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"summary", "error", "metadata"})

    id: str
    channel_id: str
    received_at: float
    source_type: str | None
    control_id: str | None
    message_type: str | None
    status: str
    error: str | None
    event: str | None = None  # latest processing event (received/delivered/failed/dead/replayed)
    summary: str | None = None  # ingest-derived: MRN/name (+ order/accession for ORM/ORU)
    metadata: str | None = None  # code/operator-attached values (mechanism TBD)


class MessageList(BaseModel):
    total: int
    limit: int
    offset: int
    messages: list[MessageSummary]


class MessageSearchResults(BaseModel):
    """Result of a scan-and-decrypt content search (ADR 0046 #51). ``messages`` are the matched message
    summaries (metadata only — same shape + PHI redaction as ``MessageList``, never a decrypted body).
    ``scanned`` is how many candidate rows were decrypted; ``matched`` the number that matched (==
    ``len(messages)`` before the result cap); ``truncated`` is True when the scan stopped at the
    ``scan_limit`` ceiling before exhausting the candidate set — the "narrow your filters" signal."""

    messages: list[MessageSummary]
    scanned: int
    matched: int
    truncated: bool
    limit: int
    scan_limit: int


class MessageSearchRequest(BaseModel):
    """The POST body for content search and for export's search-mode selection (BACKLOG #1184).

    ASVS 14.2.1 asks that sensitive data reach the server in the body or the headers and never in the
    URL. ``content`` and ``field_value`` are whatever an operator typed to find a patient, so they are
    PHI-shaped, and a query string is copied verbatim into the engine's access log, the reverse proxy's
    log and browser history -- none of which the log redactor can reach. They therefore live HERE and
    nowhere else. The rest of the criteria travel with them: a model split across a body and a query
    string is the arrangement that lets the next PHI-shaped field land on the URL by default.

    ``field_path`` is the one criterion that also stays on the GET. It is a structural locator
    (``PID-3``), not a value, which is why the search audit records it verbatim while never recording
    the needle -- so a presence-test search keeps a plain, bookmarkable URL.

    ``scan_limit`` is ``None`` for "the engine default": the ceiling constants live in
    :mod:`messagefoundry.store.content_search`, and importing them here would drag the engine into
    every process that imports these models (ADR 0088 keeps the apiclient engine-free), so the route
    resolves the default and enforces the ceiling instead of the field doing it.

    ``field_path`` carries a length bound only, and deliberately so: its grammar is
    :func:`messagefoundry.parsing.peek.parse_path`, applied eagerly by
    :func:`messagefoundry.store.content_search.make_spec` at every acceptance point, so a malformed
    path is already a 4xx. A pattern here would be a second definition of a rule that has one.
    """

    content: SearchText | None = None
    field_path: str | None = Field(None, max_length=32)
    field_value: SearchText | None = None
    target: Literal["raw", "summary", "both"] = "both"
    channel_id: ConnectionName | None = None
    status: StatusFilter | None = None
    message_type: MessageTypeFilter | None = None
    control_id: ControlIdFilter | None = None
    limit: int = Field(50, ge=1, le=500)
    scan_limit: int | None = Field(None, ge=1)


class MessageExportRequest(MessageSearchRequest):
    """The POST body for ``/messages/export`` (BACKLOG #1184). Adds the explicit ``ids`` selection (the
    console's *save-selected*) beside the inherited search criteria (*save-all*), and raises ``limit``
    to the export route's own ceiling."""

    ids: list[ResourceId] = Field(default_factory=list, max_length=MAX_EXPORT_IDS)
    limit: int = Field(1000, ge=1, le=100_000)


class UploadedMessageSearchRequest(BaseModel):
    """The POST body for browsing an uploaded file's split messages (BACKLOG #1184). The uploaded-log
    browse takes no channel/status filter and pages with ``offset``, so it is a sibling of
    :class:`MessageSearchRequest` rather than a subclass of it."""

    content: SearchText | None = None
    field_path: str | None = Field(None, max_length=32)
    field_value: SearchText | None = None
    target: Literal["raw", "summary", "both"] = "both"
    message_type: MessageTypeFilter | None = None
    control_id: ControlIdFilter | None = None
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0)


class OutboxInfo(PhiGatedModel):
    phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"last_error"})

    id: str
    destination_name: str
    status: str
    attempts: int
    next_attempt_at: float
    last_error: str | None


class EventInfo(PhiGatedModel):
    phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"detail"})

    ts: float
    event: str
    destination: str | None
    detail: str | None


class AttachmentInfo(BaseModel):
    """Metadata for one very-large document detached from a message into the content-addressed
    attachment substrate (#149, ADR 0105 Phase 3b). **Metadata only — never the document bytes**: ``id``
    is the sha256 content address (the store's ``attachment.id``), ``content_type`` the declared MIME/ED
    type, ``total_bytes`` the reconstructed document size. The bytes are pulled on demand from the
    audited, PHI-gated ``GET /messages/{message_id}/attachments/{id}`` download endpoint."""

    id: str  # sha256 content address (attachment.id)
    content_type: str
    total_bytes: int


class MessageDetail(MessageSummary):
    """Full single-message view, including the raw body and delivery/audit trail."""

    raw: str
    outbox: list[OutboxInfo]
    events: list[EventInfo]
    # Very-large documents detached from this message at ingress (#149, ADR 0105 Phase 3b). Metadata
    # only (id/content_type/total_bytes) — the bytes ride the audited per-attachment download endpoint.
    # Defaulted so an older client (or a message with no detached document) deserializes unchanged.
    attachments: list[AttachmentInfo] = Field(default_factory=list)


class CapturedResponseInfo(PhiGatedModel):
    """One captured request/response reply (ADR 0013). ``outcome``/``detail`` are visible with the
    message-read permission; ``body`` is PHI and populated only when the caller also holds the raw-body
    permission (``None`` otherwise, and ``None`` once retention has purged it)."""

    phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"detail"})

    destination_name: str
    response_seq: int
    outcome: str
    detail: str | None
    captured_at: float
    body: str | None = None


class MessageResponses(BaseModel):
    """The captured-reply history for one message (ADR 0013), ordered by destination then seq."""

    message_id: str
    responses: list[CapturedResponseInfo]


class OutboundPayloadInfo(BaseModel):
    """One outbound delivery's **transformed payload** (#14 parity tool). ``payload`` is the PHI body
    MEFOR routed/transformed for ``destination_name``; it is returned in full only to a caller holding
    ``MESSAGES_VIEW_RAW``, and every access is audited. (Distinct from :class:`OutboxInfo`, which is
    the body-free delivery *metadata* shown in the message-detail view.)"""

    destination_name: str
    status: str
    payload: str


class OutboundPayloads(BaseModel):
    """The transformed outbound payloads for one message — one entry per destination (#14). Populated
    on both simulate/shadow and live runs (the transformed payload is retained on the done outbound
    row in either mode), enabling the ``tee compare`` parity check against Corepoint's output."""

    message_id: str
    payloads: list[OutboundPayloadInfo]


class ReplayResult(BaseModel):
    message_id: str
    requeued: int


class ResendRequest(BaseModel):
    """Resend a stored message's transformed body to an ALTERNATE outbound (ADR 0090, BACKLOG #123).

    ``to`` is the alternate outbound connection; ``source`` (optional) names which delivered
    destination's stored body to copy when the origin fanned out to several (omit when there was one).
    ``idempotency_key`` makes a retry a no-op — a *new* key is a genuine second resend. Values carry
    the connection-name rule (BACKLOG #1108), so an over-long or structurally impossible name is
    refused before it can reach a store query (ASVS 1.3.3, 2.1.1)."""

    to: ConnectionName  # the alternate outbound connection
    idempotency_key: IdempotencyKey
    source: ConnectionName | None = None  # source delivery to copy the body from


class ResendResult(BaseModel):
    """The outcome of a resend. ``status`` is ``"resent"`` (a new delivery was queued to ``to`` at the
    lane tail) or ``"duplicate"`` (the ``idempotency_key`` was already used — no new delivery). Carries
    ids only, never a body."""

    message_id: str
    status: str  # "resent" | "duplicate"
    to: str
    source: str
    outbox_id: str | None = None


class EditResendRequest(BaseModel):
    """Edit a stored message and resubmit the edited body (ADR 0090 §9, BACKLOG #153).

    The edit is CLIENT-SIDE + EPHEMERAL: the console holds the editable copy until this POST — nothing
    edited is stored as a server-side draft. ``raw`` is the operator's edited body (PHI — bounded, and
    NEVER echoed in a 4xx: a validation failure is stripped by the ``RequestValidationError`` handler).
    ``reroute`` (default) re-ingresses ``raw`` as a fresh correlated ``RECEIVED`` message on the ORIGIN
    channel — the normal router→transform→outbound pipeline. ``to`` (optional power-path) instead
    delivers the edited body DIRECTLY to that alternate outbound (reusing #123's resend seam); when set
    it overrides ``reroute``. ``idempotency_key`` makes a retry a no-op — a *new* key is a genuine second
    resubmit. The ORIGINAL message stays byte-identical either way."""

    # ``raw`` is a MESSAGE BODY — the data plane. It keeps a size bound and no alphabet rule: an HL7
    # v2 body is separated by carriage returns and may carry any encoding the sender used, so the
    # control-plane printable rule (BACKLOG #1108) must not reach it.
    raw: str = Field(min_length=1, max_length=16_000_000)  # the edited body (PHI — never echoed)
    idempotency_key: IdempotencyKey
    reroute: bool = True
    to: ConnectionName | None = None  # optional direct alternate outbound (power-path)


class EditResendResult(BaseModel):
    """The outcome of an edit-and-resubmit (ADR 0090 §9). ``status`` is ``"resubmitted"`` (re-route:
    a new correlated child was ingressed) / ``"resent"`` (direct: a new outbound row) / ``"duplicate"``
    (the ``idempotency_key`` was already used — no new work). ``new_message_id`` is the correlated child
    (re-route) and ``outbox_id``/``to`` the direct delivery. Carries ids only, never a body."""

    message_id: str  # the ORIGIN (unchanged)
    status: str  # "resubmitted" | "resent" | "duplicate"
    reroute: bool
    new_message_id: str | None = None  # the re-ingressed correlated child (re-route path)
    to: str | None = None  # the alternate outbound (direct path)
    outbox_id: str | None = None  # the direct delivery's queue row


class PurgeResult(BaseModel):
    cancelled: int


class DeadLetterRow(PhiGatedModel):
    """One dead-lettered delivery (a message→destination that exhausted its retries)."""

    phi_gated_properties: ClassVar[frozenset[str]] = frozenset({"summary", "last_error"})

    outbox_id: str
    message_id: str
    channel_id: str
    destination_name: str
    attempts: int
    last_error: str | None
    failed_at: float  # when the delivery was dead-lettered (outbox.updated_at)
    control_id: str | None
    message_type: str | None
    received_at: float
    summary: str | None = None  # PHI-bearing (MRN/name); display is audited


class DeadLetterList(BaseModel):
    total: int
    limit: int
    offset: int
    dead_letters: list[DeadLetterRow]


class ConnectionEventInfo(BaseModel):
    """One connection/transport event (Corepoint-style log, #46) — **metadata only, no PHI**: the
    connection name, transport, direction, event kind, peer IP, and a scrubbed reason. Read via the
    ``monitoring:read``-gated ``GET /events`` / ``GET /connections/{name}/events`` routes."""

    id: int
    ts: float
    connection: str
    transport: str
    direction: str  # 'inbound' | 'outbound'
    kind: str
    peer_host: str | None = None
    message_id: str | None = None
    reason: str | None = None


class AlertInstanceInfo(BaseModel):
    """One resolvable operator-alert instance (ADR 0044, #56) — **metadata only, no PHI**: the alert
    type, connection label, severity, lifecycle status (open/acknowledged/resolved), the
    first/last-seen window + occurrence count, a scrubbed reason, and the ack/resolve audit fields.
    Read via the ``monitoring:diagnose``-gated ``GET /alerts/active`` route."""

    id: int
    event_type: str
    connection: str
    severity: str
    status: str  # 'open' | 'acknowledged' | 'resolved'
    first_seen: float
    last_seen: float
    count: int
    reason: str | None = None
    acked_by: str | None = None
    acked_at: float | None = None
    resolved_at: float | None = None
    # #143 — windowed NOTIFICATION-mute end-epoch (None/past = not suspended). Notification-only: a
    # suspended instance stays open/counted (it is still returned by GET /alerts/active).
    suspended_until: float | None = None


class AlertSuspendRequest(BaseModel):
    """Body for ``POST /alerts/{id}/suspend`` (#143) — the length of the NOTIFICATION-mute window. The
    window end is ``now + minutes·60``; the instance keeps firing into state (stays open/counted) — only
    re-alerts are silenced for the window. ``POST /alerts/{id}/resume`` takes no body."""

    # Bounded so an operator can't set an unbounded / absurd window; 1 minute .. 30 days.
    minutes: float = Field(gt=0, le=43200)


class AlertInstanceList(BaseModel):
    """The active (open + acknowledged) operator-alert instances, newest ``last_seen`` first (ADR 0044)."""

    alerts: list[AlertInstanceInfo]


class DeadLetterReplayRequest(BaseModel):
    # Connection names; they carry the connection-name rule so a value that could not name a
    # connection never reaches the store query (ASVS 1.3.3, 2.1.1 — BACKLOG #1108).
    channel_id: ConnectionName | None = None  # scope replay to one inbound (None = all)
    destination_name: ConnectionName | None = None  # scope to one outbound (None = all)


class DeadLetterReplayResult(BaseModel):
    requeued: int


class PendingApprovalResponse(BaseModel):
    """Returned (HTTP 202) when a high-value action is held for dual-control approval (ASVS 2.3.5)
    instead of executing inline. A distinct second approver must release it via ``/approvals``."""

    approval_id: str
    operation: str
    status: str = "pending_approval"
    detail: str


class PendingApprovalInfo(BaseModel):
    """One open (still-pending, unexpired) approval request in the approver's queue."""

    id: str
    operation: str
    label: str
    requester: str
    requested_at: float
    expires_at: float | None = None


class ApprovalList(BaseModel):
    approvals: list[PendingApprovalInfo]


class ApprovalDecisionResult(BaseModel):
    """The outcome of approving or rejecting a pending request. On approval, ``result`` carries the
    executed operation's summary (e.g. ``{"requeued": 3}``)."""

    operation: str
    requested_by: str
    approved_by: str | None = None
    rejected_by: str | None = None
    result: dict[str, Any] | None = None


class ReloadRequest(BaseModel):
    # Directory of code-first config modules to load + apply. Optional: omitted/None reloads the
    # server's startup --config dir. Any value must resolve within an allowed reload root (the
    # startup dir or [api].config_reload_roots) — the loader executes Python from it. Length-bounded
    # (ASVS 1.3.3); the allow-list confinement remains the real control.
    config_dir: FilesystemPath | None = None
    # dry_run: validate the graph against THIS environment (loads + build-checks connectors, which
    # resolves env() values for the target) and report the result WITHOUT swapping the live graph.
    # The promote pre-flight: catch a missing env value / bad spec before it goes live.
    dry_run: bool = False


class ReloadResult(BaseModel):
    """Summary of the graph that is now live after a reload — or, for a dry run, the graph that
    *would* go live (``dry_run=True``; ``running`` then reflects the still-current graph)."""

    inbound: int
    outbound: int
    routers: int
    handlers: int
    running: bool
    dry_run: bool = False


class ConfigProvenance(BaseModel):
    """Provenance of the config graph the engine currently has loaded (ADR 0041 D1): the content
    ``fingerprint`` and best-effort git ``git_head`` captured at load, plus whether the on-disk config
    has since **drifted** from it. Read-only and non-secret — a one-way content hash and a commit sha,
    never resolved ``env()`` / ``MEFOR_VALUE_*`` values. ``loaded`` is False before any graph is loaded
    (or if the fingerprint could not be computed); ``drift`` is only meaningful when ``loaded`` is True."""

    loaded: bool
    fingerprint: str | None = None  # content hash of the loaded bundle (scheme mefor-cfg-fp:v1)
    git_head: str | None = None  # commit sha at load, when the config dir is a git work tree
    files: int | None = None  # number of files folded into the fingerprint
    drift: bool = False  # the on-disk config now differs from what was loaded


class ConnectionRow(BaseModel):
    """One endpoint (a channel's source, or one of its destinations) for the connections
    dashboard. Fields are role-dependent: source rows carry read/inbound-errored/idle and the
    listen peer/port; destination rows carry queue/written/dead/backlog/delivered-age and the
    remote peer/port. Unused fields are None so the UI can render blanks."""

    role: str  # "source" | "destination"
    channel_id: str
    channel_name: str
    destination: str | None  # destination name; None for the source row
    name: str  # display name
    status: str  # "running" | "stopping" (outbound: operator-paused, an in-flight head still draining) | "stopped" (outbound: paused AND quiesced) | "failed" (start failed, ADR 0031) | "filtered" (DR run-profile parked it below [dr].priority_threshold, #61 ADR 0048) | "draining" | "not_deployed" (present in the graph but deployed=false, #233 ADR 0111 — never wired, deploying it is a config change; distinct from "stopped", which SHOULD be running)
    direction: str  # "in" (source) | "out" (destination)
    method: str  # connection method/protocol, e.g. MLLP / File / TCP / REST
    peer: str | None  # MLLP host or file directory
    port: int | None
    queue_depth: int | None
    idle_seconds: float | None
    alerts_active: int  # count of OPEN alert instances for this connection (ADR 0044, #56)
    errored: int | None  # source: inbound errors; destination: dead-lettered
    read: int | None  # source only: inbound received
    written: int | None  # destination only: delivered
    backlog_seconds: float | None  # destination only; None = unknown/stalled
    delivered_age_seconds: float | None  # destination only; age of oldest queued item
    simulated: bool | None = None  # destination only; True = egress-suppressed shadow lane (#15)
    # Destination-only operator-pause flag (connection controls). True = the outbound is operator-paused
    # AND fully quiesced (delivery stopped, zero in-flight), so its queue may be purged. Deliberately
    # INDEPENDENT of the collapsed display ``status`` above: a failed/filtered-but-paused outbound shows
    # status "failed"/"filtered" yet stays purge-eligible (``paused`` True). ``False`` for source rows and
    # for a running or still-"stopping" (not-yet-quiesced) outbound.
    paused: bool = False
    error: str | None = (
        None  # set when status == "failed" (why it failed to start, ADR 0031) or "filtered" (why the DR run-profile parked it, #61 ADR 0048)
    )
    # Destination-only, sharded deployments only (ADR 0073): the engine shard that owns claiming/
    # delivery for this outbound lane. None when unsharded (every lane is local) or for source rows.
    # Lets an operator watching a backlog on one shard's view see WHICH shard is responsible for
    # draining it (controls/purge for a non-owned lane 409 with the same owner).
    owner_shard: str | None = None
    # #131 (ADR 0007 amendment): the operator "object of interest" flag for the Flagged Objects filter.
    # Display-only (no runtime effect); True when the connection is marked flagged. Console-settable via
    # POST /connections/{name}/flag on a connections.toml-managed connection only. Additive + defaulted
    # so an older client deserializes /connections unchanged.
    flagged: bool = False
    # #131: whether this connection is authored in connections.toml (vs code-first). The console shows
    # the flag TOGGLE only on TOML-managed rows (the write seam persists there); a code-first row shows a
    # read-only flag indicator. The API refuses the toggle on a non-TOML connection regardless (the guard
    # of record). Additive + defaulted.
    toml_managed: bool = False
    # #136 (ADR 0065 amendment): destination-only per-message "Waiting for Reply" display state — True
    # while this outbound's live connector is awaiting an MLLP ACK past its waiting_display_delay. DISPLAY
    # ONLY (no delivery effect); False for source rows, non-ACK-waiting connectors, and no-ack mode.
    # Additive + defaulted so an older client deserializes /connections unchanged.
    waiting_for_reply: bool = False


class ConnectionFlagRequest(BaseModel):
    """Body for ``POST /connections/{name}/flag`` (#131, ADR 0007 amendment) — the FIRST
    console→connections.toml write seam. ``direction`` disambiguates a name declared as both an inbound
    and an outbound. Display-only; the write is refused (409) on a code-first connection (no TOML home)."""

    flagged: bool
    direction: Literal["inbound", "outbound"]


class StatsResetTarget(BaseModel):
    """One connections-dashboard endpoint to reset, matching a row's (role, channel_id, destination).
    For ``source`` rows ``destination`` is ignored; for ``destination`` rows it is required."""

    role: Literal["source", "destination"]
    channel_id: ConnectionName
    destination: ConnectionName | None = None


class StatsResetRequest(BaseModel):
    """Reset the dashboard's cumulative counters for ``targets``, or for every connection (``all``)."""

    all: bool = False
    targets: list[StatsResetTarget] = Field(default_factory=list, max_length=MAX_MAP_ENTRIES)


class StatsResetResult(BaseModel):
    reset: int  # number of connection endpoints whose dashboard counters were reset


class StatsResponse(BaseModel):
    outbox_by_status: dict[str, int]
    # NOT-DONE rows (pending|inflight) across every stage (ingress + routed + outbound) — a
    # whole-pipeline drain gauge, vs outbox_by_status which sees only the outbound stage. Defaults to 0
    # so a client reading an older engine (no field) degrades gracefully.
    in_pipeline: int = 0
    # B11 connection-scale observability (read-only, additive): cumulative count of EMPTY claims — a
    # stage worker (router/transform/delivery) that claimed its lane and found it empty (a wasted DB
    # round-trip). Split into idle-poll re-SELECTs vs the per-commit wake-fanout (thundering herd); the
    # connection-scale report plots the herd slope (empty_claims_wake_fanout) distinctly from the
    # idle-poll floor. All default 0, so a client reading an older engine degrades gracefully and an
    # engine the harness never measures is byte-identical.
    empty_claims: int = 0
    empty_claims_idle_poll: int = 0
    empty_claims_wake_fanout: int = 0
    # BACKLOG #1270: claim ROUND-TRIPS the store aborted on a lock timeout. The operator-visible half
    # of that item: without it, a lane that has stopped claiming reads from outside exactly like an
    # idle system with no work. The split above classifies why the WORKER was awake and is
    # structurally blind to why the STORE returned nothing; this is the store-side axis.
    #
    # PER ATTEMPT, NOT PER LANE, AND IT NAMES NO LANE. Deliberately outside the empty_claims_* family
    # because it is a DIFFERENT UNIT: those three count lanes, this counts round-trips, and one
    # aborted 256-lane chunk adds 256 there and 1 here. Dividing one by the other is meaningless. The
    # claim's transaction rolled back before a row was read, so "at least one row this claim needed
    # was held" is the whole of what the store knows — which lane, and how many, are not knowable.
    # (#1270's first attempt shipped a per-lane field, name and log line that asserted otherwise.)
    #
    # ZERO IS NOT A CLEAN BILL, for two independent reasons. It is POOLED-MODE ONLY — the per-lane
    # workers never call claim_fifo_heads, so a per-lane engine reports zero forever. And only the
    # SQL Server 1222 yield produces the event at all: Postgres claims with FOR UPDATE SKIP LOCKED,
    # which does not abort, and SQLite's single-writer lock makes the case unobservable. Zero
    # therefore means NOT ESTABLISHED; do not render it as "no contention" — that is the empty-scan-
    # versus-clean-scan conflation this repo keeps meeting.
    claim_lock_timeouts: int = 0
    # B11 wall #1 (executor saturation): the default ThreadPoolExecutor's submit-queue depth + in-flight
    # ("busy") count — observable ONLY when the connection-scale harness installs its default-sized boot
    # shim (loop.set_default_executor); ``None`` on a normal engine (no shim), so production /stats is
    # byte-identical. The router/transform workers run route_only/transform_one via asyncio.to_thread on
    # that shared pool, so queue_depth > 0 means the pool is saturated (the wall).
    executor_queue_depth: int | None = None
    executor_busy: int | None = None
    # A1 live cost counters (read-only, additive): cumulative physical transactions committed
    # (``committed_txns`` — the 3+2H+2N-per-message cost-model currency, ADR 0051) and raw/payload body
    # strings durably written (``body_copies`` — the 2+H+N-per-message amplification) since store open.
    # Both default 0 so a client reading an older engine (no field) degrades gracefully; the Postgres
    # backend reports 0 (counting is wired on SQLite + SQL Server).
    committed_txns: int = 0
    body_copies: int = 0
    # ADR 0157 C3: terminal queue resolves rejected by the H1 leader-epoch fence (Postgres only; 0
    # elsewhere). Non-zero == a superseded ex-leader was stopped mid-write. MUST be declared here:
    # this model takes Pydantic's default extra='ignore', so an undeclared kwarg is dropped SILENTLY
    # and /stats would never grow the field.
    fenced_writes: int = 0


class MetricsHistorySample(BaseModel):
    """One point-in-time metrics sample for the console trend charts (BACKLOG #76, ADR 0065 amendment).
    ``ts`` is epoch seconds; ``outbox_by_status`` is the outbound-row count by status at that instant.
    Aggregate counts only — **never** a message field or body (no PHI)."""

    ts: float
    outbox_by_status: dict[str, int] = Field(default_factory=dict)


class MetricsHistoryResponse(BaseModel):
    """A bounded, in-memory ring of :class:`MetricsHistorySample` for the console trend charts (#76).
    Oldest-first; fed by the existing ~1s ``/ws/stats`` sampler (no durable table — ``store_schema``
    stays false — and no PHI). ``capacity`` is the ring's maximum retained sample count."""

    samples: list[MetricsHistorySample] = Field(default_factory=list)
    capacity: int = 0


class GraphNode(BaseModel):
    """One node in the by-name data-flow graph (BACKLOG #76, ADR 0065 amendment). ``kind`` is one of
    ``inbound``/``router``/``handler``/``outbound``; ``status`` is the LIVE connection status for an
    inbound/outbound node (``running``/``stopping``/``stopped``/``failed``/``filtered``/``draining``/
    ``not_deployed``) and ``None`` for a router/handler node. Names + status only — no PHI. The colour a
    console derives from ``status`` is live-derived, never operator-assigned (that is BACKLOG #79)."""

    name: str
    kind: str
    status: str | None = None


class GraphEdge(BaseModel):
    """One directed edge ``source`` → ``target`` in the data-flow graph (BACKLOG #76). ``provenance`` is
    ``declared``/``literal``/``heuristic`` (from :func:`messagefoundry.config.graph.build_wiring_graph`)."""

    source: str
    source_kind: str
    target: str
    target_kind: str
    provenance: str


class GraphResponse(BaseModel):
    """The static by-name wiring graph (BACKLOG #76, ADR 0065 amendment): the Registry edge set from
    :func:`messagefoundry.config.graph.build_wiring_graph` with each connection node's LIVE status joined
    in. Read-only (``monitoring:read``); it constructs **no** ``channel``/``route`` bundling object
    (CLAUDE.md §1) and carries **no** message body. ``dynamic`` lists the ``kind:name`` elements whose
    full target set is not statically resolvable (their edge list may be incomplete — surfaced, never
    silently dropped)."""

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    dynamic: list[str] = Field(default_factory=list)


class Health(BaseModel):
    status: str = "ok"
    # WP-L3-07 (ASVS 13.4.6): the build version is a fingerprinting detail, disclosed only to an
    # authenticated caller. A tokenless liveness probe gets ``status`` with ``version`` omitted/None.
    version: str | None = None
    # The client address the ENGINE observes for this request, echoed ONLY when
    # [security].allowed_client_networks is in use (None — and omitted from nothing else — by default,
    # so a stock deployment's /health is unchanged). ``/health`` is exempt from the network gate
    # precisely so a locked-out operator can curl it and read this: it is the one self-service answer
    # to "which address is the engine actually matching?", which also immediately exposes a reverse
    # proxy or NAT that is rewriting the source. Disclosing the caller's own address to the caller
    # reveals nothing it does not already know.
    observed_client: str | None = None


class EngineInfo(BaseModel):
    version: str
    uptime_seconds: float
    pid: int
    channels_total: int
    channels_running: int
    channels_stopped: int
    outbox_by_status: dict[str, int]


class EngineKpis(BaseModel):
    """Engine-wide TOP-LINE roll-up KPIs (#93) — the single-glance headline no per-connection metric
    gives, surfaced first-class on ``/status`` (and the console Engine Status page + the #75 dashboard).

    ``messages_total`` is the total messages the engine has received (store-wide, process lifetime);
    ``connections_total`` / ``connections_running`` / ``connections_stopped`` combine **both** inbound
    and outbound endpoints (vs :class:`EngineInfo`.channels_*, which count inbound only);
    ``messages_per_second`` is the engine-wide drain rate, derived by **reusing the same
    ``recent_done`` rate window** that already powers the dashboard's per-destination backlog ETA (no
    second sampler). Additive + defaulted so an older client deserializes ``/status`` unchanged.

    ``connections_not_deployed`` (#233, ADR 0111) counts endpoints present in the graph but
    ``deployed=false`` — never wired, never a lane. Such a connection is deliberately EXCLUDED from
    ``connections_total`` (it is in the registry but is not a lane), so the running/stopped split keeps
    counting only lanes and the ``connections_stopped == connections_total - connections_running``
    identity holds unchanged. Without the exclusion, a not-deployed connection would inflate
    ``connections_stopped`` and read as "should be running, isn't" — the exact confusion this state
    exists to remove."""

    messages_total: int = 0
    connections_total: int = 0  # DEPLOYED inbound + outbound endpoints (not-deployed excluded)
    connections_running: int = 0
    connections_stopped: int = 0
    connections_not_deployed: int = 0  # #233: present in the graph, deployed=false; not a lane
    messages_per_second: float = 0.0  # engine-wide, from recent_done / rate_window


class DbInfo(BaseModel):
    path: str
    size_bytes: int  # db file + -wal + -shm
    disk_free_bytes: int
    journal_mode: str
    messages: int
    events: int
    audit: int
    # SQLite durability mode (PRAGMA synchronous): "normal" (shipped default) or "full"; None on the
    # server backends (a SQLite-only knob). Read-only observability (B7) so a status reader / load run
    # records which durability mode it measured. Defaulted so older clients deserialize unchanged.
    synchronous: str | None = None


class LogInfo(BaseModel):
    """App-log storage metering for the configured ``[logging].log_dir`` (#50), mirroring
    :class:`DbInfo`'s DB-side ``size_bytes`` / ``disk_free_bytes``. **Metadata only — never any log
    content** (no PHI). Present only when a log directory is configured; when the engine logs to stdout
    (captured off-process by NSSM) the ``logs`` field on :class:`SystemStatus` is ``None``."""

    path: str
    size_bytes: int  # total bytes of regular files under the log directory (one level)
    disk_free_bytes: int  # free space on the log directory's filesystem


class LogLevelInfo(BaseModel):
    """Runtime log-verbosity state (BACKLOG #171, ADR 0130). ``level`` is the current effective root
    level; ``configured`` is the startup ``[logging].level`` baseline a restart returns to; ``levels`` is
    the accepted set for the control. **Not PHI** — level names only."""

    level: str
    configured: str | None = None
    levels: list[str]


class LogLevelUpdate(BaseModel):
    """PATCH body for the runtime verbosity control (BACKLOG #171): the new root/uvicorn level. Ephemeral
    — the override resets on process restart, and NOT on ``/config/reload`` (ADR 0130 §1)."""

    # The authority for which names are legal is ``logging_setup.LOG_LEVELS``, which the route calls
    # and 4xxs on; this only fixes the shape (BACKLOG #1108).
    level: LogLevelName


class LogTailPage(BaseModel):
    """One page of the **redacted** application-log tail for the in-console viewer (BACKLOG #171, ADR
    0130). ``lines`` are already passed through ``support.redact`` (HL7/DOB/name + secret spans scrubbed),
    oldest-first within the page; ``offset`` counts lines back from the END of the newest log file and
    ``total_lines`` is that file's line count, so the viewer can page. ``available`` is False when no
    ``[logging].log_dir`` is configured or no readable log file exists (the viewer degrades gracefully).
    Best-effort redaction — a residual single-token identifier can survive, so this route is RBAC-gated +
    audited like a message view."""

    lines: list[str]
    total_lines: int
    offset: int
    limit: int
    available: bool


class UpdateInfo(BaseModel):
    """No-network version-update result (#30, ADR 0026): the running version vs the installed/pinned
    one + the derived ``update_available`` bool. Carries **only version strings** — no PHI, no
    dependency list. Present on :class:`SystemStatus` only when ``[update_check]`` is enabled and the
    runner has produced a result; ``None``/absent otherwise (so the payload is unchanged when off)."""

    current_version: str
    pinned_version: (
        str | None
    )  # None in a source/checkout run with no installed-distribution metadata
    update_available: bool


class PoolWaitInfo(BaseModel):
    """Connection-pool acquire-WAIT percentiles in milliseconds — the PRIMARY connection-scale
    pool-wait signal (B11). The time a stage worker spends waiting for a pooled connection grows
    monotonically with worker contention once the pool saturates (where size/idle occupancy can't tell
    500 connections from 1500), so these percentiles are the load-bearing wall metric."""

    count: int  # number of acquire() waits sampled since engine start
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float


class ClaimPoolInfo(BaseModel):
    """The ADR 0114 dedicated-claim-connection holder snapshot (SQL Server only, the
    ``fifo_claim_prepared`` sub-lever). These connections live OUTSIDE the main pool — an aioodbc
    pool cannot retain a cursor across acquire/release — so without this additive sibling the B11
    connection-budget arithmetic would under-count the store's real connection footprint."""

    open: int  # holders currently open (borrowed + idle)
    idle: int  # holders sitting in the per-stage free lists
    opened_total: int  # lifetime opens (a reopen after a discard counts again)
    discarded_total: int  # lifetime discards (cancellation / unclassified errors only)


class PoolInfo(BaseModel):
    """A **server-only** connection-pool snapshot (B11), surfaced as the additive ``pool`` field on
    :class:`SystemStatus`. ``None`` on SQLite (no pool — it has a single writer + lockfree read
    connections, not a contended pool), so an older client deserializes ``/status`` unchanged. Carries
    the PRIMARY acquire-wait percentiles plus a secondary size/idle occupancy ("is it saturated":
    ``idle == 0`` at the wall). Read-only observability — never affects routing or disposition."""

    backend: str  # "postgres" | "sqlserver"
    max_size: int  # the configured pool maximum
    size: int  # connections currently open in the pool
    idle: int  # currently-free connections (idle == 0 ⇒ saturated)
    acquire_wait: PoolWaitInfo  # PRIMARY: acquire() wait-time percentiles
    # ADR 0114 sub-lever B: the out-of-pool dedicated claim holders. Additive + None unless
    # fifo_claim_prepared is effectively active on SQL Server, so existing clients are untouched.
    claim_pool: ClaimPoolInfo | None = None


class ClaimProcInfo(BaseModel):
    """The ADR 0114 sub-lever A (``fifo_claim_proc``) startup-gate verdict — AC-7's **degraded
    gauge**, surfaced as the additive ``claim_proc`` field on :class:`SystemStatus`.

    ``None`` on every backend without the lever and on SQL Server when the flag is off, so "not
    requested" reads differently from "requested and degraded". When ``effective`` is False,
    ``degraded_reason`` says why the store fell back to the shipped ad-hoc batch — claims keep
    flowing either way, so this is a performance-lever gauge, not a health alarm.

    Metadata only: proc names, a head-form word, and the gate's own reason string — no message
    content and no PHI."""

    effective: bool  # the gate passed; pooled claims run through the procs
    degraded_reason: str | None = None  # why it degraded to the batch; None when effective
    # proc name -> the stored head form the deployed module matched ("rewritten" | "verbatim").
    # "verbatim" means this server does NOT rewrite CREATE OR ALTER — no engine measured to date
    # does, so it is worth reporting; it is an engine difference, not a fault.
    head_forms: dict[str, str] = Field(default_factory=dict)


class SystemStatus(BaseModel):
    engine: EngineInfo
    # Engine-wide top-line roll-up KPIs (#93): total messages, combined in+out connection count with
    # running/stopped breakdown, and the engine-wide msg/s rate (reusing the recent_done window).
    # Additive + defaulted so an older client deserializes /status unchanged.
    kpis: EngineKpis = EngineKpis()
    db: DbInfo
    # App-log disk metering (#50), alongside the DB metrics. ``None`` when no [logging].log_dir is
    # configured (the engine logs to stdout under NSSM) or the directory is unreadable — never raises.
    logs: LogInfo | None = None
    # No-network version-update signal (#30, ADR 0026). Additive + ``None`` when [update_check] is
    # disabled or the runner hasn't produced a result yet, so the existing payload is unchanged when off.
    update: UpdateInfo | None = None
    # B11 connection-scale observability: a SERVER-ONLY connection-pool snapshot (acquire-wait
    # percentiles + size/idle occupancy). Additive + ``None`` on SQLite (no pool) so the existing
    # payload is unchanged on the default backend and an older client deserializes /status unchanged.
    pool: PoolInfo | None = None
    # ADR 0114 AC-7's degraded gauge: whether the SQL Server proc claim path is effectively active,
    # and why not when it isn't. Additive + ``None`` on every backend without the lever and whenever
    # [store].fifo_claim_proc is off, so the default payload is unchanged.
    claim_proc: ClaimProcInfo | None = None


class IntegrityResult(BaseModel):
    ok: bool
    detail: str


class ClusterStatus(BaseModel):
    """This node's cluster posture (Track B Step 7), from the cheap in-memory coordinator gates — no DB
    round-trip. ``clustered`` is False on a single node (NullCoordinator), where ``is_leader`` is always
    True and ``config_version`` is 0. ``role`` (Workstream A5) is the operator-facing active-passive
    role: ``"single-node"`` when not clustered, else ``"primary"`` when this node is the leader (it runs
    the graph) or ``"standby"`` when it is a warm follower (no listeners bound, no workers running)."""

    node_id: str
    clustered: bool
    is_leader: bool
    role: str
    config_version: int


class ClusterNode(BaseModel):
    """One node in the cluster (Track B Step 7). ``is_leader`` is the DERIVED live leader (the durable
    ``nodes.is_leader`` heartbeat flag filtered for freshness, so a crashed ex-leader's stale flag is not
    reported). ``started_at``/``last_seen`` are epoch seconds, ``None`` only for the single-node
    synthetic self-entry."""

    node_id: str
    host: str | None
    pid: int | None
    status: str
    started_at: float | None
    last_seen: float | None
    is_leader: bool
    # Leader-preference config (ADR 0096). ``acquire_delay_seconds`` = this node's take-over-of-expired
    # handicap (0.0 = none); ``promotable`` = whether it may ever become leader (False = a non-promotable
    # standby). Defaulted so single-node / older clients stay valid.
    acquire_delay_seconds: float = 0.0
    promotable: bool = True


class ClusterNodeList(BaseModel):
    """Cluster membership (Track B Step 7). ``leader_node_id`` is the node_id of the single derived
    leader (from the ``nodes.is_leader`` heartbeat flag), or ``None`` if no fresh node currently holds
    it. ``lease_owner`` / ``lease_expires_at`` (Workstream A5) are the **authoritative** leadership-lease
    state — who holds the self-fencing lease and the DB-clock epoch at which it expires (when a standby
    could acquire if the leader stops renewing). ``lease_owner`` normally equals ``leader_node_id``; a
    brief divergence during failover is expected (the lease is the source of truth). ``lease_expires_at``
    is ``None`` single-node (no lease)."""

    nodes: list[ClusterNode]
    leader_node_id: str | None
    lease_owner: str | None
    lease_expires_at: float | None


class DrStatus(BaseModel):
    """Third-tier DR standby posture (#61, ADR 0048). ``enabled`` = this deployment is a DR box at all
    (``[dr].enabled``); ``active`` = it is currently serving under the DR run-profile (the priority feeds
    are bound, the rest report ``status:"filtered"``); ``threshold`` is ``[dr].priority_threshold``;
    ``activation_mode`` is always ``"manual"`` in this slice (``auto`` is rejected at config load). A
    non-DR deployment reports ``enabled=false`` / ``active=false``."""

    enabled: bool
    active: bool
    threshold: str
    activation_mode: str


class ServiceStatusInfo(BaseModel):
    """The engine's own hosting-service (NSSM) run state (L6a, ADR 0065). ``enabled`` reflects
    ``[service].report_status``; when off, no query runs and ``state`` is ``"disabled"``. Otherwise
    ``state`` is ``running`` / ``stopped`` / ``not_installed`` / ``unknown`` / ``unavailable`` (off
    Windows or when ``sc`` can't run). Read-only, ``monitoring:read``; carries no PHI and no secret."""

    enabled: bool
    state: str
    service_name: str


class DrActionResult(BaseModel):
    """The PHI-free outcome of a ``POST /dr/activate`` or ``/dr/release`` (#61, ADR 0048): the new
    posture plus, for an activation, the verified cold-seed archive name + restore-verify status + the
    new audit-chain segment marker hash. Paths/counts/one-way fingerprints only — never a body or key
    bytes."""

    action: str  # "activate" | "release"
    active: bool
    threshold: str
    archive: str | None = None
    verify_status: str | None = None
    seed_segment: str | None = None
    vip_hook_ran: bool = False


class DrActivateRequest(BaseModel):
    """Request body for ``POST /dr/activate`` (#61 / BACKLOG #102, ADR 0048). Both fields are optional so
    an empty body still reaches the fail-closed cold-seed step (a missing seed then aborts as before).

    ``archive`` overrides ``[dr].seed_archive`` (the runbook may pass the chosen #60 backup).
    ``dba_attests_restored`` is the operator's explicit, per-activation attestation that a DBA has restored
    the server-DB ``mefor`` database for THIS failover — REQUIRED on a Postgres/SQL Server store (the
    config-only cold-seed archive cannot restore/verify a DBA-managed DB), IGNORED on SQLite (the archive
    verifies the whole store). It is deliberately a per-request field, not a static ``[dr]`` setting: a
    permanent config attestation would be no attestation at all. NOTE: even when ``true`` the engine's live
    restore-provenance probe still fails closed against a fresh/unrestored DB (defense in depth); the
    attestation does NOT prove the restore's vintage or completeness — that rests on the DBA runbook
    (BACKLOG #102)."""

    archive: FilesystemPath | None = None
    dba_attests_restored: bool = False


class AiPolicy(BaseModel):
    """The effective AI-assistance policy for the IDE gate. ``assist_permitted`` is the
    identity-dependent bit: ``True``/``False`` when the caller's RBAC can be evaluated, ``None`` when
    no/invalid token under enabled auth made it unknown (a tokenless read still gets mode/scope, so a
    central ``off`` is honored)."""

    mode: AiMode
    data_scope: AiDataScope
    environment: str | None  # the free-form active-environment NAME (ADR 0017)
    data_class: DataClass | None = None  # PHI posture (synthetic|phi), if resolvable
    production: bool | None = None  # production-tier posture, if resolvable
    assist_permitted: bool | None
    reason: str | None = None


class AiChatRequest(BaseModel):
    """A single engine-brokered AI-assist request (ADR 0135, BACKLOG #95) — the body of
    ``POST /ai/chat``. ``prompt`` is the IDE-assembled **code_only** context (the config graph *names* +
    the active editor *code* — never message bodies / PHI). ``data_scope`` is the IDE's CLAIMED scope; the
    SERVER IGNORES it for policy and re-resolves its own effective scope — a claim ABOVE what the server
    enforces is DENIED (403), never honoured (the server is the sole enforcement point)."""

    prompt: str = Field(min_length=1, max_length=200_000)
    # The IDE's claimed data scope. Defaults to the code_only floor; the server NEVER trusts it to widen
    # anything (it re-resolves the effective policy) and refuses an over-claim.
    data_scope: AiDataScope = AiDataScope.CODE_ONLY


class AiChatResponse(BaseModel):
    """The engine-brokered AI-assist reply (ADR 0135). ``data_scope`` is the SERVER-enforced effective
    scope actually applied (always ``code_only`` in this MVP), so the IDE can never infer it obtained
    more than the server granted."""

    reply: str
    model: str
    data_scope: AiDataScope


class SecurityLoosening(BaseModel):
    """One ``[security]`` switch currently at its INSECURE value (ADR 0118 AC-4/AC-5), as reported by the
    read-only posture view. ``switch`` is the plain-language ``[security]`` key; ``risk`` names what the
    deliberate opt-out gives up. Advisory — the posture GATES still refuse a production-PHI weakening."""

    switch: str
    risk: str


class SecurityPosture(BaseModel):
    """The instance's **effective** PHI-at-rest security posture (M5), behind the authenticated,
    permission-gated ``GET /security/posture`` route. Surfaces what protection is *actually* in effect
    (vs. what an operator assumes) so an EF-3-class accidental-dangerous-deploy is visible.

    **No secret material ever appears here** (SECRET-1): ``key_id`` is only the active key's one-way
    **fingerprint** (the first 16 hex of SHA-256(key)), never key bytes, and ``key_source`` is the
    provider *name*, not a credential. ``data_class``/``production`` are the resolved posture;
    ``encryption_enabled`` is read from the *live* store cipher (not just config). ``plaintext_columns``
    lists any PHI-bearing columns that stay UNENCRYPTED at rest on the active backend — ``[]`` on every
    backend now (the SQL Server ``error``/``last_error``/``message_events.detail`` residual was retired
    by H4; SQLite, Postgres, and SQL Server all have full at-rest coverage of the PHI-bearing columns).
    """

    data_class: DataClass | None = None  # resolved PHI posture (synthetic|phi), if resolvable
    production: bool | None = None  # production-tier posture, if resolvable
    # The security REFUSE/WARN dial (this refactor): enforce (secure default) reproduces the historical
    # production=True refuse posture; warn reproduces the non-production warn+continue. Decoupled from the
    # production tier above (that stays a true property; this drives the posture gates + escape-clamp).
    enforcement: SecurityEnforcement = SecurityEnforcement.ENFORCE
    environment: str | None = None  # the active-environment NAME (ADR 0017)
    backend: str  # store backend: "sqlite" | "postgres" | "sqlserver"
    encryption_enabled: bool  # whether the LIVE store cipher encrypts at rest
    key_source: str  # [store].key_provider name (auto|env|dpapi|aws_kms|...); NOT key material
    key_id: str | None = (
        None  # active key FINGERPRINT only (first 16 hex of SHA-256(key)); never bytes
    )
    require_encryption: bool  # whether keyless start is refused regardless of data_class
    allow_unencrypted_phi: bool  # whether the audited keyless-PHI override is set
    # PHI-bearing columns NOT encrypted at rest on this backend; empty on every backend (the SQL Server
    # error/last_error/detail residual was retired by H4) or when encryption is off, where it is N/A.
    plaintext_columns: list[str] = Field(default_factory=list)
    # ADR 0118: the EFFECTIVE [security] switch values (the plain-language posture section), the active
    # loosenings (each opt-out at its insecure value), and — on a synthetic instance — the notice that the
    # PHI-only gates are (defensibly) relaxed. Read-only; the IDE is the sole authoring surface.
    security: dict[str, object] = Field(default_factory=dict)
    loosenings: list[SecurityLoosening] = Field(default_factory=list)
    # ``None`` = the loosening list above is COMPLETE. A string names what it could NOT see — set only
    # when this engine has no loaded connection graph (an embedding, or an app queried before start),
    # where the ADR 0153 per-connection ``cleartext_accepted`` declarations are unreadable. Reporting a
    # settings-only subset with no marker would understate the posture, which is the one thing this
    # route must not do; ``messagefoundry security show`` carries the same marker for the same reason.
    loosenings_scope: str | None = None
    # Set WHERE handles_real_patient_data=false: the strict PHI-only controls (at-rest-encryption refusal,
    # deny-by-default egress, bounded retention) are relaxed because the instance carries no ePHI (AC-6).
    synthetic_relaxation: str | None = None
    # FIPS-provider attestation (report-only, #73 / ADR 0120). ``fips_mode`` is the FIPS-provider state of
    # the INTERPRETER's ssl/_hashlib OpenSSL (True/False, or None = undeterminable on a non-OpenSSL build);
    # ``openssl_version`` is that OpenSSL's version string. Metadata only — NOT secret material (SECRET-1),
    # and NOT a FIPS-140 certification. Scoped to the ssl/_hashlib OpenSSL, which is separate from the
    # cryptography-wheel OpenSSL that encrypts PHI at rest — so it is "reported", never "certified".
    fips_mode: bool | None = None
    openssl_version: str | None = None
    # TLS key-exchange groups read-out (report-only, #338 / ASVS 11.6.2). A read of whether the approved
    # KEX groups are PINNED on built contexts or INHERITED from OpenSSL's default group list — today
    # always inherited, because ``SSLContext.set_groups`` is a Python 3.15 API. Report-only: it reflects,
    # and changes, NO live TLS behaviour (the TLS 1.2+ floor is the enforced control; see docs/PHI.md §4).
    kex_groups: str | None = None
    # Platform memory-encryption READ-OUT (report-only, ADR 0152 Phase 1 / ASVS 11.7.1) + the operator
    # declaration (Phase 2). Named "self_reported" on purpose: these are values the host OS emits
    # about ITSELF (/proc/cpuinfo flags, guest device-node presence), and 11.7.1 exists precisely
    # because that OS may be the adversary. NONE OF THESE FIELDS SATISFIES ASVS 11.7.1, at any value,
    # in any combination. Only a CPU-signed attestation report verified against the silicon vendor's
    # root PKI would, and that is ADR 0152 rung 3 — not built. Capability and activation are kept as
    # SEPARATE fields because a CPU flag ("this silicon can") and a guest device ("this guest is") are
    # different facts; fusing them is the most likely route to a false compliance claim.
    memory_encryption_self_reported_capability: bool | None = None
    memory_encryption_self_reported_active: bool | None = None
    memory_encryption_self_reported_mechanism: str | None = None
    memory_encryption_readout_source: str | None = None
    # [security].memory_encryption_operator_declared — the OPERATOR'S UNVERIFIED CLAIM that the host
    # provides memory encryption. NOT called "attested": in confidential computing (the domain of
    # 11.7.1) "attestation" means a CPU-signed quote verified against vendor root PKI, which is rung 3
    # and is not built — and this field, unlike the four above, has no measurement behind it at all,
    # so it is the single most quotable value in the response. The word has to carry its own weakness.
    memory_encryption_operator_declared: bool = False
    # Tri-state, and the third state is the point. None = nothing was measured that COULD contradict
    # anything (nobody declared, or the platform is unreadable, or a missing guest device node is
    # uninformative there — an SME/TME host, or a container that does not map /dev/sev-guest).
    # False = declared and the read-out reports a guest interface present. True = declared while the
    # host advertises a guest-attestable mechanism and exposes no guest interface. A bare bool would
    # render "corroborated", "undeterminable" and "nobody claimed" identically as `false` — on
    # Windows, false by vacuity — which is the same fusion this feature refuses for capability vs
    # activation.
    memory_encryption_readout_contradicts_declaration: bool | None = None
    # The disclaimer that TRAVELS WITH THE ARTIFACT. ADR 0152 designates this endpoint the evidence
    # artifact for 11.7.1, and every other disclaimer this feature writes lives where an assessor
    # never looks (comments, docstrings, the ADR, the console HTML). Always populated, on every
    # posture, precisely so no reading of this response is missing it. Prose-in-posture has precedent
    # on this same model — see ``synthetic_relaxation`` above.
    memory_encryption_note: str | None = None
    # [security].allowed_client_networks observability. A control nobody can see firing is a control
    # that gets ripped back out the first time someone cannot reach the console, so these answer "is it
    # firing, and at whom?" without log-file access. Zero/None on every deployment that has not set the
    # allow-list. ``client_address_monoculture`` is the R3 tripwire: the allow-list is set, no proxy is
    # declared, and every observed request resolved to the same loopback address — i.e. an UNDECLARED
    # reverse proxy is in front and the allow-list is INERT.
    client_network_denials: int = 0
    client_denied_last: str | None = None
    client_address_monoculture: bool = False


class ConnectionMetadata(BaseModel):
    """Static metadata for one connection (operability Tier 4). ``metadata`` is the operator's
    free-form label table (owner / runbook / environment); ``settings`` is **secret-scrubbed**
    (``env()`` refs shown as ``{"env": key}``, inline credentials redacted). No live probe — use
    ``POST /connections/{name}/test`` for reachability."""

    name: str
    direction: str  # "in" (inbound) | "out" (outbound)
    method: str  # connector type, e.g. "mllp" / "file" / "rest"
    running: bool
    router: str | None = None  # inbound only
    metadata: dict[str, Any] | None = None  # operator labels
    settings: dict[str, Any]  # secret-scrubbed view
    simulated: bool | None = None  # outbound only; True = egress-suppressed shadow lane (#15)
    error: str | None = None  # why this connection failed to start, if it did (ADR 0031)


class AlertRuleInfo(BaseModel):
    """One operator-authored alert rule (ADR 0014), read-only. Pure routing/threshold data — no secrets.
    Per-rule recipient addresses (#146) are reported as a COUNT only (never the addresses), matching the
    ``AlertsConfig.email_recipient_count`` policy."""

    event_type: str
    connection: str
    min_depth: int | None = None
    min_oldest_seconds: float | None = None
    severity: str
    transports: list[str] | None = None
    cooldown_seconds: float | None = None
    recipient_count: int = (
        0  # #146 — per-rule email recipients (count only; 0 = uses global email_to)
    )
    id: str | None = None  # #138 — operator rule label ({rule_id} template var); None = unlabelled
    control_action: str | None = (
        None  # #144 — restart_inbound/restart_outbound fired on match (None = none)
    )
    control_target: str | None = (
        None  # #144 — connection acted on (None = the event's own connection)
    )
    mute: bool = False  # #143 — static per-rule NOTIFICATION mute (still records state)
    escalate_tiers: int = 0  # #81 — number of occurrence-driven escalation tiers (0 = none)
    schedule_configured: bool = False  # #81 — whether the rule is schedule-gated (present-or-not)
    content_label: str | None = None  # #81 — content_match label this rule routes by (None = any)


class AlertsConfig(BaseModel):
    """Read-only view of the loaded [alerts] config (ADR 0014, BACKLOG #22b). Transports are reported
    present-or-not; NO secrets (webhook URL, SMTP password/username) or recipient addresses are ever
    included. The #138 alert-email templates are reported present-or-not (booleans) — the template TEXT
    is non-PHI operator config, but present/absent is the honest read-only signal."""

    webhook_configured: bool
    webhook_timeout: float
    webhook_allowed_hosts: list[str]
    email_configured: bool
    email_smtp_port: int
    email_use_tls: bool
    email_recipient_count: int
    smtp_allowed_hosts: list[str]
    realert_seconds: float
    # #138 — whether each operator-editable alert-email template is set (validated at config-load).
    email_subject_template_configured: bool = False
    email_body_template_configured: bool = False
    email_html_template_configured: bool = False
    rules: list[AlertRuleInfo]


class ConnectionTestResult(BaseModel):
    """Result of ``POST /connections/{name}/test`` — a reachability probe that sends no real payload.
    ``supported`` is False when the connector has nothing external to probe (a bound listen source, a
    timer); ``success`` is the reachability outcome; ``detail`` carries the failure / not-supported
    reason."""

    name: str
    direction: str  # "in" | "out"
    supported: bool
    success: bool
    duration_ms: float
    detail: str | None = None


class AlertTestEmailRequest(BaseModel):
    """Body for ``POST /alerts/test-email`` (BACKLOG #118). All fields optional — an empty body tests
    the configured ``[alerts]`` email transport against the configured ``email_to``. ``recipient_override``,
    when set, redirects this one test send to a single alternate address (operator config, admin-gated);
    it is never echoed back in the result."""

    recipient_override: EmailAddress | None = None


class AlertTestEmailResult(BaseModel):
    """Result of ``POST /alerts/test-email`` (BACKLOG #118) — a live SMTP send of a synthetic, PHI-free
    event through the **real** alert-email transport (the same path a genuine alert takes). Carries NO
    email addresses: only whether email is configured, the send outcome, how long the attempt took, the
    recipient count, and a ``safe_exc``-scrubbed failure detail."""

    configured: bool
    success: bool
    duration_ms: float
    recipient_count: int
    detail: str | None = None


# --- Offline uploaded logs (BACKLOG #125/#126, ADR 0134) ----------------------------------------


class UploadedFileInfo(BaseModel):
    """Metadata about one operator-uploaded diagnostic file (no body). ``filename`` is display-only
    (sanitized, never a path); ``content_type`` is the format tag; ``message_count`` is the number of
    HL7 messages the file split into at upload time."""

    file_id: str
    filename: str
    uploader: str
    content_type: str
    size: int
    sha256: str
    uploaded_at: float
    message_count: int


class UploadedFileList(BaseModel):
    """The caller's visible uploaded files (metadata only).

    ``scope`` says WHOSE files ``total`` counted (ASVS 8.2.2): ``own`` for the owner-scoped default,
    ``any_owner`` when the caller holds ``files:access_any``. It is the same value the ``upload.list``
    audit row records, computed once at the route — so a reader of the response and a reader of the
    audit interpret the same count the same way, and a UI can state which listing it is showing
    instead of asserting one of the two unconditionally. It is a fixed enum, never operator text."""

    total: int
    files: list[UploadedFileInfo]
    scope: Literal["own", "any_owner"]


class UploadedMessageSummary(BaseModel):
    """One split message inside an uploaded file (metadata only — never the decrypted body). ``index``
    is its position in the file; ``message_type``/``control_id`` are peeked from the HL7."""

    index: int
    message_type: str | None
    control_id: str | None
    size: int


class UploadedMessagesResult(BaseModel):
    """A page of an uploaded file's split messages, after the (optional) offline filters/search.
    ``scanned`` is how many messages were examined; ``matched`` how many matched; ``truncated`` True
    when the result cap was hit."""

    file_id: str
    filename: str
    messages: list[UploadedMessageSummary]
    total_messages: int
    scanned: int
    matched: int
    truncated: bool


class UploadResendRequest(BaseModel):
    """Resend one message from an uploaded file INTO a chosen inbound connection's pipeline (ADR 0134).

    ``index`` is the 0-based message position in the file; ``to`` is the target inbound connection the
    message is injected onto (a fresh ``RECEIVED`` via ``enqueue_ingress`` — NOT ``reingress``).
    ``idempotency_key`` is unused today (each inject is a distinct receipt) but reserved for parity."""

    index: int = Field(ge=0)
    to: ConnectionName  # the target inbound connection


class UploadResendResult(BaseModel):
    """The outcome of an uploaded-message inject: the new ``message_id`` minted on the target inbound's
    channel. Carries ids only, never a body."""

    file_id: str
    index: int
    to: str
    message_id: str
    status: str  # "injected"


class UploadDeleteResult(BaseModel):
    file_id: str
    filename: str
    deleted: bool


# --- Saved / layered Log-Search filter presets (BACKLOG #151, ADR 0136) -------------------------


class SearchPresetCriteria(BaseModel):
    """The saved content-search form state. Mirrors the ``/messages/search`` typed params exactly (the
    ADR 0046 seam). ``content`` / ``field_value`` are PHI-shaped — the preset column is encrypted at
    rest and every save/recall is step-up-gated + audited."""

    content: SearchText | None = None
    field_path: str | None = Field(None, max_length=32)
    field_value: SearchText | None = None
    target: Literal["raw", "summary", "both"] = "both"
    channel_id: ConnectionName | None = None
    status: StatusFilter | None = None
    message_type: MessageTypeFilter | None = None
    control_id: ControlIdFilter | None = None
    limit: int = Field(50, ge=1, le=500)


class SearchPresetInfo(BaseModel):
    """A saved preset's identity + metadata (NO criteria — the PHI-shaped terms are returned only by the
    step-up-gated layered-search compose, never listed)."""

    id: str
    name: str
    created_at: float
    updated_at: float


class SearchPresetList(BaseModel):
    total: int
    presets: list[SearchPresetInfo]


class SearchPresetCreateRequest(BaseModel):
    """Create-or-replace a named preset for the calling user. ``name`` is a per-user unique label."""

    name: DisplayLabel
    criteria: SearchPresetCriteria


class SearchPresetCreateResult(BaseModel):
    id: str
    name: str
    status: str  # "created" | "replaced"


class SearchPresetDeleteResult(BaseModel):
    id: str
    deleted: bool
