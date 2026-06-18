# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Response schemas for the localhost API.

These are the wire contract the console (and any other client) sees — deliberately
separate from the internal SQLite rows and channel-config models so storage/runtime
changes don't leak into the API. Message *list* responses carry metadata only; the raw
body (PHI) appears only in the single-message detail view, which is audited.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from messagefoundry.config.ai_policy import AiDataScope, AiMode, DataClass


class ChannelInfo(BaseModel):
    id: str
    name: str
    enabled: bool
    running: bool
    source_type: str
    destinations: list[str]


class MessageSummary(BaseModel):
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


class OutboxInfo(BaseModel):
    id: str
    destination_name: str
    status: str
    attempts: int
    next_attempt_at: float
    last_error: str | None


class EventInfo(BaseModel):
    ts: float
    event: str
    destination: str | None
    detail: str | None


class MessageDetail(MessageSummary):
    """Full single-message view, including the raw body and delivery/audit trail."""

    raw: str
    outbox: list[OutboxInfo]
    events: list[EventInfo]


class CapturedResponseInfo(BaseModel):
    """One captured request/response reply (ADR 0013). ``outcome``/``detail`` are visible with the
    message-read permission; ``body`` is PHI and populated only when the caller also holds the raw-body
    permission (``None`` otherwise, and ``None`` once retention has purged it)."""

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


class PurgeResult(BaseModel):
    cancelled: int


class DeadLetterRow(BaseModel):
    """One dead-lettered delivery (a message→destination that exhausted its retries)."""

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


class DeadLetterReplayRequest(BaseModel):
    # Connection names; bounded so an over-long value can't reach the store query (ASVS 1.3.3).
    channel_id: str | None = Field(None, max_length=256)  # scope replay to one inbound (None = all)
    destination_name: str | None = Field(None, max_length=256)  # scope to one outbound (None = all)


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
    config_dir: str | None = Field(None, max_length=4096)
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
    status: str  # "running" | "stopped"
    direction: str  # "in" (source) | "out" (destination)
    method: str  # connection method/protocol, e.g. MLLP / File / TCP / REST
    peer: str | None  # MLLP host or file directory
    port: int | None
    queue_depth: int | None
    idle_seconds: float | None
    alerts_active: int  # stubbed 0 until the alerts feature exists
    errored: int | None  # source: inbound errors; destination: dead-lettered
    read: int | None  # source only: inbound received
    written: int | None  # destination only: delivered
    backlog_seconds: float | None  # destination only; None = unknown/stalled
    delivered_age_seconds: float | None  # destination only; age of oldest queued item
    simulated: bool | None = None  # destination only; True = egress-suppressed shadow lane (#15)


class StatsResponse(BaseModel):
    outbox_by_status: dict[str, int]
    # NOT-DONE rows (pending|inflight) across every stage (ingress + routed + outbound) — a
    # whole-pipeline drain gauge, vs outbox_by_status which sees only the outbound stage. Defaults to 0
    # so a client reading an older engine (no field) degrades gracefully.
    in_pipeline: int = 0


class Health(BaseModel):
    status: str = "ok"
    # WP-L3-07 (ASVS 13.4.6): the build version is a fingerprinting detail, disclosed only to an
    # authenticated caller. A tokenless liveness probe gets ``status`` with ``version`` omitted/None.
    version: str | None = None


class EngineInfo(BaseModel):
    version: str
    uptime_seconds: float
    pid: int
    channels_total: int
    channels_running: int
    channels_stopped: int
    outbox_by_status: dict[str, int]


class DbInfo(BaseModel):
    path: str
    size_bytes: int  # db file + -wal + -shm
    disk_free_bytes: int
    journal_mode: str
    messages: int
    events: int
    audit: int


class SystemStatus(BaseModel):
    engine: EngineInfo
    db: DbInfo


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
